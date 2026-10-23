"""Step 2 tests: email parsing, sanitization, URL analysis. Synthetic emails only."""

from email.message import EmailMessage

import pytest

from app.services.email_parser import (
    MAX_URLS,
    ParseError,
    analyze_url,
    parse_eml,
    parse_text,
)

PLAIN_EML = (
    b"From: \"PayPal Support\" <support@paypal-update.example>\r\n"
    b"Return-Path: <bounce@mailer-x91.example>\r\n"
    b"Reply-To: help@other.example\r\n"
    b"Subject: URGENT Account Update Required\r\n"
    b"Authentication-Results: mx.local; spf=fail smtp.mailfrom=mailer-x91.example; "
    b"dkim=none; dmarc=fail header.from=paypal-update.example\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"\r\n"
    b"Please verify your account at http://203.0.113.9/login?token=SECRET123 now.\r\n"
)


# ----------------------------------------------------------------- headers / body
def test_plain_eml_headers_and_auth_results():
    p = parse_eml(PLAIN_EML)
    assert p.subject == "URGENT Account Update Required"
    assert p.sender_address == "support@paypal-update.example"
    assert p.sender_domain == "paypal-update.example"
    assert p.return_path_domain == "mailer-x91.example"
    assert p.reply_to_domain == "other.example"
    assert (p.spf_result, p.dkim_result, p.dmarc_result) == ("fail", "none", "fail")
    assert "verify your account" in p.body_text
    assert p.had_headers and not p.had_html
    assert len(p.content_sha256) == 64


def test_missing_auth_headers_default_to_none():
    p = parse_eml(b"From: a@b.example\r\nSubject: hi\r\n\r\nhello there\r\n")
    assert (p.spf_result, p.dkim_result, p.dmarc_result) == ("none", "none", "none")


def test_empty_return_path_is_none():
    p = parse_eml(b"From: a@b.example\r\nReturn-Path: <>\r\nSubject: x\r\n\r\nbody text\r\n")
    assert p.return_path_domain is None


def test_html_only_eml_strips_markup_and_scripts():
    raw = (
        b"From: a@b.example\r\nSubject: s\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        b"<html><head><title>T</title><style>p{color:red}</style></head><body>"
        b"<script>alert('xss')</script><p>Hello <b>world</b></p></body></html>"
    )
    p = parse_eml(raw)
    assert "Hello" in p.body_text and "world" in p.body_text
    for forbidden in ("<", ">", "alert", "color:red"):
        assert forbidden not in p.body_text
    assert p.had_html


def test_multipart_counts_attachments_and_reads_both_parts():
    msg = EmailMessage()
    msg["From"] = "a@b.example"
    msg["Subject"] = "Invoice"
    msg.set_content("plain version http://plain.example/x")
    msg.add_alternative("<p>html <a href='http://html.example/y'>click</a></p>", subtype="html")
    msg.add_attachment(b"data", maintype="application", subtype="pdf", filename="inv.pdf")
    p = parse_eml(msg.as_bytes())
    assert p.attachment_count == 1
    assert "plain version" in p.body_text
    domains = {u.domain for u in p.urls}
    assert domains == {"plain.example", "html.example"}


def test_unknown_charset_does_not_crash():
    raw = (
        b"From: a@b.example\r\nSubject: s\r\nContent-Type: text/plain; charset=bogus-9\r\n\r\n"
        b"caf\xe9 verify now\r\n"
    )
    assert "verify now" in parse_eml(raw).body_text


# ------------------------------------------------------------------ sanitization
def test_control_characters_removed_and_header_collapsed():
    p = parse_text("Subject: Hello\x00 there\x07\n\nbody\x00 text\x1b here")
    assert p.subject == "Hello there"
    assert "\x00" not in p.body_text and "\x1b" not in p.body_text


def test_repr_does_not_leak_body():
    p = parse_eml(PLAIN_EML)
    assert "verify your account" not in repr(p)


# --------------------------------------------------------------------- parse_text
def test_pasted_body_only():
    p = parse_text("Dear customer: please confirm your password at https://evil.example/a")
    assert not p.had_headers
    assert p.sender_domain is None
    assert p.urls[0].domain == "evil.example"


def test_pasted_full_message_with_headers():
    p = parse_text("From: a@b.example\nSubject: Test\n\nHello world")
    assert p.had_headers and p.subject == "Test" and p.body_text == "Hello world"


def test_pasted_html_is_converted_to_text():
    p = parse_text("<div>Hi <a href='http://x.example/'>there</a></div>")
    assert p.body_text.startswith("Hi") and "<" not in p.body_text
    assert p.urls[0].domain == "x.example"


# ----------------------------------------------------------------------- errors
@pytest.mark.parametrize("bad", [b"", b"   \r\n  "])
def test_empty_eml_rejected(bad):
    with pytest.raises(ParseError):
        parse_eml(bad)


def test_oversize_rejected_without_leaking_content():
    secret = b"TOPSECRETCONTENT" * 10
    with pytest.raises(ParseError) as err:
        parse_eml(secret, max_bytes=50)
    assert "TOPSECRET" not in str(err.value)


def test_attachment_only_email_has_no_body():
    msg = EmailMessage()
    msg["From"] = "a@b.example"
    msg.add_attachment(b"x", maintype="application", subtype="pdf", filename="a.pdf")
    with pytest.raises(ParseError):
        parse_eml(msg.as_bytes())


# ------------------------------------------------------------------ URL analysis
def test_url_is_defanged_and_query_userinfo_fragment_removed():
    u = analyze_url("http://user:pw@Login.Example.com:8080/a/b?token=SECRET#frag")
    assert u.url_defanged == "hxxp://login[.]example[.]com:8080/a/b"
    assert "SECRET" not in u.url_defanged and "pw" not in u.url_defanged
    assert u.has_at_symbol and not u.is_https and u.is_suspicious
    assert u.domain == "example.com" and u.subdomain_count == 1 and u.tld == "com"


def test_ip_url():
    u = analyze_url("http://203.0.113.9/login")
    assert u.has_ip_address and u.is_suspicious and u.tld is None


def test_numeric_ip_forms_detected():
    assert analyze_url("http://3232235777/x").has_ip_address
    assert analyze_url("http://0xC0A80101/x").has_ip_address


def test_shortener_and_punycode_flagged():
    assert analyze_url("https://bit.ly/abc").uses_shortener
    assert analyze_url("https://xn--pypal-4ve.example/").is_suspicious


def test_clean_https_url_not_suspicious():
    u = analyze_url("https://www.example.org/page")
    assert u.is_https and not u.is_suspicious and u.subdomain_count == 1


def test_country_sld_subdomain_heuristic():
    u = analyze_url("https://mail.plp.edu.ph/x")
    assert u.domain == "plp.edu.ph" and u.subdomain_count == 1


def test_non_http_and_malformed_urls_ignored():
    assert analyze_url("ftp://x.example/") is None
    assert analyze_url("http://[::1/") is None
    assert analyze_url("http:///nohost") is None


def test_link_text_mismatch_detected():
    html = "<a href='http://evil.example/'>www.paypal.com</a><a href='http://ok.example/'>ok.example</a>"
    p = parse_text(html)
    by_domain = {u.domain: u for u in p.urls}
    assert by_domain["evil.example"].link_text_mismatch
    assert not by_domain["ok.example"].link_text_mismatch


def test_urls_deduplicated_and_trailing_punctuation_stripped():
    p = parse_text("see http://a.example/x, and http://a.example/x. also (http://b.example/y)")
    assert [u.domain for u in p.urls] == ["a.example", "b.example"]


def test_url_cap_sets_truncated_flag():
    text = " ".join(f"http://site{i}.example/" for i in range(MAX_URLS + 5))
    p = parse_text(text)
    assert p.url_count == MAX_URLS and p.urls_truncated
