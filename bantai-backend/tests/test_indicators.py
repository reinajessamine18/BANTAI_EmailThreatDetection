from app.services.email_parser import parse_eml, parse_text
from app.services.indicators import compute_indicator_values, surface_indicators
from tests.helpers import real_catalog

PHISH = (
    b"From: \"Support\" <support@paypal-update.example>\r\n"
    b"Return-Path: <bounce@mailer-x91.example>\r\n"
    b"Reply-To: help@other.example\r\n"
    b"Subject: URGENT!!! Verify your account\r\n"
    b"Authentication-Results: mx.local; spf=fail; dkim=none; dmarc=fail\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
    b"Dear customer, your account is suspended. Verify your password immediately at "
    b"http://203.0.113.9/login or http://bit.ly/abc now!\r\n"
)


def test_phishing_example_indicator_values(tmp_path):
    cat = real_catalog(tmp_path)
    v = compute_indicator_values(parse_eml(PHISH), cat.lexicons)
    assert len(v) == 20
    assert v["sender_domain_mismatch"] == 1.0 and v["reply_to_mismatch"] == 1.0
    assert v["spf_fail"] == 1.0 and v["dmarc_fail"] == 1.0
    assert v["dkim_fail"] == 0.0                          # 'none' is unknown, not a failure
    assert v["has_ip_url"] == 1.0 and v["uses_url_shortener"] == 1.0 and v["non_https_url"] == 1.0
    assert v["url_count"] == 2.0
    assert v["generic_greeting"] == 1.0
    assert v["urgency_keyword_count"] >= 3                # urgent, suspended, immediately
    assert v["credential_request_count"] >= 2             # verify x2, password
    assert v["exclamation_count"] == 4.0


def test_benign_email_has_no_surfaced_indicators(tmp_path):
    cat = real_catalog(tmp_path)
    parsed = parse_eml(
        b"From: Ana <ana@school.example>\r\nReturn-Path: <ana@school.example>\r\nSubject: Lunch\r\n"
        b"Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\r\n\r\n"
        b"Hi Ben, are we still meeting for lunch tomorrow? See https://school.example/menu\r\n"
    )
    values = compute_indicator_values(parsed, cat.lexicons)
    assert surface_indicators(values, cat) == ()
    assert values["spf_fail"] == 0.0 and values["url_count"] == 1.0


def test_surfaced_indicators_carry_catalog_text_in_catalog_order(tmp_path):
    cat = real_catalog(tmp_path)
    findings = surface_indicators(compute_indicator_values(parse_eml(PHISH), cat.lexicons), cat)
    keys = [f.feature_key for f in findings]
    assert {"sender_domain_mismatch", "spf_fail", "has_ip_url", "uses_url_shortener",
            "urgency_keyword_count", "generic_greeting"} <= set(keys)
    assert keys == sorted(keys, key=lambda k: cat.features[k].feature_id)
    ip = next(f for f in findings if f.feature_key == "has_ip_url")
    assert ip.insight_type == "Security Tip" and "raw IP addresses" in ip.message


def test_related_domains_do_not_count_as_mismatch(tmp_path):
    cat = real_catalog(tmp_path)
    parsed = parse_eml(b"From: a@example.com\r\nReturn-Path: <b@mail.example.com>\r\nSubject: s\r\n\r\nhello there\r\n")
    assert compute_indicator_values(parsed, cat.lexicons)["sender_domain_mismatch"] == 0.0


def test_free_mail_is_recorded_but_never_surfaced(tmp_path):
    cat = real_catalog(tmp_path)
    parsed = parse_eml(b"From: bob@gmail.com\r\nSubject: hi\r\n\r\nhello there friend\r\n")
    values = compute_indicator_values(parsed, cat.lexicons)
    assert values["free_mail_sender"] == 1.0
    assert all(f.feature_key != "free_mail_sender" for f in surface_indicators(values, cat))


def test_shouting_and_short_text_rules(tmp_path):
    cat = real_catalog(tmp_path)
    loud = parse_text("PLEASE READ THIS MESSAGE CAREFULLY BEFORE YOU DO ANYTHING ELSE TODAY")
    assert compute_indicator_values(loud, cat.lexicons)["uppercase_ratio"] > 0.9
    short = parse_text("OK THANKS")
    assert compute_indicator_values(short, cat.lexicons)["uppercase_ratio"] == 0.0   # < 20 letters


def test_pasted_body_without_headers_is_not_penalized_for_missing_auth(tmp_path):
    cat = real_catalog(tmp_path)
    values = compute_indicator_values(parse_text("Hello, the report is attached to the shared folder."), cat.lexicons)
    assert values["spf_fail"] == values["dkim_fail"] == values["dmarc_fail"] == 0.0
    assert values["sender_domain_mismatch"] == 0.0
