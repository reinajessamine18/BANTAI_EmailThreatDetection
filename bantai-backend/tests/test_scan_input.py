import base64

import pytest

from app.services.scan_input import ScanInputError, clean_file_name, parse_scan_input

EML = b"From: a@b.example\r\nSubject: Hello\r\n\r\nPlease verify http://x.example/a\r\n"


def test_eml_as_text_and_as_base64_give_the_same_result():
    a, size_a = parse_scan_input("eml_upload", EML.decode(), "text")
    b, size_b = parse_scan_input("eml_upload", base64.b64encode(EML).decode(), "base64")
    assert a.content_sha256 == b.content_sha256 and size_a == size_b == len(EML)
    assert a.subject == "Hello" and a.urls[0].domain == "x.example"


def test_base64_preserves_non_utf8_bytes():
    raw = b"From: a@b.example\r\nSubject: s\r\nContent-Type: text/plain; charset=latin-1\r\n\r\ncaf\xe9 verify\r\n"
    parsed, _ = parse_scan_input("eml_upload", base64.b64encode(raw).decode(), "base64")
    assert "café" in parsed.body_text


def test_raw_text_body_only_and_with_headers():
    body_only, _ = parse_scan_input("raw_text", "Dear customer, click here", "text")
    assert not body_only.had_headers
    with_headers, _ = parse_scan_input("raw_text", "Subject: Hi\n\nHello there", "text")
    assert with_headers.had_headers and with_headers.subject == "Hi"


@pytest.mark.parametrize("method,content,encoding,code", [
    ("eml_upload", "!!!not base64!!!", "base64", "invalid_base64"),
    ("raw_text", "aGVsbG8=", "base64", "invalid_encoding"),
    ("eml_upload", "x", "rot13", "invalid_encoding"),
    ("fax", "x", "text", "invalid_input_method"),
    ("raw_text", "   \n  ", "text", "unparseable"),
])
def test_bad_submissions_get_stable_codes(method, content, encoding, code):
    with pytest.raises(ScanInputError) as err:
        parse_scan_input(method, content, encoding)
    assert err.value.code == code and err.value.status == 422


def test_oversize_is_413_for_text_and_base64_and_leaks_nothing():
    secret = "SECRET-BODY " * 50
    with pytest.raises(ScanInputError) as err:
        parse_scan_input("raw_text", secret, "text", max_bytes=100)
    assert err.value.status == 413 and err.value.code == "too_large" and "SECRET" not in err.value.message
    with pytest.raises(ScanInputError) as err2:
        parse_scan_input("eml_upload", base64.b64encode(secret.encode()).decode(), "base64", max_bytes=100)
    assert err2.value.status == 413


def test_attachment_only_eml_is_unparseable_not_a_crash():
    from email.message import EmailMessage
    m = EmailMessage()
    m["From"] = "a@b.example"
    m.add_attachment(b"x", maintype="application", subtype="pdf", filename="a.pdf")
    with pytest.raises(ScanInputError) as err:
        parse_scan_input("eml_upload", base64.b64encode(m.as_bytes()).decode(), "base64")
    assert err.value.code == "unparseable"


@pytest.mark.parametrize("raw,clean", [
    ("MicTest.eml", "MicTest.eml"),
    ("C:\\Users\\bob\\Desktop\\mail.eml", "mail.eml"),
    ("../../etc/passwd", "passwd"),
    ("bad\x00na\nme.eml", "badname.eml"),
    ("", None), (None, None), ("   ", None), ("dir/", None),
])
def test_clean_file_name(raw, clean):
    assert clean_file_name(raw) == clean


def test_clean_file_name_is_capped():
    assert len(clean_file_name("a" * 1000 + ".eml")) == 255
