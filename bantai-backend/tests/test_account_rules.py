import base64

import pytest

from app.services.account_rules import MAX_PICTURE_CHARS, clean_text, is_valid_picture, normalize_email

PNG = "data:image/png;base64," + base64.b64encode(b"\x89PNG fake image bytes").decode()


@pytest.mark.parametrize("value", [
    PNG, "data:image/jpeg;base64,AAAA", "data:image/webp;base64,AAAA", "data:image/gif;base64,AAA=",
])
def test_raster_data_uris_are_accepted(value):
    assert is_valid_picture(value)


@pytest.mark.parametrize("value", [
    "data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=",             # SVG can carry scripts
    "data:text/html;base64,PHNjcmlwdD4=", "javascript:alert(1)", "http://evil.example/a.png",
    "data:image/png;base64,", "data:image/png;base64,AA AA", "data:image/png;base64,AAAA\n",
    "data:image/png;base64,AAAA<script>", "data:image/png,AAAA", "", "data:image/png;base64,AAAA====",
])
def test_everything_else_is_rejected(value):
    assert not is_valid_picture(value)


def test_picture_size_cap_matches_the_database_check():
    ok = "data:image/png;base64," + "A" * (MAX_PICTURE_CHARS - 22)
    assert len(ok) == MAX_PICTURE_CHARS and is_valid_picture(ok)
    assert not is_valid_picture(ok + "A")


@pytest.mark.parametrize("raw,limit,expected", [
    ("  Ana   Test ", 120, "Ana Test"), ("A\x00b\nc\td", 120, "A b c d"), (None, 120, ""),
    ("x" * 500, 120, "x" * 120), ("\x00\x01", 120, ""),
])
def test_clean_text(raw, limit, expected):
    assert clean_text(raw, limit) == expected


@pytest.mark.parametrize("raw,expected", [
    (" Ana@Example.COM ", "ana@example.com"), ("a@b.co", "a@b.co"),
    ("nope", None), ("a@b", None), ("a b@c.com", None), ("", None), (None, None), ("a@b.com" + "x" * 300, None),
])
def test_normalize_email(raw, expected):
    assert normalize_email(raw) == expected
