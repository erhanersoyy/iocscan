import pytest

from iocscan.core.ioc import defang, detect_type, parse_iocs
from iocscan.providers.base import IOCType


@pytest.mark.parametrize("raw,expected", [
    ("1.2.3[.]4",       "1.2.3.4"),
    ("1.2.3(.)4",       "1.2.3.4"),
    ("hxxp://evil.com", "http://evil.com"),
    ("evil[dot]com",    "evil.com"),
    ("evil.com",        "evil.com"),
])
def test_defang(raw, expected):
    assert defang(raw) == expected


@pytest.mark.parametrize("value,expected", [
    ("8.8.8.8",                       IOCType.IP),
    ("2001:db8::1",                   IOCType.IP),
    ("evil.com",                      IOCType.DOMAIN),
    ("sub.example.co.uk",             IOCType.DOMAIN),
    ("https://evil.com/path?x=1",     IOCType.DOMAIN),
    ("hxxp://1.2.3[.]4/abc",          IOCType.IP),
    ("not an ioc",                    None),
    ("",                              None),
    ("999.999.999.999",               None),
])
def test_detect_type(value, expected):
    assert detect_type(value) == expected


def test_parse_iocs_dedupes_and_normalizes():
    raw = ["1.2.3.4", "1.2.3[.]4", "EVIL.COM", "evil.com", "garbage"]
    parsed = parse_iocs(raw)
    assert ("1.2.3.4", IOCType.IP) in parsed
    assert ("evil.com", IOCType.DOMAIN) in parsed
    assert len(parsed) == 2  # dedupe + invalid drop


def test_parse_iocs_returns_warnings_for_invalid():
    parsed, warnings = parse_iocs(["1.2.3.4", "garbage"], return_warnings=True)
    assert parsed == [("1.2.3.4", IOCType.IP)]
    assert "garbage" in warnings[0]


# --- to_defanged + round-trip with refang (existing defang) ---

from iocscan.core.ioc import to_defanged, defang


def test_to_defanged_replaces_all_dots():
    assert to_defanged("evil.com") == "evil[.]com"
    assert to_defanged("sub.evil.com") == "sub[.]evil[.]com"
    assert to_defanged("1.2.3.4") == "1[.]2[.]3[.]4"


def test_to_defanged_no_dots_unchanged():
    assert to_defanged("localhost") == "localhost"


def test_defang_to_defanged_round_trip():
    """Refanging a previously defanged string returns the canonical form."""
    canonical = "1.2.3.4"
    assert defang(to_defanged(canonical)) == canonical

    canonical = "evil.example.com"
    assert defang(to_defanged(canonical)) == canonical


# --- hash detection ---


@pytest.mark.parametrize("value,expected", [
    ("d41d8cd98f00b204e9800998ecf8427e",                                       IOCType.HASH_MD5),    # MD5 of empty string
    ("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",                               IOCType.HASH_SHA1),   # SHA-1 uppercase
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",       IOCType.HASH_SHA256),
])
def test_detect_type_hash(value, expected):
    assert detect_type(value) == expected


@pytest.mark.parametrize("value", [
    "0" * 32,            # all-zero sentinel
    "f" * 64,            # all-f sentinel
    "abc",               # too short
    "g" * 32,            # not hex
    "abcd1234" * 4 + "z",# 33 chars (off-by-one)
])
def test_detect_type_rejects_non_hash(value):
    # Should NOT be classified as a hash. May return None or another type.
    result = detect_type(value)
    assert result not in (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256)


def test_parse_iocs_normalizes_hash_to_lowercase():
    parsed = parse_iocs(["D41D8CD98F00B204E9800998ECF8427E"])
    assert parsed == [("d41d8cd98f00b204e9800998ecf8427e", IOCType.HASH_MD5)]
