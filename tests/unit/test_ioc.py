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
    ("https://evil.com/path?x=1",     IOCType.URL),
    ("hxxp://1.2.3[.]4/abc",          IOCType.URL),
    ("not an ioc",                    None),
    ("",                              None),
    ("999.999.999.999",               None),
])
def test_detect_type(value, expected):
    assert detect_type(value) == expected


@pytest.mark.parametrize("value,expected", [
    ("http://evil.com/path",                          IOCType.URL),
    ("https://evil.com",                              IOCType.URL),    # URL even without path
    ("hxxps://corporate-login[.]xyz/auth?token=ABC",  IOCType.URL),
    ("https://1.2.3.4/admin",                         IOCType.URL),
    ("ftp://evil.com/file",                           None),           # non-http(s) schemes rejected
    ("://nothing",                                    None),           # malformed
    ("https://",                                      None),           # no host
])
def test_detect_type_url(value, expected):
    assert detect_type(value) == expected


def test_parse_iocs_preserves_url_path_case():
    """URL path is case-sensitive per RFC 3986; host is not."""
    parsed = parse_iocs(["HTTP://EVIL.COM/CaseSensitivePath?Q=A"])
    assert parsed == [("http://evil.com/CaseSensitivePath?Q=A", IOCType.URL)]


def test_parse_iocs_url_refangs_hxxp():
    parsed = parse_iocs(["hxxps://evil[.]com/path"])
    assert parsed == [("https://evil.com/path", IOCType.URL)]


@pytest.mark.parametrize("crafted", [
    'https://evil.com/path" OR url IN ("',            # double-quote smuggling
    "https://evil.com/path' OR url IN ('",            # single-quote smuggling
    "https://evil.com/path with space",                # raw whitespace
    "https://evil.com/path\twith\ttabs",               # control whitespace
    "https://evil.com/path\nwith\nnewlines",           # CRLF
    "https://evil.com/path`with`backtick",             # shell meta
    "https://evil.com/path\\with\\backslash",          # backslash
])
def test_detect_type_rejects_unsafe_url_chars(crafted):
    """SIEM-query-injection defense: unencoded quotes, whitespace, and
    control characters must NOT survive into a URL IOC."""
    assert detect_type(crafted) is None


def test_parse_iocs_url_preserves_port():
    """URL normalization must keep the port intact while lowercasing the host."""
    parsed = parse_iocs(["HTTPS://Evil.com:8443/Path"])
    assert parsed == [("https://evil.com:8443/Path", IOCType.URL)]


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
