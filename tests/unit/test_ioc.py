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
