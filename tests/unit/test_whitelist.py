from iocscan.core.whitelist import is_whitelisted
from iocscan.providers.base import IOCType


def test_exact_domain_match():
    assert is_whitelisted("cloudflare.com", IOCType.DOMAIN) is True


def test_subdomain_match():
    assert is_whitelisted("api.cloudflare.com", IOCType.DOMAIN) is True
    assert is_whitelisted("www.google.com", IOCType.DOMAIN) is True
    assert is_whitelisted("foo.bar.github.com", IOCType.DOMAIN) is True


def test_non_whitelisted_domain():
    assert is_whitelisted("evil.com", IOCType.DOMAIN) is False
    assert is_whitelisted("example.com", IOCType.DOMAIN) is False


def test_ip_never_whitelisted():
    assert is_whitelisted("8.8.8.8", IOCType.IP) is False
    assert is_whitelisted("1.1.1.1", IOCType.IP) is False


def test_case_insensitive():
    assert is_whitelisted("Cloudflare.COM", IOCType.DOMAIN) is True
