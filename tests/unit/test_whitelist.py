import pytest

from iocscan.core.whitelist import is_whitelisted
from iocscan.providers.base import IOCType


@pytest.fixture(autouse=True)
def _clear_tranco_lru():
    from iocscan.core import whitelist
    whitelist._tranco_cache.cache_clear()
    yield
    whitelist._tranco_cache.cache_clear()


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


def test_tranco_cache_contributes_to_whitelist(tmp_path, monkeypatch):
    from iocscan.core import tranco, whitelist
    # Write a fake tranco cache that includes "example-not-bundled.com"
    cache_path = tmp_path / ".iocscan" / "tranco-1k.txt"
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text("example-not-bundled.com\nfoo-popular.com\n")
    # Repoint tranco's CACHE_PATH to the temp file
    monkeypatch.setattr(tranco, "CACHE_PATH", cache_path)
    # Clear the lru_cache used by whitelist (autouse fixture already did this,
    # but we need it cleared again after monkeypatching)
    whitelist._tranco_cache.cache_clear()
    assert whitelist.is_whitelisted("example-not-bundled.com", IOCType.DOMAIN) is True
    assert whitelist.is_whitelisted("sub.foo-popular.com", IOCType.DOMAIN) is True
    assert whitelist.is_whitelisted("evil.com", IOCType.DOMAIN) is False
