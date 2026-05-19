import pytest

from iocscan.core.whitelist import is_whitelisted
from iocscan.providers.base import IOCType


@pytest.fixture(autouse=True)
def _clean_tranco_cache(tmp_path, monkeypatch):
    """Force tranco cache to be empty for all tests in this file."""
    from iocscan.core import tranco, whitelist
    monkeypatch.setattr(tranco, "CACHE_PATH", tmp_path / "nonexistent-tranco.txt")
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


def test_hash_never_whitelisted():
    assert is_whitelisted("d41d8cd98f00b204e9800998ecf8427e", IOCType.HASH_MD5) is False
    assert is_whitelisted("da39a3ee5e6b4b0d3255bfef95601890afd80709", IOCType.HASH_SHA1) is False
    assert is_whitelisted("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", IOCType.HASH_SHA256) is False


def test_case_insensitive():
    assert is_whitelisted("Cloudflare.COM", IOCType.DOMAIN) is True


@pytest.mark.parametrize("attacker_host", [
    "evil-bucket.s3.amazonaws.com",
    "malware.cloudfront.net",
    "phish.azurewebsites.net",
    "exfil.azureedge.net",
    "evil.raw.githubusercontent.com",
])
def test_shared_tenant_subdomains_not_whitelisted(attacker_host):
    """Subdomains of shared-tenant platforms must NOT be whitelisted."""
    from iocscan.core.whitelist import is_whitelisted
    assert is_whitelisted(attacker_host, IOCType.DOMAIN) is False, \
        f"{attacker_host} should NOT be whitelisted"


def test_url_never_whitelisted():
    """URLs always go through; even whitelisted hosts can serve malicious paths."""
    from iocscan.core.whitelist import is_whitelisted
    from iocscan.providers.base import IOCType
    assert is_whitelisted("https://evil.com/path", IOCType.URL) is False
    # Even an URL on a whitelisted DOMAIN host must NOT be whitelisted as URL.
    assert is_whitelisted("https://cloudflare.com/login", IOCType.URL) is False


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
