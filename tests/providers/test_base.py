from iocscan.providers.base import IOCType, Verdict, ProviderResult, Provider


def test_iocype_enum_values():
    assert IOCType.IP.value == "ip"
    assert IOCType.DOMAIN.value == "domain"


def test_ioctype_has_hash_and_url_members():
    assert IOCType.HASH_MD5.value == "hash_md5"
    assert IOCType.HASH_SHA1.value == "hash_sha1"
    assert IOCType.HASH_SHA256.value == "hash_sha256"
    assert IOCType.URL.value == "url"


def test_ioctype_existing_members_unchanged():
    assert IOCType.IP.value == "ip"
    assert IOCType.DOMAIN.value == "domain"


def test_verdict_enum_values():
    assert Verdict.MALICIOUS.value == "malicious"
    assert Verdict.SUSPICIOUS.value == "suspicious"
    assert Verdict.CLEAN.value == "clean"
    assert Verdict.UNKNOWN.value == "unknown"
    assert Verdict.ERROR.value == "error"


def test_provider_result_is_frozen():
    r = ProviderResult(
        provider="x", verdict=Verdict.CLEAN, score="—",
        raw=None, error=None, latency_ms=42,
    )
    import dataclasses
    with __import__("pytest").raises(dataclasses.FrozenInstanceError):
        r.score = "hit"


def test_provider_is_abstract():
    import pytest
    with pytest.raises(TypeError):
        Provider()  # cannot instantiate ABC


class _Dummy(Provider):
    name = "dummy"
    supports = {IOCType.IP}

    async def lookup(self, ioc, ioc_type, client, config):
        return ProviderResult(self.name, Verdict.CLEAN, "", None, None, 0)


def test_provider_permalink_default_returns_none():
    p = _Dummy()
    assert p.permalink("1.2.3.4", IOCType.IP) is None


def test_provider_enrichment_only_defaults_false():
    p = _Dummy()
    assert p.enrichment_only is False


def test_provider_key_alias_default_is_none():
    p = _Dummy()
    assert p.key_alias is None


def test_provider_has_key_uses_key_alias_when_set():
    """A provider with `key_alias` should look up that name, not its own."""
    from iocscan.core.config import Config

    class _Aliased(Provider):
        name = "downstream"
        supports = {IOCType.IP}
        requires_key = True
        key_alias = "shared"

        async def lookup(self, ioc, ioc_type, client, config):
            return ProviderResult(self.name, Verdict.CLEAN, "", None, None, 0)

    p = _Aliased()
    cfg_with = Config(keys={"shared": "VALUE"})
    cfg_without = Config(keys={"downstream": "VALUE"})  # wrong name → still missing
    assert p.has_key(cfg_with) is True
    assert p.has_key(cfg_without) is False
