from iocscan.providers.base import IOCType, Verdict, ProviderResult, Provider


def test_iocype_enum_values():
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
