import httpx
import pytest

from iocscan.core.config import Config
from iocscan.core.scan import ScanResult, scan_ioc
from iocscan.providers.base import IOCType, Provider, ProviderResult, Verdict


@pytest.fixture(autouse=True)
def _reset_rate_limiters():
    from iocscan.core import scan as scan_mod
    scan_mod._RATE_LIMITERS.clear()
    yield


class FakeProvider(Provider):
    def __init__(self, name, verdict, supports=None, max_rps=None):
        self.name = name
        self.supports = supports or {IOCType.IP, IOCType.DOMAIN}
        self.requires_key = False
        self._verdict = verdict
        if max_rps is not None:
            self.max_rps = max_rps

    async def lookup(self, ioc, ioc_type, client, config):
        return ProviderResult(self.name, self._verdict, "x", None, None, 5)


async def test_scan_ioc_runs_all_providers_in_parallel():
    providers = [
        FakeProvider("a", Verdict.MALICIOUS),
        FakeProvider("b", Verdict.MALICIOUS),
        FakeProvider("c", Verdict.CLEAN),
        FakeProvider("d", Verdict.CLEAN),
        FakeProvider("e", Verdict.CLEAN),
    ]
    async with httpx.AsyncClient() as client:
        result = await scan_ioc("1.2.3.4", IOCType.IP, providers, client, Config())
    assert isinstance(result, ScanResult)
    assert result.ioc == "1.2.3.4"
    assert result.verdict == Verdict.MALICIOUS  # 2 mal / 5 = 40% >= 30% threshold
    assert len(result.provider_results) == 5


async def test_scan_ioc_filters_unsupported_providers():
    providers = [
        FakeProvider("ip_only", Verdict.CLEAN, supports={IOCType.IP}),
        FakeProvider("both", Verdict.CLEAN),
    ]
    async with httpx.AsyncClient() as client:
        result = await scan_ioc("evil.com", IOCType.DOMAIN, providers, client, Config())
    names = {r.provider for r in result.provider_results}
    assert names == {"both"}


async def test_scan_ioc_respects_max_rps(monkeypatch):
    """A provider with max_rps=10 should be called with ~0.1s spacing across two scans."""
    from iocscan.core import scan as scan_mod
    scan_mod._RATE_LIMITERS.clear()

    timestamps: list[float] = []

    class TimedProvider(Provider):
        name = "timed"
        supports = {IOCType.IP}
        requires_key = False
        max_rps = 10.0  # min interval 100ms

        async def lookup(self, ioc, ioc_type, client, config):
            import time
            timestamps.append(time.perf_counter())
            return ProviderResult(self.name, Verdict.CLEAN, "ok", None, None, 0)

    providers = [TimedProvider()]
    async with httpx.AsyncClient() as client:
        await scan_ioc("1.1.1.1", IOCType.IP, providers, client, Config())
        await scan_ioc("2.2.2.2", IOCType.IP, providers, client, Config())

    assert len(timestamps) == 2
    gap = timestamps[1] - timestamps[0]
    assert gap >= 0.08, f"expected ≥0.08s between calls due to throttle, got {gap:.3f}s"


async def test_scan_ioc_isolates_provider_exceptions():
    """A provider that raises must not crash the scan; result becomes ERROR."""
    class CrashyProvider(Provider):
        name = "crashy"
        supports = {IOCType.IP, IOCType.DOMAIN}
        requires_key = False

        async def lookup(self, ioc, ioc_type, client, config):
            raise RuntimeError("boom")

    providers = [
        FakeProvider("a", Verdict.CLEAN),
        CrashyProvider(),
        FakeProvider("b", Verdict.CLEAN),
        FakeProvider("c", Verdict.CLEAN),
    ]
    async with httpx.AsyncClient() as client:
        result = await scan_ioc("1.2.3.4", IOCType.IP, providers, client, Config())
    # Crashy provider should appear as ERROR, others normal
    by_name = {r.provider: r for r in result.provider_results}
    assert by_name["crashy"].verdict == Verdict.ERROR
    assert "boom" in (by_name["crashy"].error or "") or "RuntimeError" in (by_name["crashy"].error or "")
    assert by_name["a"].verdict == Verdict.CLEAN
    assert result.verdict == Verdict.CLEAN  # 3 clean responders, majority


async def test_whitelist_overrides_malicious_verdict():
    """A whitelisted domain that providers flag malicious gets clamped to CLEAN."""
    providers = [
        FakeProvider("a", Verdict.MALICIOUS),
        FakeProvider("b", Verdict.MALICIOUS),
        FakeProvider("c", Verdict.MALICIOUS),
        FakeProvider("d", Verdict.CLEAN),
        FakeProvider("e", Verdict.CLEAN),
    ]
    async with httpx.AsyncClient() as client:
        result = await scan_ioc("cloudflare.com", IOCType.DOMAIN, providers, client, Config())
    assert result.whitelisted is True
    assert result.verdict == Verdict.CLEAN


async def test_non_whitelisted_not_overridden():
    providers = [
        FakeProvider("a", Verdict.MALICIOUS),
        FakeProvider("b", Verdict.MALICIOUS),
        FakeProvider("c", Verdict.MALICIOUS),
    ]
    async with httpx.AsyncClient() as client:
        result = await scan_ioc("evil.com", IOCType.DOMAIN, providers, client, Config())
    assert result.whitelisted is False
    assert result.verdict == Verdict.MALICIOUS


async def test_apply_whitelist_helper_clamps_malicious():
    """_apply_whitelist clamps M/S verdicts on whitelisted domains."""
    from iocscan.core.scan import _apply_whitelist
    v, w = _apply_whitelist("google.com", IOCType.DOMAIN, Verdict.MALICIOUS)
    assert v == Verdict.CLEAN
    assert w is True


async def test_apply_whitelist_helper_preserves_clean():
    from iocscan.core.scan import _apply_whitelist
    v, w = _apply_whitelist("google.com", IOCType.DOMAIN, Verdict.CLEAN)
    assert v == Verdict.CLEAN
    assert w is True


async def test_apply_whitelist_helper_non_whitelisted():
    from iocscan.core.scan import _apply_whitelist
    v, w = _apply_whitelist("evil.com", IOCType.DOMAIN, Verdict.MALICIOUS)
    assert v == Verdict.MALICIOUS
    assert w is False
