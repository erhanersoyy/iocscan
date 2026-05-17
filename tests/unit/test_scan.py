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
    assert result.verdict == Verdict.CLEAN  # 2 mal / 5 — not majority
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
