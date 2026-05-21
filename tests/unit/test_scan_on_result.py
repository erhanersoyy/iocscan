from __future__ import annotations

import httpx

from iocscan.core.config import Config
from iocscan.core.scan import scan_ioc
from iocscan.providers.base import IOCType, Provider, ProviderResult, Verdict


class _StubProvider(Provider):
    requires_key = False
    max_rps = None
    enrichment_only = False

    def __init__(self, name: str, verdict: Verdict = Verdict.CLEAN):
        self.name = name
        self._verdict = verdict
        self.supports = {IOCType.IP}

    async def lookup(self, ioc, ioc_type, client, config):
        return ProviderResult(self.name, self._verdict, "", None, None, 1)


async def test_on_result_called_once_per_provider():
    providers = [_StubProvider(f"p{i}") for i in range(5)]
    seen: list[str] = []

    async with httpx.AsyncClient(timeout=1.0) as client:
        scan = await scan_ioc(
            "1.2.3.4", IOCType.IP, providers, client, Config(),
            on_result=lambda r: seen.append(r.provider),
        )
    assert sorted(seen) == ["p0", "p1", "p2", "p3", "p4"]
    assert {r.provider for r in scan.provider_results} == set(seen)


async def test_on_result_optional_keeps_existing_callers_working():
    providers = [_StubProvider("only")]
    async with httpx.AsyncClient(timeout=1.0) as client:
        scan = await scan_ioc("1.2.3.4", IOCType.IP, providers, client, Config())
    assert len(scan.provider_results) == 1
    assert scan.provider_results[0].provider == "only"


async def test_on_result_exception_does_not_break_scan():
    providers = [_StubProvider("only")]

    def bad_cb(_r):
        raise RuntimeError("cosmetic")

    async with httpx.AsyncClient(timeout=1.0) as client:
        scan = await scan_ioc(
            "1.2.3.4", IOCType.IP, providers, client, Config(),
            on_result=bad_cb,
        )
    assert len(scan.provider_results) == 1
