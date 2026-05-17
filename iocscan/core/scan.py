from __future__ import annotations

import asyncio
from dataclasses import dataclass

import httpx

from iocscan.core.config import Config
from iocscan.core.verdict import aggregate, coverage
from iocscan.providers.base import IOCType, Provider, ProviderResult, Verdict


@dataclass(frozen=True)
class ScanResult:
    ioc: str
    ioc_type: IOCType
    verdict: Verdict
    provider_results: list[ProviderResult]
    responding: int
    total: int


async def scan_ioc(
    ioc: str,
    ioc_type: IOCType,
    providers: list[Provider],
    client: httpx.AsyncClient,
    config: Config,
) -> ScanResult:
    applicable = [p for p in providers if ioc_type in p.supports]
    tasks = [p.lookup(ioc, ioc_type, client, config) for p in applicable]
    results = await asyncio.gather(*tasks)
    final_verdict = aggregate(results, min_coverage=config.min_coverage)
    responding, total = coverage(results)
    return ScanResult(
        ioc=ioc, ioc_type=ioc_type, verdict=final_verdict,
        provider_results=results, responding=responding, total=total,
    )
