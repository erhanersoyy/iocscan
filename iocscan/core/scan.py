from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

import httpx

from iocscan.core.config import Config
from iocscan.core.verdict import aggregate, coverage
from iocscan.core.whitelist import is_whitelisted
from iocscan.providers.base import IOCType, Provider, ProviderResult, Verdict

log = logging.getLogger(__name__)


def _apply_whitelist(ioc: str, ioc_type: IOCType, raw_verdict: Verdict) -> tuple[Verdict, bool]:
    """Clamp MALICIOUS/SUSPICIOUS to CLEAN for whitelisted domains. Returns (verdict, whitelisted)."""
    whitelisted = is_whitelisted(ioc, ioc_type)
    if whitelisted and raw_verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS):
        return Verdict.CLEAN, True
    return raw_verdict, whitelisted

_RATE_LIMITERS: dict[str, "_RateLimiter"] = {}


class _RateLimiter:
    def __init__(self, max_rps: float | None):
        self.min_interval = 1.0 / max_rps if max_rps and max_rps > 0 else 0.0
        self._lock = asyncio.Lock()
        self._last_call: float = 0.0

    async def wait(self) -> None:
        if self.min_interval <= 0:
            return
        loop = asyncio.get_running_loop()
        async with self._lock:
            now = loop.time()
            delay = self.min_interval - (now - self._last_call)
            # Update last_call to scheduled time BEFORE sleeping, then release
            # lock so concurrent callers can compute their own scheduled time
            # immediately rather than waiting in a chain of held-lock sleeps.
            scheduled = now + max(delay, 0)
            self._last_call = scheduled
        if delay > 0:
            await asyncio.sleep(delay)


def _limiter_for(provider: Provider) -> _RateLimiter:
    lim = _RATE_LIMITERS.get(provider.name)
    if lim is None:
        lim = _RateLimiter(getattr(provider, "max_rps", None))
        _RATE_LIMITERS[provider.name] = lim
    return lim


async def _throttled_lookup(
    provider: Provider,
    ioc: str,
    ioc_type: IOCType,
    client: httpx.AsyncClient,
    config: Config,
) -> ProviderResult:
    log.debug("%s lookup starting for %s (%s)", provider.name, ioc, ioc_type.value)
    await _limiter_for(provider).wait()
    result = await provider.lookup(ioc, ioc_type, client, config)
    log.debug(
        "%s lookup result for %s: verdict=%s score=%r error=%r latency=%dms",
        provider.name, ioc, result.verdict.value, result.score, result.error, result.latency_ms,
    )
    return result


@dataclass(frozen=True)
class ScanResult:
    ioc: str
    ioc_type: IOCType
    verdict: Verdict
    provider_results: list[ProviderResult]
    responding: int
    total: int
    whitelisted: bool = False


async def scan_ioc(
    ioc: str,
    ioc_type: IOCType,
    providers: list[Provider],
    client: httpx.AsyncClient,
    config: Config,
) -> ScanResult:
    applicable = [p for p in providers if ioc_type in p.supports]
    tasks = [_throttled_lookup(p, ioc, ioc_type, client, config) for p in applicable]
    raw = await asyncio.gather(*tasks, return_exceptions=True)
    results: list[ProviderResult] = []
    for provider, item in zip(applicable, raw):
        if isinstance(item, (KeyboardInterrupt, asyncio.CancelledError, SystemExit)):
            # Propagate user-driven interrupts and event-loop cancellations
            # instead of converting them into ERROR rows.
            raise item
        if isinstance(item, BaseException):
            results.append(ProviderResult(
                provider.name, Verdict.ERROR, "", None,
                f"unhandled: {item.__class__.__name__}: {item}", 0,
            ))
        else:
            results.append(item)
    raw_verdict = aggregate(results, min_coverage=config.min_coverage)
    responding, total = coverage(results)
    final_verdict, whitelisted = _apply_whitelist(ioc, ioc_type, raw_verdict)
    return ScanResult(
        ioc=ioc, ioc_type=ioc_type, verdict=final_verdict,
        provider_results=results, responding=responding, total=total,
        whitelisted=whitelisted,
    )
