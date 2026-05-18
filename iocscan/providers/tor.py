from __future__ import annotations

import asyncio
import time

import httpx

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Provider, ProviderResult, Verdict

ENDPOINT = "https://check.torproject.org/torbulkexitlist"
_CACHE: dict[str, set[str]] = {}
_CACHE_TS: dict[str, float] = {}
_CACHE_TTL = 6 * 3600
# Module-level Lock: Python 3.10+ binds the lock to the running loop on
# first await rather than at construction, so this works under any loop
# the CLI happens to spawn. Do NOT downgrade Python to 3.9.
_LOCK = asyncio.Lock()


class Tor(Provider):
    name = "tor"
    supports = {IOCType.IP}
    requires_key = False
    max_rps = 1.0

    async def lookup(self, ioc: str, ioc_type: IOCType, client: httpx.AsyncClient, config: Config) -> ProviderResult:
        start = time.perf_counter()
        if ioc_type != IOCType.IP:
            return ProviderResult(self.name, Verdict.UNKNOWN, "—", None, None, 0)
        try:
            exits = await self._load(client)
        except httpx.HTTPError as e:
            return _err(self.name, f"network: {e.__class__.__name__}", start)
        except ValueError as e:
            return _err(self.name, str(e), start)
        latency = int((time.perf_counter() - start) * 1000)
        if ioc in exits:
            return ProviderResult(self.name, Verdict.SUSPICIOUS, "tor exit", None, None, latency)
        return ProviderResult(self.name, Verdict.CLEAN, "—", None, None, latency)

    async def _load(self, client: httpx.AsyncClient) -> set[str]:
        now = time.time()
        if "data" in _CACHE and now - _CACHE_TS.get("data", 0) < _CACHE_TTL:
            return _CACHE["data"]
        async with _LOCK:
            # re-check inside the lock
            now = time.time()
            if "data" in _CACHE and now - _CACHE_TS.get("data", 0) < _CACHE_TTL:
                return _CACHE["data"]
            resp = await client.get(ENDPOINT)
            if resp.status_code >= 400:
                raise ValueError(f"{resp.status_code}")
            exits = {line.strip() for line in resp.text.splitlines() if line.strip()}
            _CACHE["data"] = exits
            _CACHE_TS["data"] = now
            return exits


def _err(name, msg, start):
    return ProviderResult(name, Verdict.ERROR, "", None, msg, int((time.perf_counter() - start) * 1000))
