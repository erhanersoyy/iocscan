from __future__ import annotations

import asyncio
import time

import httpx

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Provider, ProviderResult, Verdict

ENDPOINT = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
_CACHE: dict[str, dict] = {}
_CACHE_TS: dict[str, float] = {}
_CACHE_TTL = 6 * 3600  # in-process cache 6h
# Module-level Lock: Python 3.10+ binds the lock to the running loop on
# first await rather than at construction, so this works under any loop
# the CLI happens to spawn. Do NOT downgrade Python to 3.9.
_LOCK = asyncio.Lock()


class Feodo(Provider):
    name = "feodo"
    supports = {IOCType.IP}
    requires_key = False
    max_rps = 1.0

    async def lookup(self, ioc: str, ioc_type: IOCType, client: httpx.AsyncClient, config: Config) -> ProviderResult:
        start = time.perf_counter()
        if ioc_type != IOCType.IP:
            return ProviderResult(self.name, Verdict.UNKNOWN, "—", None, None, 0)
        try:
            blocklist = await self._load(client)
        except httpx.HTTPError as e:
            return _err(self.name, f"network: {e.__class__.__name__}", start)
        except ValueError as e:
            return _err(self.name, str(e), start)
        latency = int((time.perf_counter() - start) * 1000)
        if ioc in blocklist:
            entry = blocklist[ioc]
            malware = entry.get("malware", "C2")
            return ProviderResult(self.name, Verdict.MALICIOUS, malware, entry, None, latency)
        return ProviderResult(self.name, Verdict.CLEAN, "—", None, None, latency)

    async def _load(self, client: httpx.AsyncClient) -> dict[str, dict]:
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
            data = resp.json()
            index = {entry["ip_address"]: entry for entry in data}
            _CACHE["data"] = index
            _CACHE_TS["data"] = now
            return index


def _err(name: str, msg: str, start: float) -> ProviderResult:
    latency = int((time.perf_counter() - start) * 1000)
    return ProviderResult(name, Verdict.ERROR, "", None, msg, latency)
