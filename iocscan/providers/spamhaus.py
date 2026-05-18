from __future__ import annotations

import asyncio
import ipaddress
import time

import httpx

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Provider, ProviderResult, Verdict

ENDPOINT = "https://www.spamhaus.org/drop/drop.txt"
_CACHE: dict[str, list[tuple[ipaddress.IPv4Network, str]]] = {}
_CACHE_TS: dict[str, float] = {}
_CACHE_TTL = 6 * 3600
# Module-level Lock: Python 3.10+ binds the lock to the running loop on
# first await rather than at construction, so this works under any loop
# the CLI happens to spawn. Do NOT downgrade Python to 3.9.
_LOCK = asyncio.Lock()
MAX_BODY = 50 * 1024 * 1024  # 50 MB — guard against OOM on hostile/MitM endpoints
_FAILURE_TTL = 30  # seconds before retrying after a fetch failure
_FAILED_UNTIL: dict[str, float] = {"ts": 0.0}


class Spamhaus(Provider):
    name = "spamhaus"
    supports = {IOCType.IP}
    requires_key = False
    max_rps = 1.0

    async def lookup(self, ioc: str, ioc_type: IOCType, client: httpx.AsyncClient, config: Config) -> ProviderResult:
        start = time.perf_counter()
        if ioc_type != IOCType.IP:
            return ProviderResult(self.name, Verdict.UNKNOWN, "—", None, None, 0)
        try:
            cidrs = await self._load(client)
        except httpx.HTTPError as e:
            return _err(self.name, f"network: {e.__class__.__name__}", start)
        except ValueError as e:
            return _err(self.name, str(e), start)
        latency = int((time.perf_counter() - start) * 1000)
        try:
            addr = ipaddress.ip_address(ioc)
        except ValueError:
            return ProviderResult(self.name, Verdict.UNKNOWN, "—", None, None, latency)
        for net, sbl in cidrs:
            if isinstance(addr, ipaddress.IPv4Address) and addr in net:
                return ProviderResult(self.name, Verdict.MALICIOUS, sbl, {"cidr": str(net), "sbl": sbl}, None, latency)
        return ProviderResult(self.name, Verdict.CLEAN, "—", None, None, latency)

    async def _load(self, client: httpx.AsyncClient) -> list[tuple[ipaddress.IPv4Network, str]]:
        now = time.time()
        if "data" in _CACHE and now - _CACHE_TS.get("data", 0) < _CACHE_TTL:
            return _CACHE["data"]
        loop = asyncio.get_running_loop()
        async with _LOCK:
            # re-check inside the lock
            now = time.time()
            if "data" in _CACHE and now - _CACHE_TS.get("data", 0) < _CACHE_TTL:
                return _CACHE["data"]
            mono = loop.time()
            if mono < _FAILED_UNTIL["ts"]:
                raise httpx.HTTPError(
                    f"in failure backoff for {_FAILED_UNTIL['ts'] - mono:.0f}s"
                )
            try:
                body = bytearray()
                async with client.stream("GET", ENDPOINT) as resp:
                    if resp.status_code >= 400:
                        raise ValueError(f"{resp.status_code}")
                    async for chunk in resp.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > MAX_BODY:
                            raise ValueError(
                                f"response too large (>{MAX_BODY} bytes)"
                            )
                text = body.decode("utf-8")
                cidrs: list[tuple[ipaddress.IPv4Network, str]] = []
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith(";"):
                        continue
                    parts = line.split(";")
                    if len(parts) < 2:
                        continue
                    cidr_str = parts[0].strip()
                    sbl = parts[1].strip()
                    try:
                        cidrs.append((ipaddress.IPv4Network(cidr_str, strict=False), sbl))
                    except ValueError:
                        continue
                _CACHE["data"] = cidrs
                _CACHE_TS["data"] = now
                return cidrs
            except Exception:
                _FAILED_UNTIL["ts"] = loop.time() + _FAILURE_TTL
                raise


def _err(name, msg, start):
    return ProviderResult(name, Verdict.ERROR, "", None, msg, int((time.perf_counter() - start) * 1000))
