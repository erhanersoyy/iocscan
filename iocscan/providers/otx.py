from __future__ import annotations

import time

import httpx

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Provider, ProviderResult, Verdict, err_result as _err

BASE = "https://otx.alienvault.com/api/v1/indicators"


class OTX(Provider):
    name = "otx"
    supports = {IOCType.IP, IOCType.DOMAIN, IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256}
    requires_key = True
    max_rps = 5.0

    async def lookup(self, ioc: str, ioc_type: IOCType, client: httpx.AsyncClient, config: Config) -> ProviderResult:
        key = config.key_for(self.name)
        if not key:
            return ProviderResult(self.name, Verdict.ERROR, "", None, "key required", 0)
        if ioc_type == IOCType.IP:
            path_prefix = "IPv4"
        elif ioc_type == IOCType.DOMAIN:
            path_prefix = "domain"
        else:
            path_prefix = "file"   # hash variants
        url = f"{BASE}/{path_prefix}/{ioc}/general"
        start = time.perf_counter()
        try:
            resp = await client.get(url, headers={"X-OTX-API-KEY": key})
        except httpx.HTTPError as e:
            return _err(self.name, f"network: {e.__class__.__name__}", start)
        latency = int((time.perf_counter() - start) * 1000)
        if resp.status_code == 429:
            return ProviderResult(self.name, Verdict.ERROR, "", None, "429 rate limit", latency)
        if resp.status_code in (401, 403):
            return ProviderResult(self.name, Verdict.ERROR, "", None, "auth failed", latency)
        if resp.status_code >= 400:
            return ProviderResult(self.name, Verdict.ERROR, "", None, f"{resp.status_code}", latency)
        try:
            data = resp.json()
            count = int(data.get("pulse_info", {}).get("count", 0))
        except (ValueError, KeyError):
            return ProviderResult(self.name, Verdict.ERROR, "", None, "parse error", latency)
        if count >= 3:
            v = Verdict.MALICIOUS
        elif count >= 1:
            v = Verdict.SUSPICIOUS
        else:
            v = Verdict.CLEAN
        return ProviderResult(self.name, v, f"{count} pulses", data, None, latency)
