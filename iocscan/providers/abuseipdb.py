from __future__ import annotations

import time

import httpx

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Provider, ProviderResult, Verdict, err_result as _err

ENDPOINT = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDB(Provider):
    name = "abuseipdb"
    supports = {IOCType.IP}
    requires_key = True
    max_rps = 1.0
    max_per_day = 1000

    async def lookup(self, ioc: str, ioc_type: IOCType, client: httpx.AsyncClient, config: Config) -> ProviderResult:
        if ioc_type != IOCType.IP:
            return ProviderResult(self.name, Verdict.UNKNOWN, "—", None, None, 0)
        key = config.key_for(self.name)
        if not key:
            return ProviderResult(self.name, Verdict.ERROR, "", None, "key required", 0)
        start = time.perf_counter()
        try:
            resp = await client.get(
                ENDPOINT,
                params={"ipAddress": ioc, "maxAgeInDays": "90"},
                headers={"Key": key, "Accept": "application/json"},
            )
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
            score = int(data["data"]["abuseConfidenceScore"])
        except (ValueError, KeyError):
            return ProviderResult(self.name, Verdict.ERROR, "", None, "parse error", latency)
        if score >= 75:
            v = Verdict.MALICIOUS
        elif score >= 25:
            v = Verdict.SUSPICIOUS
        else:
            v = Verdict.CLEAN
        return ProviderResult(self.name, v, f"{score}%", data, None, latency)
