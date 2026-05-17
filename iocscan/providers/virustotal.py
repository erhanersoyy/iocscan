from __future__ import annotations

import time

import httpx

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Provider, ProviderResult, Verdict

BASE = "https://www.virustotal.com/api/v3"


class VirusTotal(Provider):
    name = "virustotal"
    supports = {IOCType.IP, IOCType.DOMAIN}
    requires_key = True
    max_rps = 0.06       # 4 req/min free tier
    max_per_day = 500

    async def lookup(self, ioc: str, ioc_type: IOCType, client: httpx.AsyncClient, config: Config) -> ProviderResult:
        key = config.key_for(self.name)
        if not key:
            return ProviderResult(self.name, Verdict.ERROR, "", None, "key required", 0)
        path = "ip_addresses" if ioc_type == IOCType.IP else "domains"
        start = time.perf_counter()
        try:
            resp = await client.get(f"{BASE}/{path}/{ioc}", headers={"x-apikey": key})
        except httpx.HTTPError as e:
            return _err(self.name, f"network: {e.__class__.__name__}", start)
        latency = int((time.perf_counter() - start) * 1000)
        if resp.status_code == 429:
            return ProviderResult(self.name, Verdict.ERROR, "", None, "429 rate limit", latency)
        if resp.status_code in (401, 403):
            return ProviderResult(self.name, Verdict.ERROR, "", None, "auth failed", latency)
        if resp.status_code == 404:
            return ProviderResult(self.name, Verdict.UNKNOWN, "—", None, None, latency)
        if resp.status_code >= 400:
            return ProviderResult(self.name, Verdict.ERROR, "", None, f"{resp.status_code}", latency)
        try:
            data = resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
        except (ValueError, KeyError):
            return ProviderResult(self.name, Verdict.ERROR, "", None, "parse error", latency)
        mal = int(stats.get("malicious", 0))
        susp = int(stats.get("suspicious", 0))
        total = sum(int(stats.get(k, 0)) for k in
                    ("malicious", "suspicious", "harmless", "undetected", "timeout"))
        score = f"{mal}/{total}"
        if mal >= 3:
            v = Verdict.MALICIOUS
        elif mal >= 1 or susp >= 1:
            v = Verdict.SUSPICIOUS
        else:
            v = Verdict.CLEAN
        return ProviderResult(self.name, v, score, data, None, latency)


def _err(name, msg, start):
    return ProviderResult(name, Verdict.ERROR, "", None, msg, int((time.perf_counter() - start) * 1000))
