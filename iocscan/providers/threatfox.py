from __future__ import annotations

import json
import time

import httpx

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Provider, ProviderResult, Verdict

ENDPOINT = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFox(Provider):
    name = "threatfox"
    supports = {IOCType.IP, IOCType.DOMAIN}
    requires_key = False
    max_rps = 5.0

    async def lookup(self, ioc: str, ioc_type: IOCType, client: httpx.AsyncClient, config: Config) -> ProviderResult:
        start = time.perf_counter()
        payload = {"query": "search_ioc", "search_term": ioc}
        try:
            resp = await client.post(ENDPOINT, content=json.dumps(payload))
        except httpx.HTTPError as e:
            return _err(self.name, f"network: {e.__class__.__name__}", start)
        latency = int((time.perf_counter() - start) * 1000)
        if resp.status_code == 429:
            return ProviderResult(self.name, Verdict.ERROR, "", None, "429 rate limit", latency)
        if resp.status_code >= 400:
            return ProviderResult(self.name, Verdict.ERROR, "", None, f"{resp.status_code}", latency)
        try:
            data = resp.json()
        except ValueError:
            return ProviderResult(self.name, Verdict.ERROR, "", None, "parse error", latency)
        if data.get("query_status") == "ok" and data.get("data"):
            entry = data["data"][0]
            malware = entry.get("malware", "unknown")
            return ProviderResult(self.name, Verdict.MALICIOUS, malware, data, None, latency)
        return ProviderResult(self.name, Verdict.CLEAN, "—", data, None, latency)


def _err(name: str, msg: str, start: float) -> ProviderResult:
    latency = int((time.perf_counter() - start) * 1000)
    return ProviderResult(name, Verdict.ERROR, "", None, msg, latency)
