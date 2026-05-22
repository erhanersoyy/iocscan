from __future__ import annotations

import json
import time
from urllib.parse import quote

import httpx

from iocscan.core.config import Config
from iocscan.providers.base import HASH_TYPES, IOCType, Provider, ProviderResult, Verdict, err_result as _err

ENDPOINT = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFox(Provider):
    name = "threatfox"
    supports = {IOCType.IP, IOCType.DOMAIN, IOCType.URL, *HASH_TYPES}
    requires_key = False
    max_rps = 5.0

    async def lookup(self, ioc: str, ioc_type: IOCType, client: httpx.AsyncClient, config: Config) -> ProviderResult:
        start = time.perf_counter()
        headers = {}
        abusech_key = config.key_for("abusech")
        if abusech_key:
            headers["Auth-Key"] = abusech_key
        payload = {"query": "search_ioc", "search_term": ioc}
        try:
            resp = await client.post(ENDPOINT, content=json.dumps(payload), headers=headers)
        except httpx.HTTPError as e:
            return _err(self.name, f"network: {e.__class__.__name__}", start)
        latency = int((time.perf_counter() - start) * 1000)
        if resp.status_code == 429:
            return ProviderResult(self.name, Verdict.ERROR, "", None, "429 rate limit", latency)
        if resp.status_code in (401, 403):
            return ProviderResult(self.name, Verdict.ERROR, "", None, "auth failed (Auth-Key required)", latency)
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

    def permalink(self, ioc: str, ioc_type: IOCType) -> str | None:
        return f"https://threatfox.abuse.ch/browse.php?search={quote(ioc, safe='')}"
