from __future__ import annotations

import time

import httpx

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Provider, ProviderResult, Verdict, err_result as _err

ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"


class URLhaus(Provider):
    name = "urlhaus"
    supports = {IOCType.DOMAIN, IOCType.IP}
    requires_key = False
    max_rps = 5.0

    async def lookup(self, ioc: str, ioc_type: IOCType, client: httpx.AsyncClient, config: Config) -> ProviderResult:
        start = time.perf_counter()
        headers = {}
        abusech_key = config.key_for("abusech")
        if abusech_key:
            headers["Auth-Key"] = abusech_key
        try:
            resp = await client.post(ENDPOINT, data={"host": ioc}, headers=headers)
        except httpx.HTTPError as e:
            return _err(self.name, f"network: {e.__class__.__name__}", start)
        latency = int((time.perf_counter() - start) * 1000)
        if resp.status_code == 429:
            return ProviderResult(self.name, Verdict.ERROR, "", None, "429 rate limit", latency)
        if resp.status_code in (401, 403):
            return ProviderResult(self.name, Verdict.ERROR, "", None, "auth failed (Auth-Key required)", latency)
        if resp.status_code >= 500:
            return ProviderResult(self.name, Verdict.ERROR, "", None, f"{resp.status_code} server", latency)
        if resp.status_code >= 400:
            return ProviderResult(self.name, Verdict.ERROR, "", None, f"{resp.status_code}", latency)
        try:
            data = resp.json()
        except ValueError:
            return ProviderResult(self.name, Verdict.ERROR, "", None, "parse error", latency)
        if data.get("query_status") == "ok":
            url_count = data.get("url_count", "?")
            return ProviderResult(
                self.name, Verdict.MALICIOUS, f"{url_count} urls", data, None, latency
            )
        return ProviderResult(self.name, Verdict.CLEAN, "—", data, None, latency)
