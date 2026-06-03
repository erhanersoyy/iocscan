from __future__ import annotations

import time

import httpx

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Provider, ProviderResult, Verdict, err_result as _err

HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"
URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"


class URLhaus(Provider):
    name = "urlhaus"
    supports = {IOCType.DOMAIN, IOCType.IP, IOCType.URL}
    requires_key = False
    optional_key = True
    key_alias = "abusech"
    max_rps = 5.0

    async def lookup(self, ioc: str, ioc_type: IOCType, client: httpx.AsyncClient, config: Config) -> ProviderResult:
        start = time.perf_counter()
        headers = {}
        abusech_key = config.key_for("abusech")
        if abusech_key:
            headers["Auth-Key"] = abusech_key
        if ioc_type == IOCType.URL:
            endpoint = URL_ENDPOINT
            data = {"url": ioc}
        else:
            endpoint = HOST_ENDPOINT
            data = {"host": ioc}
        try:
            resp = await client.post(endpoint, data=data, headers=headers)
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
            body = resp.json()
        except ValueError:
            return ProviderResult(self.name, Verdict.ERROR, "", None, "parse error", latency)
        if body.get("query_status") == "ok":
            # /v1/host/ returns url_count; /v1/url/ returns threat (e.g.
            # "malware_download"). Prefer threat label when present.
            score = body.get("threat") or f"{body.get('url_count', '?')} urls"
            return ProviderResult(self.name, Verdict.MALICIOUS, score, body, None, latency)
        return ProviderResult(self.name, Verdict.CLEAN, "—", body, None, latency)

    def permalink(self, ioc: str, ioc_type: IOCType) -> str | None:
        if ioc_type in (IOCType.IP, IOCType.DOMAIN):
            return f"https://urlhaus.abuse.ch/host/{ioc}/"
        # No stable per-URL deeplink for arbitrary URLs.
        return None
