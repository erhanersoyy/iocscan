from __future__ import annotations

import time
from urllib.parse import quote

import httpx

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Provider, ProviderResult, Verdict, err_result as _err

ENDPOINT = "https://urlscan.io/api/v1/search/"


class URLScan(Provider):
    name = "urlscan"
    supports = {IOCType.URL}
    requires_key = False
    optional_key = True
    # urlscan.io anonymous tier is strict (~120 req/min hard limit); 1 rps keeps us well below.
    max_rps = 1.0

    async def lookup(self, ioc: str, ioc_type: IOCType, client: httpx.AsyncClient, config: Config) -> ProviderResult:
        start = time.perf_counter()
        headers: dict[str, str] = {}
        key = config.key_for(self.name)
        if key:
            headers["API-Key"] = key
        try:
            resp = await client.get(
                ENDPOINT,
                params={"q": f'page.url:"{ioc}"'},
                headers=headers,
            )
        except httpx.HTTPError as e:
            return _err(self.name, f"network: {e.__class__.__name__}", start)
        latency = int((time.perf_counter() - start) * 1000)
        if resp.status_code == 429:
            return ProviderResult(self.name, Verdict.ERROR, "", None, "429 rate limit", latency)
        if resp.status_code in (401, 403):
            return ProviderResult(self.name, Verdict.ERROR, "", None, "auth failed", latency)
        if resp.status_code >= 500:
            return ProviderResult(self.name, Verdict.ERROR, "", None, f"{resp.status_code} server", latency)
        if resp.status_code >= 400:
            return ProviderResult(self.name, Verdict.ERROR, "", None, f"{resp.status_code}", latency)
        try:
            data = resp.json()
            results = data.get("results") or []
            # `.get("total") or len(results)` covers both "missing" and
            # explicit null — int(None) would otherwise raise TypeError.
            total = int(data.get("total") or len(results))
        except (ValueError, TypeError):
            return ProviderResult(self.name, Verdict.ERROR, "", None, "parse error", latency)
        if total == 0:
            return ProviderResult(self.name, Verdict.CLEAN, "—", data, None, latency)
        malicious_count = sum(
            1 for r in results
            if (((r.get("verdicts") or {}).get("overall") or {}).get("malicious"))
        )
        if malicious_count > 0:
            return ProviderResult(
                self.name, Verdict.MALICIOUS,
                f"{total} scans ({malicious_count} malicious)",
                data, None, latency,
            )
        return ProviderResult(self.name, Verdict.SUSPICIOUS, f"{total} scans", data, None, latency)

    def permalink(self, ioc: str, ioc_type: IOCType) -> str | None:
        if ioc_type == IOCType.URL:
            return f"https://urlscan.io/search/#page.url%3A%22{quote(ioc, safe='')}%22"
        return None
