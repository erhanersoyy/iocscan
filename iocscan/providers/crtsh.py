"""Certificate Transparency hit count via crt.sh.

crt.sh is a public CT log mirror; the `?q=<domain>&output=json` endpoint
returns an array of cert entries. We surface count + oldest not_before.
Never votes — enrichment-only.
"""
from __future__ import annotations

import time
from typing import Any
from urllib.parse import quote

import httpx

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Provider, ProviderResult, Verdict, err_result as _err

ENDPOINT = "https://crt.sh/"


class CrtSh(Provider):
    name = "crtsh"
    supports = {IOCType.DOMAIN}
    requires_key = False
    max_rps = 1.0
    enrichment_only = True

    async def lookup(self, ioc: str, ioc_type: IOCType, client: httpx.AsyncClient, config: Config) -> ProviderResult:
        start = time.perf_counter()
        try:
            resp = await client.get(ENDPOINT, params={"q": ioc, "output": "json"})
        except httpx.HTTPError as e:
            return _err(self.name, f"network: {e.__class__.__name__}", start)
        latency = int((time.perf_counter() - start) * 1000)
        if resp.status_code == 429:
            return ProviderResult(self.name, Verdict.ERROR, "", None, "429 rate limit", latency)
        if resp.status_code >= 500:
            return ProviderResult(self.name, Verdict.ERROR, "", None, f"{resp.status_code} server", latency)
        if resp.status_code >= 400:
            return ProviderResult(self.name, Verdict.ERROR, "", None, f"{resp.status_code}", latency)
        try:
            data = resp.json()
        except ValueError:
            return ProviderResult(self.name, Verdict.ERROR, "", None, "parse error", latency)
        if not isinstance(data, list) or not data:
            return ProviderResult(self.name, Verdict.UNKNOWN, "—", None, None, latency)
        # `not_before` is ISO 8601; pick the earliest. Missing/None entries
        # are pushed to the far future so a real date wins the min().
        oldest = min((e.get("not_before") or "9999-12-31") for e in data)
        oldest_date = oldest.split("T")[0]
        score = f"{len(data)} certs (oldest {oldest_date})"
        out: dict[str, Any] = {"count": len(data), "oldest_not_before": oldest}
        return ProviderResult(self.name, Verdict.CLEAN, score, out, None, latency)

    def permalink(self, ioc: str, ioc_type: IOCType) -> str | None:
        if ioc_type == IOCType.DOMAIN:
            return f"https://crt.sh/?q={quote(ioc, safe='')}"
        return None
