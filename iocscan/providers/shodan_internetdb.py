from __future__ import annotations

import time

import httpx

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Provider, ProviderResult, Verdict, err_result as _err

ENDPOINT = "https://internetdb.shodan.io"


class ShodanInternetDB(Provider):
    name = "shodan_internetdb"
    supports = {IOCType.IP}
    requires_key = False
    # Shodan InternetDB is anonymous; docs recommend ~1 req/s ceiling.
    max_rps = 1.0
    # Surfaces ports / vulns as context, never votes on the verdict.
    enrichment_only = True

    async def lookup(self, ioc: str, ioc_type: IOCType, client: httpx.AsyncClient, config: Config) -> ProviderResult:
        start = time.perf_counter()
        try:
            resp = await client.get(f"{ENDPOINT}/{ioc}")
        except httpx.HTTPError as e:
            return _err(self.name, f"network: {e.__class__.__name__}", start)
        latency = int((time.perf_counter() - start) * 1000)
        if resp.status_code == 404:
            # Not in Shodan's last-30-days scan corpus.
            return ProviderResult(self.name, Verdict.UNKNOWN, "—", None, None, latency)
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
        except ValueError:
            return ProviderResult(self.name, Verdict.ERROR, "", None, "parse error", latency)
        ports = data.get("ports") or []
        vulns = data.get("vulns") or []
        if vulns:
            return ProviderResult(
                self.name, Verdict.SUSPICIOUS,
                f"{len(ports)} ports, {len(vulns)} vulns",
                data, None, latency,
            )
        if ports:
            return ProviderResult(
                self.name, Verdict.CLEAN, f"{len(ports)} ports",
                data, None, latency,
            )
        return ProviderResult(self.name, Verdict.CLEAN, "—", data, None, latency)
