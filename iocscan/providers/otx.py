from __future__ import annotations

import time
from urllib.parse import quote

import httpx

from iocscan.core.config import Config
from iocscan.providers.base import HASH_TYPES, IOCType, Provider, ProviderResult, Verdict, err_result as _err

BASE = "https://otx.alienvault.com/api/v1/indicators"

# OTX's canonical whitelist sources. We trust only these in the response's
# "validation" list — a spoofed/MitM response could otherwise inject an
# arbitrary entry to force CLEAN and suppress a malicious verdict (OTX votes
# with weight 2 in aggregation).
_TRUSTED_VALIDATION_SOURCES = {"majestic", "alexa", "whitelist"}


class OTX(Provider):
    name = "otx"
    supports = {IOCType.IP, IOCType.DOMAIN, *HASH_TYPES}
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
            # OTX's own validation list (majestic / alexa / whitelist) marks the
            # indicator as known-good. It wins over pulse count: popular legit
            # domains accrue pulses from phishing reports that impersonate them.
            # Trust only canonical sources so a spoofed response can't inject an
            # arbitrary entry to force CLEAN.
            validation = data.get("validation")
            if isinstance(validation, list) and any(
                isinstance(v, dict) and v.get("source") in _TRUSTED_VALIDATION_SOURCES
                for v in validation
            ):
                return ProviderResult(self.name, Verdict.CLEAN, "whitelisted", data, None, latency)
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

    def permalink(self, ioc: str, ioc_type: IOCType) -> str | None:
        if ioc_type == IOCType.IP:
            return f"https://otx.alienvault.com/indicator/ip/{ioc}"
        if ioc_type == IOCType.DOMAIN:
            return f"https://otx.alienvault.com/indicator/domain/{ioc}"
        if ioc_type == IOCType.URL:
            return f"https://otx.alienvault.com/indicator/url/{quote(ioc, safe='')}"
        return f"https://otx.alienvault.com/indicator/file/{ioc}"
