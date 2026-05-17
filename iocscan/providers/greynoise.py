from __future__ import annotations

import time

import httpx

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Provider, ProviderResult, Verdict

ENDPOINT = "https://api.greynoise.io/v3/community"


class GreyNoise(Provider):
    name = "greynoise"
    supports = {IOCType.IP}
    requires_key = False
    max_rps = 1.0

    async def lookup(self, ioc: str, ioc_type: IOCType, client: httpx.AsyncClient, config: Config) -> ProviderResult:
        if ioc_type != IOCType.IP:
            return ProviderResult(self.name, Verdict.UNKNOWN, "—", None, None, 0)
        start = time.perf_counter()
        headers = {}
        key = config.key_for(self.name)
        if key:
            headers["key"] = key
        try:
            resp = await client.get(f"{ENDPOINT}/{ioc}", headers=headers)
        except httpx.HTTPError as e:
            return _err(self.name, f"network: {e.__class__.__name__}", start)
        latency = int((time.perf_counter() - start) * 1000)
        if resp.status_code == 404:
            return ProviderResult(self.name, Verdict.UNKNOWN, "—", None, None, latency)
        if resp.status_code == 429:
            return ProviderResult(self.name, Verdict.ERROR, "", None, "429 rate limit", latency)
        if resp.status_code in (401, 403):
            return ProviderResult(self.name, Verdict.ERROR, "", None, "auth failed", latency)
        if resp.status_code >= 400:
            return ProviderResult(self.name, Verdict.ERROR, "", None, f"{resp.status_code}", latency)
        try:
            data = resp.json()
            classification = data.get("classification", "unknown")
        except ValueError:
            return ProviderResult(self.name, Verdict.ERROR, "", None, "parse error", latency)
        name = data.get("name", "")
        if classification == "malicious":
            return ProviderResult(self.name, Verdict.MALICIOUS, name or "malicious", data, None, latency)
        if classification == "benign":
            return ProviderResult(self.name, Verdict.CLEAN, f"benign: {name}".strip(": "), data, None, latency)
        return ProviderResult(self.name, Verdict.UNKNOWN, classification, data, None, latency)


def _err(name, msg, start):
    return ProviderResult(name, Verdict.ERROR, "", None, msg, int((time.perf_counter() - start) * 1000))
