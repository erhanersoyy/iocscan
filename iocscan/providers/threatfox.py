from __future__ import annotations

import json
import time
from urllib.parse import quote

import httpx

from iocscan.core.config import Config
from iocscan.providers.base import HASH_TYPES, IOCType, Provider, ProviderResult, Verdict, err_result as _err

ENDPOINT = "https://threatfox-api.abuse.ch/api/v1/"


def _ioc_matches(entry_ioc: str, ioc: str, ioc_type: IOCType) -> bool:
    """True when a ThreatFox entry refers to exactly the queried IOC.

    ThreatFox stores IP IOCs in "ip:port" form, so a bare-IP query must
    also accept "<ip>:<port>" entries. Comparison is case-insensitive —
    scheme/host of our normalized IOCs are already lowercase and hashes
    are hex.
    """
    entry_low, ioc_low = entry_ioc.lower(), ioc.lower()
    if entry_low == ioc_low:
        return True
    return ioc_type == IOCType.IP and entry_low.startswith(f"{ioc_low}:")


class ThreatFox(Provider):
    name = "threatfox"
    supports = {IOCType.IP, IOCType.DOMAIN, IOCType.URL, *HASH_TYPES}
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
        if data.get("query_status") == "ok" and isinstance(data.get("data"), list):
            # search_ioc is a substring search: querying "google.com" returns
            # lookalike IOCs such as "guard-google.com". Only an entry whose
            # `ioc` field IS the queried indicator may vote MALICIOUS.
            matches = [
                e for e in data["data"]
                if isinstance(e, dict) and _ioc_matches(e.get("ioc") or "", ioc, ioc_type)
            ]
            if matches:
                malware = matches[0].get("malware", "unknown")
                return ProviderResult(self.name, Verdict.MALICIOUS, malware, data, None, latency)
        return ProviderResult(self.name, Verdict.CLEAN, "—", data, None, latency)

    def permalink(self, ioc: str, ioc_type: IOCType) -> str | None:
        return f"https://threatfox.abuse.ch/browse.php?search={quote(ioc, safe='')}"
