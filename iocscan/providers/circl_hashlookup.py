from __future__ import annotations

import time

import httpx

from iocscan.core.config import Config
from iocscan.providers.base import (
    HASH_TYPES,
    IOCType,
    Provider,
    ProviderResult,
    Verdict,
    err_result as _err,
)

BASE = "https://hashlookup.circl.lu/lookup"

# Map IOCType → URL path segment. CIRCL exposes a separate sub-resource per
# hash algorithm; we never call md5 with a sha256 string or vice versa.
_PATH = {
    IOCType.HASH_MD5: "md5",
    IOCType.HASH_SHA1: "sha1",
    IOCType.HASH_SHA256: "sha256",
}


def _is_nsrl(source) -> bool:
    """True if the `source` field indicates an NSRL (known-good) entry.

    Accepts string or list, case-insensitive. CIRCL also indexes malicious
    feeds, so a 200 *without* an NSRL marker is ambiguous and must not be
    treated as 'known good'.
    """
    if not source:
        return False
    if isinstance(source, str):
        return "nsrl" in source.lower()
    if isinstance(source, (list, tuple)):
        return any(isinstance(s, str) and "nsrl" in s.lower() for s in source)
    return False


def _format_sources(km) -> str:
    """Render `KnownMalicious` (list / string / dict) as a flat source list."""
    if isinstance(km, list):
        return ", ".join(str(s) for s in km)
    if isinstance(km, dict):
        return ", ".join(str(k) for k in km.keys())
    return str(km)


class CIRCLHashlookup(Provider):
    """CIRCL hashlookup — anonymous hash reputation.

    Indexes the NSRL (known-good) and several malicious-hash feeds.

    - 200 with non-empty ``KnownMalicious`` → MALICIOUS (sources)
    - 200 with ``source`` containing "NSRL" → CLEAN ("known good")
    - 200 otherwise → UNKNOWN (record exists but provenance is ambiguous)
    - 404 → UNKNOWN
    """

    name = "circl_hashlookup"
    supports = {*HASH_TYPES}
    requires_key = False
    max_rps = 5.0

    async def lookup(
        self, ioc: str, ioc_type: IOCType, client: httpx.AsyncClient, config: Config
    ) -> ProviderResult:
        start = time.perf_counter()
        path = _PATH.get(ioc_type)
        if path is None:
            # Defensive: scan loop pre-filters by `supports`, but the provider
            # contract is "lookup must never raise".
            return ProviderResult(
                self.name, Verdict.ERROR, "", None, f"unsupported ioc_type: {ioc_type}", 0
            )
        try:
            resp = await client.get(f"{BASE}/{path}/{ioc}")
        except httpx.HTTPError as e:
            return _err(self.name, f"network: {e.__class__.__name__}", start)
        latency = int((time.perf_counter() - start) * 1000)
        if resp.status_code == 404:
            return ProviderResult(self.name, Verdict.UNKNOWN, "—", None, None, latency)
        if resp.status_code == 429:
            return ProviderResult(self.name, Verdict.ERROR, "", None, "429 rate limit", latency)
        if resp.status_code >= 500:
            return ProviderResult(
                self.name, Verdict.ERROR, "", None, f"{resp.status_code} server", latency
            )
        if resp.status_code >= 400:
            return ProviderResult(self.name, Verdict.ERROR, "", None, f"{resp.status_code}", latency)
        try:
            data = resp.json()
        except ValueError:
            return ProviderResult(self.name, Verdict.ERROR, "", None, "parse error", latency)

        # `is not None` rather than truthy so legitimate `0` / `""` aren't dropped.
        details: list[str] = []
        filename = data.get("FileName")
        if filename is not None:
            details.append(f"file: {filename}")
        size = data.get("FileSize")
        if size is not None:
            details.append(f"size: {size}")
        source = data.get("source")
        if source is not None:
            details.append(f"source: {source}")
        details_t = tuple(details)

        known_malicious = data.get("KnownMalicious")
        if known_malicious:  # non-empty list/string/dict
            return ProviderResult(
                self.name, Verdict.MALICIOUS, _format_sources(known_malicious),
                data, None, latency, details=details_t,
            )
        if _is_nsrl(source):
            return ProviderResult(
                self.name, Verdict.CLEAN, "known good", data, None, latency, details=details_t,
            )
        # 200 OK but neither NSRL-tagged nor flagged — provenance unclear.
        return ProviderResult(
            self.name, Verdict.UNKNOWN, "—", data, None, latency, details=details_t,
        )

    def permalink(self, ioc: str, ioc_type: IOCType) -> str | None:
        # CIRCL hashlookup has no human-facing UI page — the only endpoint is
        # the JSON API, which is not user-browsable. Return None rather than
        # link analysts to a raw JSON blob.
        return None
