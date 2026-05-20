"""WHOIS enrichment via raw TCP-43.

For DOMAINs: query the TLD authoritative registry and extract the creation
date. Verdict is SUSPICIOUS for newly-registered domains (<30 days),
CLEAN otherwise. A hardcoded TLD -> server map covers the ~25 highest-
volume TLDs so the common case stays one hop.

For IPs: query IANA (`whois.iana.org`) to discover the responsible RIR,
then query the RIR for the network registration record. Parses ARIN-
style fields (NetRange, CIDR, NetName, NetHandle, Parent, NetType,
OriginAS, Organization, RegDate, Updated, Ref) and surfaces NetName /
Organization as the table score. Other RIRs (RIPE/APNIC/LACNIC/AFRINIC)
use different field names; those responses will produce fewer matching
fields and a row score of '—'. Verdict is always CLEAN (enrichment).

The aggregator ignores this row because `enrichment_only = True`.
"""
from __future__ import annotations

import asyncio
import re
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Provider, ProviderResult, Verdict, err_result as _err

PORT = 43
_QUERY_TIMEOUT = 5.0
_NRD_DAYS = 30  # threshold for "newly registered domain"
# Hard cap on a single WHOIS response. RIR records are KB-sized; this is a
# generous upper bound that still blocks a hostile server from feeding us
# unbounded data within the 5s read window.
_MAX_BODY = 2 * 1024 * 1024
_IANA_WHOIS = "whois.iana.org"

# IANA's reply is plaintext over TCP/43 and not authenticated, so a MitM
# could rewrite the `refer:` line to point at an internal host. We only
# follow refers that match a known RIR / NIR WHOIS endpoint to keep the
# blast radius limited (port is fixed to 43, but loopback/private hosts
# still listening there would otherwise be reachable).
_RIR_ALLOWLIST = frozenset({
    "whois.arin.net",
    "whois.ripe.net",
    "whois.apnic.net",
    "whois.lacnic.net",
    "whois.afrinic.net",
    # National / regional NIRs that IANA actually refers to.
    "whois.nic.ad.jp",
    "whois.kisa.or.kr",
    "whois.twnic.net.tw",
    "whois.registro.br",
})


WHOIS_SERVERS = {
    "com":    "whois.verisign-grs.com",
    "net":    "whois.verisign-grs.com",
    "org":    "whois.publicinterestregistry.org",
    "info":   "whois.afilias.net",
    "biz":    "whois.biz",
    "io":     "whois.nic.io",
    "co":     "whois.nic.co",
    "us":     "whois.nic.us",
    "uk":     "whois.nic.uk",
    "de":     "whois.denic.de",
    "fr":     "whois.nic.fr",
    "it":     "whois.nic.it",
    "ru":     "whois.tcinet.ru",
    "jp":     "whois.jprs.jp",
    "cn":     "whois.cnnic.cn",
    "br":     "whois.registro.br",
    "nl":     "whois.domain-registry.nl",
    "ca":     "whois.cira.ca",
    "au":     "whois.auda.org.au",
    "tr":     "whois.nic.tr",
    "xyz":    "whois.nic.xyz",
    "online": "whois.nic.online",
    "site":   "whois.nic.site",
    "tech":   "whois.nic.tech",
    "ai":     "whois.nic.ai",
    "dev":    "whois.nic.google",
    "app":    "whois.nic.google",
}


_CREATION_PATTERNS = (
    re.compile(r"^\s*Creation Date:\s*(.+)$",       re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*Created On:\s*(.+)$",          re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*Domain Registered:\s*(.+)$",   re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*Registered on:\s*(.+)$",       re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*Registration Time:\s*(.+)$",   re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*created:\s*(.+)$",             re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*Created Date:\s*(.+)$",        re.MULTILINE | re.IGNORECASE),
)


# IP-specific: ARIN field set requested by users. We collect any of these
# that appear in the RIR response; first occurrence wins, so a top-level
# allocation answer is preferred over nested OrgRef/POC blocks.
_IP_FIELDS = (
    "NetRange", "CIDR", "NetName", "NetHandle", "Parent", "NetType",
    "OriginAS", "Organization", "RegDate", "Updated", "Ref",
)
# Uses [ \t] (not \s) for intra-line whitespace so trailing-space lines
# don't bleed into the next field. `\s` matches `\n`, which would let
# `(.*?)` skip past a blank value and capture the next line.
_IP_FIELD_RE = re.compile(
    r"^[ \t]*(" + "|".join(re.escape(f) for f in _IP_FIELDS) + r")[ \t]*:[ \t]*(.*?)[ \t]*$",
    re.MULTILINE,
)
# IANA's reply to an IP query carries `refer: whois.<rir>.net` pointing at
# the responsible RIR; ARIN uses the same `refer:` keyword for SWIP-style
# downstream delegations.
_REFER_RE = re.compile(r"^\s*refer:\s*(\S+)\s*$", re.MULTILINE | re.IGNORECASE)


class WhoisAge(Provider):
    name = "whois_age"
    supports = {IOCType.DOMAIN, IOCType.IP}
    requires_key = False
    max_rps = 2.0
    enrichment_only = True

    async def lookup(self, ioc: str, ioc_type: IOCType, client: httpx.AsyncClient, config: Config) -> ProviderResult:
        start = time.perf_counter()
        if ioc_type == IOCType.IP:
            return await self._lookup_ip(ioc, start)
        return await self._lookup_domain(ioc, start)

    async def _lookup_domain(self, ioc: str, start: float) -> ProviderResult:
        tld = ioc.rsplit(".", 1)[-1].lower()
        server = WHOIS_SERVERS.get(tld)
        if server is None:
            latency = int((time.perf_counter() - start) * 1000)
            return ProviderResult(self.name, Verdict.UNKNOWN, "—", None, f"unknown TLD: .{tld}", latency)
        text, exc_name = await _whois_query(server, ioc)
        if text is None:
            return _err(self.name, f"network: {exc_name}", start)
        latency = int((time.perf_counter() - start) * 1000)
        created = _extract_creation_date(text)
        if created is None:
            return ProviderResult(self.name, Verdict.UNKNOWN, "—", None, "no creation date in response", latency)
        now = datetime.now(timezone.utc)
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age_days = max(0, (now - created).days)
        score = f"{age_days}d old" if age_days < 365 else f"{age_days // 365}y old"
        verdict = Verdict.SUSPICIOUS if age_days < _NRD_DAYS else Verdict.CLEAN
        raw: dict[str, Any] = {"creation_date": created.isoformat(), "age_days": age_days, "server": server}
        return ProviderResult(self.name, verdict, score, raw, None, latency)

    async def _lookup_ip(self, ioc: str, start: float) -> ProviderResult:
        iana_text, exc_name = await _whois_query(_IANA_WHOIS, ioc)
        if iana_text is None:
            return _err(self.name, f"network: {exc_name}", start)
        rir = _extract_refer(iana_text)
        # One refer-hop max: IANA -> RIR. Some IANA replies already carry
        # enough fields for legacy allocations, so we keep that text as a
        # fallback if the RIR hop fails or returns nothing parseable.
        text = iana_text
        server = _IANA_WHOIS
        # Refer host comes from a plaintext response and is untrusted;
        # only follow it if it matches a known RIR/NIR endpoint.
        if rir and rir.lower() in _RIR_ALLOWLIST:
            rir_text, _ = await _whois_query(rir, ioc)
            if rir_text:
                text = rir_text
                server = rir
        latency = int((time.perf_counter() - start) * 1000)
        fields = _parse_ip_fields(text)
        if not fields:
            return ProviderResult(self.name, Verdict.UNKNOWN, "—", None, "no netinfo in response", latency)
        # NetName is a compact tag (e.g. "MSFT"); fall back to the longer
        # Organization or NetRange when the RIR omits it.
        score = fields.get("NetName") or fields.get("Organization") or fields.get("NetRange") or "—"
        raw: dict[str, Any] = {"server": server, **fields}
        return ProviderResult(self.name, Verdict.CLEAN, score, raw, None, latency)


async def _whois_query(server: str, query: str) -> tuple[str | None, str]:
    """Run one TCP-43 round-trip. Returns (text, exception_class_name)."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, PORT), timeout=_QUERY_TIMEOUT,
        )
    except (OSError, asyncio.TimeoutError) as e:
        return None, e.__class__.__name__
    try:
        writer.write(f"{query}\r\n".encode("ascii"))
        await writer.drain()
        body = await asyncio.wait_for(reader.read(_MAX_BODY), timeout=_QUERY_TIMEOUT)
    except asyncio.TimeoutError:
        return None, "TimeoutError"
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    return body.decode("utf-8", errors="replace"), ""


def _extract_refer(text: str) -> str | None:
    m = _REFER_RE.search(text)
    return m.group(1).strip() if m else None


def _parse_ip_fields(text: str) -> dict[str, str]:
    """Collect ARIN-style network-registration fields. First occurrence wins
    so top-level allocation values aren't overwritten by nested POC blocks.
    Empty values (e.g. `OriginAS:` with nothing after the colon) are kept
    because they convey "field present but unset" — the table cell renders
    blanks the same as missing fields."""
    out: dict[str, str] = {}
    for m in _IP_FIELD_RE.finditer(text):
        key, value = m.group(1), m.group(2).strip()
        if key not in out:
            out[key] = value
    return out


def _extract_creation_date(text: str) -> datetime | None:
    for pat in _CREATION_PATTERNS:
        m = pat.search(text)
        if m:
            d = _parse_date(m.group(1))
            if d is not None:
                return d
    return None


def _parse_date(s: str) -> datetime | None:
    """Best-effort WHOIS date parser. Stays stdlib-only on purpose."""
    s = s.strip()
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%d-%b-%Y",
        "%d.%m.%Y",
    ):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    try:
        head = s.split("T", 1)[0].split(" ", 1)[0]
        return datetime.strptime(head, "%Y-%m-%d")
    except ValueError:
        return None
