"""WHOIS enrichment via raw TCP-43.

For DOMAINs: query the TLD authoritative registry, parse ICANN-standard
fields (registrar, created, updated, expires, status, name servers,
dnssec), and surface them as table detail rows. Verdict is SUSPICIOUS
for newly-registered domains (<30 days), CLEAN otherwise — age is
captured in `raw["age_days"]` for programmatic consumers. A hardcoded
TLD -> server map covers the ~25 highest-volume TLDs so the common
case stays one hop.

For IPs: query IANA (`whois.iana.org`) to discover the responsible RIR,
then query the RIR for the network registration record. The display
parser folds both ARIN CamelCase keys (NetRange, NetName, …) and RPSL
lowercase keys used by RIPE/APNIC/AFRINIC (inetnum, netname, …) onto a
single set of RIPE-style display labels (inetnum, netname, country,
org, admin-c, tech-c, status, mnt-by, created, last-modified, source).
NetName / netname becomes the table score; all parsed fields surface
as detail rows. Verdict is always CLEAN (enrichment).

The aggregator ignores this row because `enrichment_only = True`.
"""
from __future__ import annotations

import asyncio
import re
import time
from datetime import datetime, timezone
from typing import Any

import httpx
import tldextract

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Provider, ProviderResult, Verdict, err_result as _err

# Snapshot-only PSL: empty `suffix_list_urls` + `cache_dir=None` mean this
# never fetches or caches at runtime — only the snapshot bundled in the
# package. Used by _registrable_domain.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

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
    # .tr registry moved from METU NIC to TRABIS (BTK) in Sep 2022; the old
    # whois.nic.tr host no longer resolves.
    "tr":     "whois.trabis.gov.tr",
    "top":    "whois.nic.top",
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

# Registry-side "this label is below the registrable level" rejection.
# Nominet (.uk) explicitly says "the domain name contains too many parts"
# for three-part queries like `co.uk` itself. Match the literal phrase only
# — broader patterns (e.g. `subdomain.*not.*allowed`) over-match registry
# policy / T&C boilerplate and silently drop genuine WHOIS records.
_SUBDOMAIN_REJECTION_RE = re.compile(
    r"the domain name contains too many parts",
    re.IGNORECASE,
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

# Display labels (RIPE-style) + the case-insensitive WHOIS keys we accept
# for each. Order here defines the row order in the table detail block.
# ARIN uses CamelCase keys (NetRange, NetName, …); RIPE/APNIC/AFRINIC use
# lowercase RPSL keys (inetnum, netname, …) — the alias list folds both
# vocabularies onto a single set of display labels.
_WHOIS_DISPLAY: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("inetnum",       ("inetnum", "netrange")),
    ("netname",       ("netname",)),
    ("country",       ("country",)),
    ("org",           ("org", "organization", "orgid", "orgname")),
    ("admin-c",       ("admin-c", "adminhandle")),
    ("tech-c",        ("tech-c", "techhandle")),
    ("status",        ("status", "nettype")),
    ("mnt-by",        ("mnt-by",)),
    ("created",       ("created", "regdate")),
    ("last-modified", ("last-modified", "updated")),
    ("source",        ("source",)),
)
# Generic `<key>: <value>` line matcher used by the display parsers. Allows
# spaces inside the key so domain WHOIS labels like "Creation Date" or
# "Registry Expiry Date" match alongside RPSL single-token keys (inetnum,
# mnt-by). The lazy `+?` plus the explicit `[ \t]*:` boundary stop the
# capture at the *first* colon, which keeps URL-bearing values like
# "Registrar URL: https://..." intact.
_WHOIS_LINE_RE = re.compile(r"^[ \t]*([\w\- ]+?)[ \t]*:[ \t]*(.*?)[ \t]*$")

# Domain WHOIS display fields — ICANN-mandated keys covering most gTLDs
# and major ccTLDs. Order here is the row order in the table detail block.
_WHOIS_DOMAIN_DISPLAY: tuple[tuple[str, tuple[str, ...]], ...] = (
    # TRABIS exposes registrant/registrar via "** Section:" blocks (not flat
    # key:value); _parse_trabis_sections injects them into the display dict.
    ("registrant",   ("registrant",)),
    ("registrar",    ("registrar", "organization name")),
    ("created",      (
        "creation date", "created on", "created", "registered on",
        "registration time", "created date", "domain registered",
    )),
    ("updated",      ("updated date", "last updated on", "updated", "last modified")),
    ("expires",      (
        "registry expiry date", "registrar registration expiration date",
        "expiry date", "expiration date", "expires", "expires on", "renewal date",
    )),
    ("status",       ("domain status", "status")),
    ("name servers", ("name server", "nameserver", "nserver")),
    ("dnssec",       ("dnssec",)),
)


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
        # WHOIS records live at the registrable-domain level, so a subdomain
        # must be queried as its parent (sub.example.com -> example.com) or the
        # registry returns "no match". The server stays keyed by the last label
        # above, which is correct for every WHOIS_SERVERS entry.
        query = _registrable_domain(ioc)
        text, exc_name = await _whois_query(server, query)
        if text is None:
            return _err(self.name, f"network: {exc_name}", start)
        latency = int((time.perf_counter() - start) * 1000)
        # Registry rejected the query because the name is below the
        # registrable level (e.g. three-part .co.uk). Short-circuit with a
        # clear hint instead of falling through to "no creation date" UNKNOWN.
        # `error` stays None — by project convention it is reserved for
        # `Verdict.ERROR`; reusing it on UNKNOWN inflates health-report error
        # rates. The hint lives in `details` (rendered under the score cell).
        if _SUBDOMAIN_REJECTION_RE.search(text):
            return ProviderResult(
                self.name, Verdict.UNKNOWN, "subdomain", None,
                None, latency,
                details=(f"server: {server}", "not registrable (subdomain) - try parent domain"),
            )
        # TRABIS (and possibly other registries) pad keys with dots:
        # "Created on..............: 2024-Aug-27." — strip the dots so the
        # generic "key: value" regex can match.
        text = re.sub(r"\.+:", ":", text)
        display = _parse_domain_whois_for_display(text)
        # TRABIS exposes registrant / domain servers as "** Section:" multiline
        # blocks rather than flat key:value lines — fold the first non-redacted
        # registrant line and the full server list into the display dict.
        sections = _parse_trabis_sections(text)
        if "registrant" in sections and sections["registrant"]:
            display.setdefault("registrant", sections["registrant"][0])
        if "domain servers" in sections and sections["domain servers"]:
            display.setdefault("name servers", "; ".join(sections["domain servers"]))
        created = _extract_creation_date(text)
        # Build the detail block first; it survives even if the response
        # carries no creation date — the user still wants to see registrar
        # / expiry / nameservers etc.
        detail_lines = [f"server: {server}"]
        # When a subdomain was reduced, show which domain we actually queried.
        if query != ioc:
            detail_lines.append(f"queried: {query}")
        for label, _ in _WHOIS_DOMAIN_DISPLAY:
            value = display.get(label)
            if value:
                detail_lines.append(f"{label}: {value}")
        details = tuple(detail_lines) if display else ()
        if created is None:
            return ProviderResult(
                self.name, Verdict.UNKNOWN, "—", None,
                "no creation date in response", latency, details=details,
            )
        now = datetime.now(timezone.utc)
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age_days = max(0, (now - created).days)
        verdict = Verdict.SUSPICIOUS if age_days < _NRD_DAYS else Verdict.CLEAN
        raw: dict[str, Any] = {"creation_date": created.isoformat(), "age_days": age_days, "server": server}
        return ProviderResult(self.name, verdict, "—", raw, None, latency, details=details)

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
        display = _parse_whois_for_display(text)
        if not fields and not display:
            return ProviderResult(self.name, Verdict.UNKNOWN, "—", None, "no netinfo in response", latency)
        # NetName is a compact tag (e.g. "MSFT"); fall back to org or
        # inetnum range when the RIR omits it. `display` already folds
        # ARIN CamelCase into RIPE-style labels via the alias map.
        score = (
            display.get("netname")
            or display.get("org")
            or display.get("inetnum")
            or "—"
        )
        # Carry both the legacy ARIN CamelCase keys (so existing JSON
        # consumers depending on raw["NetName"] / raw["Organization"]
        # keep working) and the RIPE-style display keys (so RIPE/APNIC/
        # AFRINIC responses, which produce no ARIN matches at all, still
        # surface their fields in JSON output rather than just `server`).
        raw: dict[str, Any] = {"server": server, **fields, **display}
        detail_lines = [f"server: {server}"]
        for label, _ in _WHOIS_DISPLAY:
            value = display.get(label)
            if value:
                detail_lines.append(f"{label}: {value}")
        return ProviderResult(
            self.name, Verdict.CLEAN, score, raw, None, latency,
            details=tuple(detail_lines),
        )


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


def _registrable_domain(host: str) -> str:
    """Reduce a hostname to its registrable domain (public suffix + one label)
    via the bundled PSL snapshot: `sub.example.com` -> `example.com`,
    `a.b.example.co.uk` -> `example.co.uk`. Falls back to the input unchanged
    when there is no registrable part (unknown suffix, or the host is itself a
    public suffix).
    """
    ext = _EXTRACT(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return host


def _extract_refer(text: str) -> str | None:
    m = _REFER_RE.search(text)
    return m.group(1).strip() if m else None


def _parse_ip_fields(text: str) -> dict[str, str]:
    """Collect ARIN-style network-registration fields. First occurrence wins
    so top-level allocation values aren't overwritten by nested POC blocks.
    Empty values (e.g. `OriginAS:` with nothing after the colon) are kept
    because they convey "field present but unset" — the table cell renders
    blanks the same as missing fields.

    Retained for `raw` JSON backward compatibility: callers depending on
    raw["NetName"] / raw["Organization"] etc. keep working. The table
    renderer itself reads only from `_parse_whois_for_display`.
    """
    out: dict[str, str] = {}
    for m in _IP_FIELD_RE.finditer(text):
        key, value = m.group(1), m.group(2).strip()
        if key not in out:
            out[key] = value
    return out


def _parse_domain_whois_for_display(text: str) -> dict[str, str]:
    """Parse domain WHOIS text into ICANN-style display labels.

    Unlike RPSL (RIPE/ARIN) records, domain WHOIS is a flat key:value list
    with no object boundaries — so we scan the whole text, take the first
    occurrence of each known key as canonical, and join repeats (multiple
    name-server / domain-status lines) with `; `. ICANN-mandated status
    values carry an EPP URL suffix that is stripped for readability.
    """
    known_aliases = {alias for _, aliases in _WHOIS_DOMAIN_DISPLAY for alias in aliases}
    collected: dict[str, list[str]] = {}
    for line in text.splitlines():
        if line.startswith("%") or line.startswith("#") or line.startswith(">>>"):
            continue
        m = _WHOIS_LINE_RE.match(line)
        if not m:
            continue
        key = m.group(1).strip().lower()
        value = m.group(2).strip()
        if not value or key not in known_aliases:
            continue
        collected.setdefault(key, []).append(value)

    out: dict[str, str] = {}
    for label, aliases in _WHOIS_DOMAIN_DISPLAY:
        for alias in aliases:
            if alias not in collected:
                continue
            values = collected[alias]
            if label == "status":
                # Strip the trailing EPP URL: "clientTransferProhibited
                # https://icann.org/epp#…" -> "clientTransferProhibited".
                # Split on any whitespace (some hostile servers separate
                # the token from the URL with a tab); .split(None, 1)
                # treats any run of whitespace as a single separator.
                values = [v.split(None, 1)[0] for v in values]
            seen: set[str] = set()
            uniq: list[str] = []
            for v in values:
                if v not in seen:
                    uniq.append(v)
                    seen.add(v)
            out[label] = "; ".join(uniq)
            break
    return out


def _parse_whois_for_display(text: str) -> dict[str, str]:
    """Parse the first WHOIS object's fields into RIPE-style display labels.

    Object boundary detection has two rules:
    1. Only enter "in object" mode when a *known* display-alias key is
       seen. This skips IANA preamble lines (`refer:`, `% comments`) so
       they don't claim the slot of the real inetnum block.
    2. Once in object, the next blank line ends the object. Prevents a
       later organisation/role block from shadowing inetnum fields
       (e.g. its `country:` line would overwrite the real one otherwise).

    Multi-value fields (e.g. RIPE `mnt-by` appearing twice within one
    object) are joined with `; ` in the order they appeared.
    """
    known_aliases = {alias for _, aliases in _WHOIS_DISPLAY for alias in aliases}
    collected: dict[str, list[str]] = {}
    in_object = False
    for line in text.splitlines():
        # `>>>` brackets the "Last update of WHOIS database" footer in
        # some Verisign/Donuts responses; skip it like a comment line.
        if line.startswith("%") or line.startswith("#") or line.startswith(">>>"):
            continue
        if not line.strip():
            if in_object:
                break
            continue
        m = _WHOIS_LINE_RE.match(line)
        if not m:
            continue
        key, value = m.group(1).strip().lower(), m.group(2).strip()
        if not value:
            continue
        if not in_object:
            if key not in known_aliases:
                continue
            in_object = True
        collected.setdefault(key, []).append(value)

    out: dict[str, str] = {}
    for label, aliases in _WHOIS_DISPLAY:
        for alias in aliases:
            if alias in collected:
                out[label] = "; ".join(collected[alias])
                break
    return out


def _extract_creation_date(text: str) -> datetime | None:
    for pat in _CREATION_PATTERNS:
        m = pat.search(text)
        if m:
            d = _parse_date(m.group(1))
            if d is not None:
                return d
    return None


def _parse_trabis_sections(text: str) -> dict[str, list[str]]:
    """Parse TRABIS-style ``** Section Name:`` multiline blocks.

    The .tr registry response groups registrant / registrar / nameserver data
    under section headers rather than flat ``key: value`` lines. "Hidden upon
    user request" placeholders are dropped so the registrant field carries
    real data when present.
    """
    sections: dict[str, list[str]] = {}
    current: str | None = None
    header_re = re.compile(r"^\*+\s*([A-Za-z][\w\s]*?)\s*:\s*$")
    for raw in text.splitlines():
        line = raw.strip()
        m = header_re.match(line)
        if m:
            current = m.group(1).strip().lower()
            sections.setdefault(current, [])
            continue
        if current is None or not line:
            continue
        if line.lower() == "hidden upon user request":
            continue
        # Inside a section we only want standalone body lines; skip "key: val"
        # rows so e.g. "Organization Name : TEKNOTEL" doesn't shadow the
        # registrant's first-line organization in another section.
        if ":" in line:
            continue
        sections[current].append(line)
    return sections


def _parse_date(s: str) -> datetime | None:
    """Best-effort WHOIS date parser. Stays stdlib-only on purpose."""
    # TRABIS trails its date values with a period ("2024-Aug-27.").
    s = s.strip().rstrip(".")
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%Y-%b-%d",
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
