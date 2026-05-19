"""WHOIS domain age via raw TCP-43 to the authoritative registry.

Two-hop (IANA -> registry) is avoided by maintaining a hardcoded
TLD -> server map for the ~25 highest-volume TLDs. Unknown TLDs
return UNKNOWN rather than chaining through IANA.

Verdict is purely visual: SUSPICIOUS for newly-registered domains
(<30 days) so they stand out, CLEAN otherwise. The aggregator
ignores this row because `enrichment_only = True`.
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


class WhoisAge(Provider):
    name = "whois_age"
    supports = {IOCType.DOMAIN}
    requires_key = False
    max_rps = 2.0
    enrichment_only = True

    async def lookup(self, ioc: str, ioc_type: IOCType, client: httpx.AsyncClient, config: Config) -> ProviderResult:
        start = time.perf_counter()
        tld = ioc.rsplit(".", 1)[-1].lower()
        server = WHOIS_SERVERS.get(tld)
        if server is None:
            latency = int((time.perf_counter() - start) * 1000)
            return ProviderResult(self.name, Verdict.UNKNOWN, "—", None, f"unknown TLD: .{tld}", latency)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(server, PORT), timeout=_QUERY_TIMEOUT,
            )
        except (OSError, asyncio.TimeoutError) as e:
            return _err(self.name, f"network: {e.__class__.__name__}", start)
        try:
            writer.write(f"{ioc}\r\n".encode("ascii"))
            await writer.drain()
            body = await asyncio.wait_for(reader.read(), timeout=_QUERY_TIMEOUT)
        except asyncio.TimeoutError:
            writer.close()
            return _err(self.name, "timeout", start)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        latency = int((time.perf_counter() - start) * 1000)
        text = body.decode("utf-8", errors="replace")
        created = _extract_creation_date(text)
        if created is None:
            return ProviderResult(self.name, Verdict.UNKNOWN, "—", None, "no creation date in response", latency)
        now = datetime.now(timezone.utc)
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age_days = max(0, (now - created).days)
        score = f"{age_days}d old" if age_days < 365 else f"{age_days // 365}y old"
        verdict = Verdict.SUSPICIOUS if age_days < _NRD_DAYS else Verdict.CLEAN
        data: dict[str, Any] = {"creation_date": created.isoformat(), "age_days": age_days, "server": server}
        return ProviderResult(self.name, verdict, score, data, None, latency)


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
    # Strip surrounding quotes and stray characters some registries emit.
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
    # Last resort: take just the date portion (split on either T or space)
    # and try plain ISO date.
    try:
        head = s.split("T", 1)[0].split(" ", 1)[0]
        return datetime.strptime(head, "%Y-%m-%d")
    except ValueError:
        return None
