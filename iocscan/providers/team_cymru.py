"""Team Cymru ASN enrichment over TCP-43.

`whois.cymru.com` responds to `" -v <ip>\\n"` with a multi-column row:
    AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name

This provider never votes — it surfaces ASN + country as context.
Team Cymru asks consumers to keep <=1 concurrent connection per
client; the `max_rps=1.0` cap is conservative.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx  # only for the abstract base; we don't issue HTTP here

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Provider, ProviderResult, Verdict, err_result as _err

HOST = "whois.cymru.com"
PORT = 43
_QUERY_TIMEOUT = 5.0


class TeamCymru(Provider):
    name = "team_cymru"
    supports = {IOCType.IP}
    requires_key = False
    max_rps = 1.0
    enrichment_only = True

    async def lookup(self, ioc: str, ioc_type: IOCType, client: httpx.AsyncClient, config: Config) -> ProviderResult:
        start = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(HOST, PORT), timeout=_QUERY_TIMEOUT,
            )
        except (OSError, asyncio.TimeoutError) as e:
            return _err(self.name, f"network: {e.__class__.__name__}", start)
        try:
            writer.write(f" -v {ioc}\n".encode("ascii"))
            await writer.drain()
            body = await asyncio.wait_for(reader.read(), timeout=_QUERY_TIMEOUT)
        except asyncio.TimeoutError:
            writer.close()
            return _err(self.name, "timeout", start)
        finally:
            # Best-effort close; the server may already have torn the socket
            # down after responding, so swallow secondary errors.
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        latency = int((time.perf_counter() - start) * 1000)
        text = body.decode("utf-8", errors="replace")
        row = _parse_cymru_row(text, ioc)
        if row is None:
            return ProviderResult(self.name, Verdict.UNKNOWN, "—", None, None, latency)
        asn, _ip, _prefix, cc, _reg, _alloc, as_name = row
        score = f"AS{asn} ({as_name}/{cc})"
        data: dict[str, Any] = {"asn": asn, "country": cc, "name": as_name}
        return ProviderResult(self.name, Verdict.CLEAN, score, data, None, latency)


def _parse_cymru_row(text: str, ip: str) -> tuple[str, str, str, str, str, str, str] | None:
    """Find the row matching `ip` in a verbose-format response.

    Header line: `AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name`.
    Skip lines whose first column is `AS` (header) or `NA` (no data).
    """
    for line in text.splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 7:
            continue
        if parts[0] in ("AS", "NA"):
            continue
        if parts[1] == ip:
            return tuple(parts)  # type: ignore[return-value]
    return None
