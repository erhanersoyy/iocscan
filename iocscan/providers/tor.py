from __future__ import annotations

import asyncio
import ipaddress
import json
import time
from datetime import datetime, timezone

import httpx

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Provider, ProviderResult, Verdict, err_result as _err

# Onionoo is the Tor Project's own metrics API. `fields` trims the ~30 MB full
# document down to ~1.2 MB; `exit_addresses` is what a Tor user's traffic
# actually arrives from, while `or_addresses` covers IPv6, which Tor's exit
# scanner (and therefore the older torbulkexitlist feed) never reports.
ENDPOINT = (
    "https://onionoo.torproject.org/details"
    "?type=relay&running=true&fields=or_addresses,exit_addresses,flags"
)
_CACHE: dict[str, dict[str, str]] = {}
_CACHE_TS: dict[str, float] = {}
_CACHE_TTL = 6 * 3600  # in-process cache 6h
# Module-level Lock: Python 3.10+ binds the lock to the running loop on
# first await rather than at construction, so this works under any loop
# the CLI happens to spawn. Do NOT downgrade Python to 3.9.
_LOCK = asyncio.Lock()
# Lower than the 50 MB the plain-text feed providers use. json.loads inflates a
# byte string into a nested object graph roughly an order of magnitude larger, so
# a hostile endpoint could spend the whole allowance on object *count* rather than
# size. Capping entries in _build would be too late — the allocation happens
# during the parse. The real document is ~1.2 MB, so this still leaves 10x headroom.
MAX_BODY = 16 * 1024 * 1024
_FAILURE_TTL = 30  # seconds before retrying after a fetch failure
_FAILED_UNTIL: dict[str, float] = {"ts": 0.0}
# Onionoo republishes hourly. Two days behind means the pipeline is broken, and
# answering "clean" from a snapshot that old is a silent lie — error instead.
_STALE_AFTER = 48 * 3600

# Lower rank wins when one IP is claimed by several relays. Exit outranks guard
# because 71% of exit IPs are also guards, and "traffic arrived anonymised" is
# the more actionable finding than "someone here reached the Tor network".
_LABEL_RANK = {"bad": 0, "exit": 1, "guard": 2, "relay": 3}
_LABEL_RESULT = {
    "bad": (Verdict.SUSPICIOUS, "tor exit (bad)"),
    "exit": (Verdict.SUSPICIOUS, "tor exit"),
    "guard": (Verdict.SUSPICIOUS, "tor guard"),
    # Being a middle relay is infrastructure context, not something to alarm on.
    "relay": (Verdict.CLEAN, "tor relay"),
}


def _norm(addr: str) -> str | None:
    """Reduce an Onionoo address to a canonical IP string, or None if unparseable.

    Onionoo mixes two shapes: `or_addresses` are "ip:port" with IPv6 bracketed
    (`[2620:7::141]:81`), `exit_addresses` are bare IPs. Both must collapse to
    the same spelling the caller's IOC normalises to, since `2620:0007::0141`
    and `2620:7::141` are one address but not one string.
    """
    a = addr.strip()
    if a.startswith("["):
        a = a[1:].split("]", 1)[0]
    elif a.count(":") == 1:  # a bare IPv6 always has >1 colon, so this is v4:port
        a = a.split(":", 1)[0]
    try:
        return ipaddress.ip_address(a).compressed
    except ValueError:
        return None


def _classify(flags: set[str], has_exit_addrs: bool) -> str:
    if "BadExit" in flags:
        return "bad"
    if "Exit" in flags or has_exit_addrs:
        return "exit"
    if "Guard" in flags:
        return "guard"
    return "relay"


def _build(payload: dict) -> dict[str, str]:
    """Flatten the Onionoo document into ip -> label, strongest label winning."""
    table: dict[str, str] = {}
    for relay in payload["relays"]:
        exits = relay.get("exit_addresses") or ()
        label = _classify(set(relay.get("flags") or ()), bool(exits))
        rank = _LABEL_RANK[label]
        for addr in tuple(relay.get("or_addresses") or ()) + tuple(exits):
            ip = _norm(addr)
            if ip is None:
                continue  # one junk address must not take the whole feed down
            current = table.get(ip)
            if current is None or rank < _LABEL_RANK[current]:
                table[ip] = label
    return table


def _reject_if_stale(payload: dict) -> None:
    """Reject a snapshot whose own timestamp says the upstream pipeline stalled.

    Not a tamper check: the timestamp comes from the same payload it validates,
    so anyone able to forge the relay data can forge this too. TLS is what makes
    the feed trustworthy; this only catches a genuinely stuck publisher.
    """
    published = payload.get("relays_published")
    try:
        ts = datetime.strptime(str(published), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        # An upstream format change shouldn't take the provider down; the relay
        # data itself is still usable, we just can't judge its freshness.
        return
    age = (datetime.now(timezone.utc) - ts).total_seconds()
    if age > _STALE_AFTER:
        raise ValueError(f"stale feed ({age / 3600:.0f}h)")


class Tor(Provider):
    name = "tor"
    supports = {IOCType.IP}
    requires_key = False
    max_rps = 1.0
    # Tor membership is context, not a threat signal — journalists and activists
    # use it too. The row is still shown (exit/guard in the suspicious style) but
    # must not vote or count toward coverage.
    enrichment_only = True

    async def lookup(self, ioc: str, ioc_type: IOCType, client: httpx.AsyncClient, config: Config) -> ProviderResult:
        start = time.perf_counter()
        if ioc_type != IOCType.IP:
            return ProviderResult(self.name, Verdict.UNKNOWN, "—", None, None, 0)
        try:
            key = ipaddress.ip_address(ioc).compressed
        except ValueError:
            return ProviderResult(self.name, Verdict.UNKNOWN, "—", None, None, 0)
        try:
            table = await self._load(client)
        except httpx.HTTPError as e:
            return _err(self.name, f"network: {e.__class__.__name__}", start)
        except ValueError as e:
            return _err(self.name, str(e), start)
        except (AttributeError, KeyError, TypeError) as e:
            # _load re-raises these when the document shape changed: a missing
            # "relays" key, or an entry that isn't the dict/str we index into.
            # AttributeError belongs here because we reach into the payload with
            # .get()/.strip() — feodo.py subscripts instead and only ever sees
            # TypeError. The backoff is already armed by _load.
            return _err(self.name, f"feed parse: {e.__class__.__name__}", start)
        latency = int((time.perf_counter() - start) * 1000)
        label = table.get(key)
        if label is None:
            return ProviderResult(self.name, Verdict.CLEAN, "—", None, None, latency)
        verdict, score = _LABEL_RESULT[label]
        return ProviderResult(self.name, verdict, score, None, None, latency)

    async def _load(self, client: httpx.AsyncClient) -> dict[str, str]:
        now = time.time()
        if "data" in _CACHE and now - _CACHE_TS.get("data", 0) < _CACHE_TTL:
            return _CACHE["data"]
        loop = asyncio.get_running_loop()
        async with _LOCK:
            # re-check inside the lock
            now = time.time()
            if "data" in _CACHE and now - _CACHE_TS.get("data", 0) < _CACHE_TTL:
                return _CACHE["data"]
            mono = loop.time()
            if mono < _FAILED_UNTIL["ts"]:
                raise httpx.HTTPError(
                    f"in failure backoff for {_FAILED_UNTIL['ts'] - mono:.0f}s"
                )
            try:
                body = bytearray()
                async with client.stream("GET", ENDPOINT) as resp:
                    if resp.status_code >= 400:
                        raise ValueError(f"{resp.status_code}")
                    async for chunk in resp.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > MAX_BODY:
                            raise ValueError(
                                f"response too large (>{MAX_BODY} bytes)"
                            )
                try:
                    payload = json.loads(bytes(body))
                except json.JSONDecodeError:
                    raise ValueError("feed parse: invalid JSON") from None
                _reject_if_stale(payload)
                table = _build(payload)
                _CACHE["data"] = table
                _CACHE_TS["data"] = now
                return table
            except (httpx.HTTPError, ValueError, AttributeError, KeyError, TypeError, UnicodeDecodeError):
                _FAILED_UNTIL["ts"] = loop.time() + _FAILURE_TTL
                raise
