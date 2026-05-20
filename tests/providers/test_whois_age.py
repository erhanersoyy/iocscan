from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Verdict
from iocscan.providers.whois_age import WhoisAge


class _FakeReader:
    def __init__(self, data: bytes):
        self._data = data

    async def read(self, n: int = -1) -> bytes:
        chunk = self._data
        self._data = b""
        return chunk if n < 0 else chunk[:n]


class _FakeWriter:
    def __init__(self):
        self.written = bytearray()

    def write(self, data: bytes) -> None:
        self.written.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        return None

    async def wait_closed(self) -> None:
        return None


def _stub_open(response_bytes: bytes, captured: dict | None = None):
    async def _open(host: str, port: int):
        writer = _FakeWriter()
        if captured is not None:
            captured["host"] = host
            captured["port"] = port
            captured["writer"] = writer
        return _FakeReader(response_bytes), writer
    return _open


def _whois_body(creation_line: str) -> bytes:
    """Build a minimal WHOIS-shaped body containing a single Creation Date row."""
    body = (
        "Domain Name: EXAMPLE.COM\r\n"
        f"{creation_line}\r\n"
        "Registry Expiry Date: 2030-01-01T00:00:00Z\r\n"
    )
    return body.encode("ascii")


async def test_old_domain_returns_clean_with_year_score(monkeypatch):
    captured: dict = {}
    body = _whois_body("Creation Date: 2010-01-01T00:00:00Z")
    monkeypatch.setattr(asyncio, "open_connection", _stub_open(body, captured))
    r = await WhoisAge().lookup("example.com", IOCType.DOMAIN, httpx.AsyncClient(), Config())
    assert r.verdict == Verdict.CLEAN
    # Year-formatted score (>= 365d): `Ny old`
    assert r.score.endswith("y old")
    # Routed to the .com authoritative server
    assert captured["host"] == "whois.verisign-grs.com"
    assert captured["port"] == 43
    assert b"example.com\r\n" in bytes(captured["writer"].written)


async def test_newly_registered_returns_suspicious(monkeypatch):
    # Pick a creation date 7 days ago so the boundary is unambiguous.
    seven_days_ago = (datetime.now(timezone.utc) - timedelta(days=7))
    line = "Creation Date: " + seven_days_ago.strftime("%Y-%m-%dT%H:%M:%SZ")
    monkeypatch.setattr(asyncio, "open_connection", _stub_open(_whois_body(line)))
    r = await WhoisAge().lookup("brand-new.com", IOCType.DOMAIN, httpx.AsyncClient(), Config())
    assert r.verdict == Verdict.SUSPICIOUS
    assert r.score.endswith("d old")
    # Allow ±1 day drift across the day boundary.
    age = int(r.score.split("d", 1)[0])
    assert 6 <= age <= 8


async def test_threshold_boundary_is_clean(monkeypatch):
    """A 31-day-old domain is past the 30-day NRD threshold -> CLEAN."""
    thirty_one_days_ago = (datetime.now(timezone.utc) - timedelta(days=31))
    line = "Creation Date: " + thirty_one_days_ago.strftime("%Y-%m-%dT%H:%M:%SZ")
    monkeypatch.setattr(asyncio, "open_connection", _stub_open(_whois_body(line)))
    r = await WhoisAge().lookup("month-old.com", IOCType.DOMAIN, httpx.AsyncClient(), Config())
    assert r.verdict == Verdict.CLEAN


async def test_missing_creation_date_returns_unknown(monkeypatch):
    body = b"Domain Name: PRIVATE.COM\r\nRegistrar: redacted\r\n"
    monkeypatch.setattr(asyncio, "open_connection", _stub_open(body))
    r = await WhoisAge().lookup("private.com", IOCType.DOMAIN, httpx.AsyncClient(), Config())
    assert r.verdict == Verdict.UNKNOWN
    assert r.score == "—"


async def test_unknown_tld_short_circuits_without_socket(monkeypatch):
    """Unknown TLD must not open a TCP connection at all."""
    called: dict = {"opened": False}

    async def _open(host: str, port: int):
        called["opened"] = True
        raise AssertionError("should not open connection for unknown TLD")

    monkeypatch.setattr(asyncio, "open_connection", _open)
    r = await WhoisAge().lookup("foo.xn--p1ai", IOCType.DOMAIN, httpx.AsyncClient(), Config())
    assert called["opened"] is False
    assert r.verdict == Verdict.UNKNOWN
    assert "unknown TLD" in (r.error or "")


async def test_network_error_returns_error(monkeypatch):
    async def _raise(host, port):
        raise OSError("connection refused")
    monkeypatch.setattr(asyncio, "open_connection", _raise)
    r = await WhoisAge().lookup("example.com", IOCType.DOMAIN, httpx.AsyncClient(), Config())
    assert r.verdict == Verdict.ERROR
    assert "OSError" in r.error


async def test_lowercase_created_pattern_matches(monkeypatch):
    """Many ccTLDs use lowercase `created:` instead of `Creation Date:`."""
    line = "created:        2005-06-15"
    monkeypatch.setattr(asyncio, "open_connection", _stub_open(_whois_body(line)))
    r = await WhoisAge().lookup("example.com", IOCType.DOMAIN, httpx.AsyncClient(), Config())
    assert r.verdict == Verdict.CLEAN
    assert r.score.endswith("y old")


async def test_enrichment_only_flag_set():
    assert WhoisAge().enrichment_only is True


async def test_supports_domain_and_ip():
    assert WhoisAge().supports == {IOCType.DOMAIN, IOCType.IP}


async def test_no_permalink():
    """WHOIS has no canonical per-domain web UI; default None inherited."""
    assert WhoisAge().permalink("example.com", IOCType.DOMAIN) is None


# ----- IP-mode tests -----------------------------------------------------

_ARIN_BODY = (
    "% IANA WHOIS server\n"
    "refer:        whois.arin.net\n"
    "\n"
    "NetRange:       52.145.0.0 - 52.191.255.255\n"
    "CIDR:           52.160.0.0/11, 52.148.0.0/14, 52.152.0.0/13, 52.145.0.0/16, 52.146.0.0/15\n"
    "NetName:        MSFT\n"
    "NetHandle:      NET-52-145-0-0-1\n"
    "Parent:         NET52 (NET-52-0-0-0-0)\n"
    "NetType:        Direct Allocation\n"
    "OriginAS:       \n"
    "Organization:   Microsoft Corporation (MSFT)\n"
    "RegDate:        2015-11-24\n"
    "Updated:        2021-12-14\n"
    "Ref:            https://rdap.arin.net/registry/ip/52.145.0.0\n"
).encode("ascii")


def _stub_open_per_host(host_to_body: dict[str, bytes], history: list[str] | None = None):
    """Stub asyncio.open_connection that picks the response body per host.

    Lets us simulate IANA -> RIR refer chaining: the IANA host returns a
    short `refer:` body, the RIR host returns the full ARIN-style record.
    """
    async def _open(host: str, port: int):
        if history is not None:
            history.append(host)
        body = host_to_body.get(host, b"")
        return _FakeReader(body), _FakeWriter()
    return _open


async def test_ip_lookup_follows_iana_refer_and_parses_arin_fields(monkeypatch):
    iana = b"refer:        whois.arin.net\n"
    history: list[str] = []
    monkeypatch.setattr(
        asyncio, "open_connection",
        _stub_open_per_host({"whois.iana.org": iana, "whois.arin.net": _ARIN_BODY}, history),
    )
    r = await WhoisAge().lookup("52.166.126.216", IOCType.IP, httpx.AsyncClient(), Config())
    assert history == ["whois.iana.org", "whois.arin.net"]
    assert r.verdict == Verdict.CLEAN
    assert r.score == "MSFT"
    # Every requested field is captured in raw (OriginAS may be empty).
    raw = r.raw or {}
    assert raw["NetRange"] == "52.145.0.0 - 52.191.255.255"
    assert raw["CIDR"].startswith("52.160.0.0/11")
    assert raw["NetName"] == "MSFT"
    assert raw["NetHandle"] == "NET-52-145-0-0-1"
    assert raw["Parent"] == "NET52 (NET-52-0-0-0-0)"
    assert raw["NetType"] == "Direct Allocation"
    assert raw["Organization"] == "Microsoft Corporation (MSFT)"
    assert raw["RegDate"] == "2015-11-24"
    assert raw["Updated"] == "2021-12-14"
    assert raw["Ref"] == "https://rdap.arin.net/registry/ip/52.145.0.0"
    assert raw["server"] == "whois.arin.net"


async def test_ip_lookup_falls_back_to_iana_when_no_refer(monkeypatch):
    """If IANA already carries the netinfo (no refer:), don't make a 2nd hop."""
    no_refer = (
        b"% IANA WHOIS server\n"
        b"NetRange:       52.145.0.0 - 52.191.255.255\n"
        b"NetName:        MSFT\n"
        b"Organization:   Microsoft Corporation (MSFT)\n"
    )
    history: list[str] = []
    monkeypatch.setattr(
        asyncio, "open_connection",
        _stub_open_per_host({"whois.iana.org": no_refer}, history),
    )
    r = await WhoisAge().lookup("52.166.126.216", IOCType.IP, httpx.AsyncClient(), Config())
    assert history == ["whois.iana.org"]
    assert r.verdict == Verdict.CLEAN
    assert r.score == "MSFT"


async def test_ip_lookup_empty_response_is_unknown(monkeypatch):
    history: list[str] = []
    monkeypatch.setattr(
        asyncio, "open_connection",
        _stub_open_per_host({"whois.iana.org": b"% no data\n"}, history),
    )
    r = await WhoisAge().lookup("203.0.113.99", IOCType.IP, httpx.AsyncClient(), Config())
    assert r.verdict == Verdict.UNKNOWN
    assert r.score == "—"
    assert "no netinfo" in (r.error or "")


async def test_ip_lookup_refuses_non_rir_refer(monkeypatch):
    """A MitM-rewritten refer line pointing at localhost must not trigger a 2nd hop."""
    iana = b"refer:        127.0.0.1\n"
    history: list[str] = []
    monkeypatch.setattr(
        asyncio, "open_connection",
        _stub_open_per_host({"whois.iana.org": iana}, history),
    )
    r = await WhoisAge().lookup("8.8.8.8", IOCType.IP, httpx.AsyncClient(), Config())
    # Only the IANA hop should have happened; the bogus refer is ignored.
    assert history == ["whois.iana.org"]
    # IANA body had no netinfo fields, so we get UNKNOWN — not an SSRF call.
    assert r.verdict == Verdict.UNKNOWN


async def test_ip_lookup_iana_network_error_returns_error(monkeypatch):
    async def _raise(host, port):
        raise OSError("connection refused")
    monkeypatch.setattr(asyncio, "open_connection", _raise)
    r = await WhoisAge().lookup("8.8.8.8", IOCType.IP, httpx.AsyncClient(), Config())
    assert r.verdict == Verdict.ERROR
    assert "OSError" in (r.error or "")
