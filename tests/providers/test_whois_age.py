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


async def test_supports_only_domain():
    assert WhoisAge().supports == {IOCType.DOMAIN}


async def test_no_permalink():
    """WHOIS has no canonical per-domain web UI; default None inherited."""
    assert WhoisAge().permalink("example.com", IOCType.DOMAIN) is None
