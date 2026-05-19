from __future__ import annotations

import asyncio

import httpx
import pytest

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Verdict
from iocscan.providers.team_cymru import TeamCymru


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
    """Stub for asyncio.open_connection that returns a (reader, writer)
    pre-loaded with `response_bytes` and captures what the caller wrote.
    """
    async def _open(host: str, port: int):
        writer = _FakeWriter()
        if captured is not None:
            captured["host"] = host
            captured["port"] = port
            captured["writer"] = writer
        return _FakeReader(response_bytes), writer
    return _open


_HIT_RESPONSE = (
    b"AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name\n"
    b"15169   | 8.8.8.8          | 8.8.8.0/24          | US | arin     | 2014-03-14 | GOOGLE\n"
)
_NA_RESPONSE = b""


async def test_hit_returns_clean_with_asn_score(monkeypatch):
    captured: dict = {}
    monkeypatch.setattr(asyncio, "open_connection", _stub_open(_HIT_RESPONSE, captured))
    r = await TeamCymru().lookup("8.8.8.8", IOCType.IP, httpx.AsyncClient(), Config())
    assert r.verdict == Verdict.CLEAN
    assert "AS15169" in r.score
    assert "GOOGLE" in r.score
    assert "US" in r.score
    assert captured["host"] == "whois.cymru.com"
    assert captured["port"] == 43
    assert b" -v 8.8.8.8\n" in bytes(captured["writer"].written)


async def test_hit_returns_structured_raw(monkeypatch):
    monkeypatch.setattr(asyncio, "open_connection", _stub_open(_HIT_RESPONSE))
    r = await TeamCymru().lookup("8.8.8.8", IOCType.IP, httpx.AsyncClient(), Config())
    assert r.raw == {"asn": "15169", "country": "US", "name": "GOOGLE"}


async def test_miss_returns_unknown(monkeypatch):
    monkeypatch.setattr(asyncio, "open_connection", _stub_open(_NA_RESPONSE))
    r = await TeamCymru().lookup("10.0.0.1", IOCType.IP, httpx.AsyncClient(), Config())
    assert r.verdict == Verdict.UNKNOWN
    assert r.score == "—"


async def test_na_row_is_treated_as_miss(monkeypatch):
    """Team Cymru returns rows starting with `NA` when the IP isn't routed."""
    na_response = (
        b"AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name\n"
        b"NA      | 10.0.0.1         | NA                  | NA | NA       | NA         | NA\n"
    )
    monkeypatch.setattr(asyncio, "open_connection", _stub_open(na_response))
    r = await TeamCymru().lookup("10.0.0.1", IOCType.IP, httpx.AsyncClient(), Config())
    assert r.verdict == Verdict.UNKNOWN


async def test_network_error_returns_error(monkeypatch):
    async def _raise(host, port):
        raise OSError("connection refused")
    monkeypatch.setattr(asyncio, "open_connection", _raise)
    r = await TeamCymru().lookup("1.2.3.4", IOCType.IP, httpx.AsyncClient(), Config())
    assert r.verdict == Verdict.ERROR
    assert "OSError" in r.error


async def test_enrichment_only_flag_set():
    """Spec: TeamCymru must not vote in verdict aggregation."""
    assert TeamCymru().enrichment_only is True


async def test_supports_only_ip():
    assert TeamCymru().supports == {IOCType.IP}


async def test_no_permalink():
    """Team Cymru has no per-IP web UI; default None inherited from base."""
    assert TeamCymru().permalink("1.2.3.4", IOCType.IP) is None
