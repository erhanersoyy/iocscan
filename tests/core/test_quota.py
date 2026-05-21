from __future__ import annotations

import httpx
import pytest

from iocscan.core.config import Config
from iocscan.core.quota import QuotaResult, probe_quotas
from iocscan.providers.abuseipdb import AbuseIPDB
from iocscan.providers.virustotal import VirusTotal


def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5.0)


async def test_vt_quota_parsed_from_overall_quotas(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("IOCSCAN_VT_KEY", "deadbeef")
    cfg = Config(keys={"virustotal": "deadbeef"})

    def h(req: httpx.Request):
        assert "deadbeef" in str(req.url)
        return httpx.Response(200, json={
            "data": {"api_requests_daily": {
                "user": {"used": 142, "allowed": 500}
            }}
        })

    async with _client(h) as client:
        out = await probe_quotas([VirusTotal()], cfg, client)
    q = out["virustotal"]
    assert q.used == 142
    assert q.allowed == 500
    assert q.note == ""


async def test_vt_no_key_returns_no_key_note():
    cfg = Config()
    async with _client(lambda r: httpx.Response(500)) as client:
        out = await probe_quotas([VirusTotal()], cfg, client)
    assert out["virustotal"] == QuotaResult(
        provider="virustotal", used=None, allowed=None, note="No Key",
    )


async def test_vt_401_returns_error_note(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    cfg = Config(keys={"virustotal": "bad"})
    async with _client(lambda r: httpx.Response(401)) as client:
        out = await probe_quotas([VirusTotal()], cfg, client)
    assert out["virustotal"].note.startswith("error: 401")


async def test_abuseipdb_quota_from_headers(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    cfg = Config(keys={"abuseipdb": "abc"})

    def h(req):
        assert req.headers.get("Key") == "abc"
        return httpx.Response(
            200,
            headers={"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "857"},
            json={"data": {"abuseConfidenceScore": 0}},
        )

    async with _client(h) as client:
        out = await probe_quotas([AbuseIPDB()], cfg, client)
    q = out["abuseipdb"]
    assert q.used == 143  # 1000 - 857
    assert q.allowed == 1000
    assert q.note == ""


async def test_abuseipdb_no_key_returns_no_key():
    cfg = Config()
    async with _client(lambda r: httpx.Response(500)) as client:
        out = await probe_quotas([AbuseIPDB()], cfg, client)
    assert out["abuseipdb"].note == "No Key"


async def test_unsupported_provider_returns_no_quota_api(monkeypatch, tmp_path):
    """Provider with a key but no probe path -> 'no quota API'."""
    from iocscan.providers.otx import OTX

    monkeypatch.setenv("HOME", str(tmp_path))
    cfg = Config(keys={"otx": "abc"})
    async with _client(lambda r: httpx.Response(500)) as client:
        out = await probe_quotas([OTX()], cfg, client)
    assert out["otx"].note == "no quota API"


async def test_timeout_sets_timeout_note(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    cfg = Config(keys={"virustotal": "x"})

    async def slow_handler(req):
        raise httpx.ReadTimeout("simulated", request=req)

    async with _client(slow_handler) as client:
        out = await probe_quotas([VirusTotal()], cfg, client, timeout_seconds=0.01)
    assert out["virustotal"].note in ("timeout", "error: ReadTimeout")
