import json
from pathlib import Path

import httpx
import pytest

from iocscan.providers.base import IOCType, Verdict
from iocscan.providers.urlhaus import URLhaus
from iocscan.core.config import Config

FIXTURES = Path(__file__).parent.parent / "fixtures" / "responses" / "urlhaus"


def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5.0)


async def test_urlhaus_hit_returns_malicious():
    body = (FIXTURES / "hit.json").read_text()
    def handler(req):
        assert req.url.path == "/v1/host/"
        return httpx.Response(200, content=body)
    async with _client(handler) as c:
        r = await URLhaus().lookup("evil.com", IOCType.DOMAIN, c, Config())
    assert r.verdict == Verdict.MALICIOUS
    assert r.score == "12 urls"


async def test_urlhaus_miss_returns_clean():
    body = (FIXTURES / "miss.json").read_text()
    def handler(req): return httpx.Response(200, content=body)
    async with _client(handler) as c:
        r = await URLhaus().lookup("good.com", IOCType.DOMAIN, c, Config())
    assert r.verdict == Verdict.CLEAN


async def test_urlhaus_rate_limit_returns_error():
    def handler(req): return httpx.Response(429)
    async with _client(handler) as c:
        r = await URLhaus().lookup("x.com", IOCType.DOMAIN, c, Config())
    assert r.verdict == Verdict.ERROR
    assert "429" in r.error


async def test_urlhaus_malformed_returns_error():
    def handler(req): return httpx.Response(200, content="not json")
    async with _client(handler) as c:
        r = await URLhaus().lookup("x.com", IOCType.DOMAIN, c, Config())
    assert r.verdict == Verdict.ERROR
    assert "parse" in r.error


async def test_urlhaus_sends_auth_key_header_when_configured():
    body = (FIXTURES / "miss.json").read_text()
    captured = {}
    def handler(req):
        captured["auth"] = req.headers.get("Auth-Key")
        return httpx.Response(200, content=body)
    async with _client(handler) as c:
        cfg = Config(keys={"abusech": "MYKEY"})
        await URLhaus().lookup("test.com", IOCType.DOMAIN, c, cfg)
    assert captured["auth"] == "MYKEY"


async def test_urlhaus_401_returns_auth_failed():
    async with _client(lambda req: httpx.Response(401, content='{"error": "Unauthorized"}')) as c:
        r = await URLhaus().lookup("x.com", IOCType.DOMAIN, c, Config())
    assert r.verdict == Verdict.ERROR
    assert "auth" in r.error.lower() or "401" in r.error
