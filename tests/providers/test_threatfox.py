from pathlib import Path
import httpx

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Verdict
from iocscan.providers.threatfox import ThreatFox

FIX = Path(__file__).parent.parent / "fixtures" / "responses" / "threatfox"


def _c(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5.0)


async def test_hit_malicious():
    body = (FIX / "hit.json").read_text()
    def h(req):
        assert req.url.path == "/api/v1/"
        import json
        payload = json.loads(req.content)
        assert payload["query"] == "search_ioc"
        return httpx.Response(200, content=body)
    async with _c(h) as c:
        r = await ThreatFox().lookup("1.2.3.4", IOCType.IP, c, Config())
    assert r.verdict == Verdict.MALICIOUS
    assert "Emotet" in r.score


async def test_miss_clean():
    body = (FIX / "miss.json").read_text()
    async with _c(lambda req: httpx.Response(200, content=body)) as c:
        r = await ThreatFox().lookup("8.8.8.8", IOCType.IP, c, Config())
    assert r.verdict == Verdict.CLEAN


async def test_rate_limit():
    async with _c(lambda req: httpx.Response(429)) as c:
        r = await ThreatFox().lookup("x", IOCType.IP, c, Config())
    assert r.verdict == Verdict.ERROR
    assert "429" in r.error


async def test_malformed():
    async with _c(lambda req: httpx.Response(200, content="bad")) as c:
        r = await ThreatFox().lookup("x", IOCType.IP, c, Config())
    assert r.verdict == Verdict.ERROR
    assert "parse" in r.error


async def test_threatfox_sends_auth_key_header_when_configured():
    body = (FIX / "miss.json").read_text()
    captured = {}
    def h(req):
        captured["auth"] = req.headers.get("Auth-Key")
        return httpx.Response(200, content=body)
    async with _c(h) as c:
        cfg = Config(keys={"abusech": "MYKEY"})
        await ThreatFox().lookup("1.2.3.4", IOCType.IP, c, cfg)
    assert captured["auth"] == "MYKEY"


async def test_threatfox_401_returns_auth_failed():
    async with _c(lambda req: httpx.Response(401, content='{"error":"Unauthorized"}')) as c:
        r = await ThreatFox().lookup("x", IOCType.IP, c, Config())
    assert r.verdict == Verdict.ERROR


async def test_hash_search_returns_malicious_on_hit():
    captured = {}
    def h(req):
        captured["body"] = req.content
        return httpx.Response(200, json={
            "query_status": "ok",
            "data": [{"malware": "Emotet"}],
        })
    async with _c(h) as c:
        r = await ThreatFox().lookup(
            "d41d8cd98f00b204e9800998ecf8427e", IOCType.HASH_MD5, c, Config(),
        )
    assert b"d41d8cd98f00b204e9800998ecf8427e" in captured["body"]
    assert r.verdict == Verdict.MALICIOUS
    assert r.score == "Emotet"


async def test_url_search_returns_malicious_on_hit():
    captured = {}
    def h(req):
        captured["body"] = req.content
        return httpx.Response(200, json={
            "query_status": "ok",
            "data": [{"malware": "Emotet"}],
        })
    async with _c(h) as c:
        r = await ThreatFox().lookup(
            "https://evil.com/c2", IOCType.URL, c, Config(),
        )
    assert b"https://evil.com/c2" in captured["body"]
    assert r.verdict == Verdict.MALICIOUS
