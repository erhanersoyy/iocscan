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
