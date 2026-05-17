from pathlib import Path
import httpx

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Verdict
from iocscan.providers.otx import OTX

FIX = Path(__file__).parent.parent / "fixtures" / "responses" / "otx"


def _c(h):
    return httpx.AsyncClient(transport=httpx.MockTransport(h), timeout=5.0)


async def test_no_key_error():
    async with _c(lambda req: httpx.Response(200, content="{}")) as c:
        r = await OTX().lookup("1.2.3.4", IOCType.IP, c, Config())
    assert r.verdict == Verdict.ERROR
    assert r.error == "key required"


async def test_ip_hit_malicious():
    body = (FIX / "hit.json").read_text()
    def h(req):
        assert req.headers["X-OTX-API-KEY"] == "K"
        assert "/IPv4/1.2.3.4/general" in str(req.url)
        return httpx.Response(200, content=body)
    async with _c(h) as c:
        cfg = Config(keys={"otx": "K"})
        r = await OTX().lookup("1.2.3.4", IOCType.IP, c, cfg)
    assert r.verdict == Verdict.MALICIOUS
    assert "7 pulses" in r.score


async def test_domain_routes_to_domain_endpoint():
    body = (FIX / "clean.json").read_text()
    captured = {}
    def h(req):
        captured["url"] = str(req.url)
        return httpx.Response(200, content=body)
    async with _c(h) as c:
        cfg = Config(keys={"otx": "K"})
        await OTX().lookup("evil.com", IOCType.DOMAIN, c, cfg)
    assert "/domain/evil.com/general" in captured["url"]


async def test_clean():
    body = (FIX / "clean.json").read_text()
    async with _c(lambda req: httpx.Response(200, content=body)) as c:
        cfg = Config(keys={"otx": "K"})
        r = await OTX().lookup("8.8.8.8", IOCType.IP, c, cfg)
    assert r.verdict == Verdict.CLEAN
