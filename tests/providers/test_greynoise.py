import httpx

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Verdict
from iocscan.providers.greynoise import GreyNoise


def _c(h):
    return httpx.AsyncClient(transport=httpx.MockTransport(h), timeout=5.0)


async def test_no_key_still_works_keyless():
    body = '{"ip": "8.8.8.8", "classification": "benign", "noise": false, "name": "Google"}'
    captured = {}
    def h(req):
        captured["had_key"] = "key" in req.headers
        return httpx.Response(200, content=body)
    async with _c(h) as c:
        r = await GreyNoise().lookup("8.8.8.8", IOCType.IP, c, Config())
    assert r.verdict == Verdict.CLEAN
    assert captured["had_key"] is False  # no key header when not configured


async def test_key_header_sent_when_configured():
    body = '{"ip": "8.8.8.8", "classification": "benign", "noise": false, "name": "Google"}'
    captured = {}
    def h(req):
        captured["key_value"] = req.headers.get("key")
        return httpx.Response(200, content=body)
    async with _c(h) as c:
        cfg = Config(keys={"greynoise": "MYKEY"})
        await GreyNoise().lookup("8.8.8.8", IOCType.IP, c, cfg)
    assert captured["key_value"] == "MYKEY"


async def test_domain_unsupported():
    async with _c(lambda req: httpx.Response(200, content="{}")) as c:
        cfg = Config(keys={"greynoise": "K"})
        r = await GreyNoise().lookup("evil.com", IOCType.DOMAIN, c, cfg)
    assert r.verdict == Verdict.UNKNOWN


async def test_malicious_classification():
    body = '{"ip": "1.2.3.4", "classification": "malicious", "noise": true, "name": "Mirai"}'
    async with _c(lambda req: httpx.Response(200, content=body)) as c:
        cfg = Config(keys={"greynoise": "K"})
        r = await GreyNoise().lookup("1.2.3.4", IOCType.IP, c, cfg)
    assert r.verdict == Verdict.MALICIOUS
    assert "Mirai" in r.score


async def test_benign_noise_clean():
    body = '{"ip": "8.8.8.8", "classification": "benign", "noise": true, "name": "Google"}'
    async with _c(lambda req: httpx.Response(200, content=body)) as c:
        cfg = Config(keys={"greynoise": "K"})
        r = await GreyNoise().lookup("8.8.8.8", IOCType.IP, c, cfg)
    assert r.verdict == Verdict.CLEAN
    assert "benign" in r.score


async def test_unknown_classification_unknown():
    body = '{"ip": "9.9.9.9", "classification": "unknown", "noise": false}'
    async with _c(lambda req: httpx.Response(200, content=body)) as c:
        cfg = Config(keys={"greynoise": "K"})
        r = await GreyNoise().lookup("9.9.9.9", IOCType.IP, c, cfg)
    assert r.verdict == Verdict.UNKNOWN


async def test_404_unknown():
    async with _c(lambda req: httpx.Response(404)) as c:
        cfg = Config(keys={"greynoise": "K"})
        r = await GreyNoise().lookup("9.9.9.9", IOCType.IP, c, cfg)
    assert r.verdict == Verdict.UNKNOWN
