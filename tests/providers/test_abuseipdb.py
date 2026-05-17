from pathlib import Path
import httpx

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Verdict
from iocscan.providers.abuseipdb import AbuseIPDB

FIX = Path(__file__).parent.parent / "fixtures" / "responses" / "abuseipdb"


def _c(h):
    return httpx.AsyncClient(transport=httpx.MockTransport(h), timeout=5.0)


async def test_no_key_returns_error():
    async with _c(lambda req: httpx.Response(200, content="{}")) as c:
        r = await AbuseIPDB().lookup("1.2.3.4", IOCType.IP, c, Config())
    assert r.verdict == Verdict.ERROR
    assert r.error == "key required"


async def test_domain_unsupported():
    async with _c(lambda req: httpx.Response(200, content="{}")) as c:
        cfg = Config(keys={"abuseipdb": "K"})
        r = await AbuseIPDB().lookup("evil.com", IOCType.DOMAIN, c, cfg)
    assert r.verdict == Verdict.UNKNOWN


async def test_high_confidence_malicious():
    body = (FIX / "hit.json").read_text()
    def h(req):
        assert req.headers["Key"] == "K"
        assert "1.2.3.4" in str(req.url)
        return httpx.Response(200, content=body)
    async with _c(h) as c:
        cfg = Config(keys={"abuseipdb": "K"})
        r = await AbuseIPDB().lookup("1.2.3.4", IOCType.IP, c, cfg)
    assert r.verdict == Verdict.MALICIOUS
    assert r.score == "95%"


async def test_clean_zero_score():
    body = (FIX / "clean.json").read_text()
    async with _c(lambda req: httpx.Response(200, content=body)) as c:
        cfg = Config(keys={"abuseipdb": "K"})
        r = await AbuseIPDB().lookup("8.8.8.8", IOCType.IP, c, cfg)
    assert r.verdict == Verdict.CLEAN


async def test_suspicious_threshold():
    body = '{"data": {"abuseConfidenceScore": 40, "totalReports": 5}}'
    async with _c(lambda req: httpx.Response(200, content=body)) as c:
        cfg = Config(keys={"abuseipdb": "K"})
        r = await AbuseIPDB().lookup("1.2.3.4", IOCType.IP, c, cfg)
    assert r.verdict == Verdict.SUSPICIOUS
