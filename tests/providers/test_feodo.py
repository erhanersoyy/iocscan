from pathlib import Path
import httpx
import pytest

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Verdict
from iocscan.providers.feodo import Feodo

FIX = Path(__file__).parent.parent / "fixtures" / "responses" / "feodo"


@pytest.fixture(autouse=True)
def _reset_feodo_cache():
    from iocscan.providers import feodo
    feodo._CACHE.clear()
    feodo._CACHE_TS.clear()
    yield


def _c(h):
    return httpx.AsyncClient(transport=httpx.MockTransport(h), timeout=5.0)


async def test_listed_ip_malicious():
    body = (FIX / "list.json").read_text()
    async with _c(lambda req: httpx.Response(200, content=body)) as c:
        r = await Feodo().lookup("1.2.3.4", IOCType.IP, c, Config())
    assert r.verdict == Verdict.MALICIOUS
    assert "Emotet" in r.score


async def test_unlisted_clean():
    body = (FIX / "list.json").read_text()
    async with _c(lambda req: httpx.Response(200, content=body)) as c:
        r = await Feodo().lookup("9.9.9.9", IOCType.IP, c, Config())
    assert r.verdict == Verdict.CLEAN


async def test_domain_unsupported_returns_unknown():
    async with _c(lambda req: httpx.Response(200, content="[]")) as c:
        r = await Feodo().lookup("evil.com", IOCType.DOMAIN, c, Config())
    assert r.verdict == Verdict.UNKNOWN


async def test_error_response():
    async with _c(lambda req: httpx.Response(503)) as c:
        r = await Feodo().lookup("1.2.3.4", IOCType.IP, c, Config())
    assert r.verdict == Verdict.ERROR
