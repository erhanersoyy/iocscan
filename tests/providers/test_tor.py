import httpx
import pytest

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Verdict
from iocscan.providers.tor import Tor


@pytest.fixture(autouse=True)
def _reset_tor_cache():
    from iocscan.providers import tor
    tor._CACHE.clear()
    tor._CACHE_TS.clear()
    yield


def _c(h):
    return httpx.AsyncClient(transport=httpx.MockTransport(h), timeout=5.0)


async def test_listed_ip_suspicious():
    body = "1.2.3.4\n5.6.7.8\n"
    async with _c(lambda req: httpx.Response(200, content=body)) as c:
        r = await Tor().lookup("1.2.3.4", IOCType.IP, c, Config())
    assert r.verdict == Verdict.SUSPICIOUS
    assert r.score == "tor exit"


async def test_unlisted_clean():
    async with _c(lambda req: httpx.Response(200, content="1.2.3.4\n")) as c:
        r = await Tor().lookup("9.9.9.9", IOCType.IP, c, Config())
    assert r.verdict == Verdict.CLEAN


async def test_domain_unsupported():
    async with _c(lambda req: httpx.Response(200, content="")) as c:
        r = await Tor().lookup("evil.com", IOCType.DOMAIN, c, Config())
    assert r.verdict == Verdict.UNKNOWN


async def test_error():
    async with _c(lambda req: httpx.Response(503)) as c:
        r = await Tor().lookup("1.2.3.4", IOCType.IP, c, Config())
    assert r.verdict == Verdict.ERROR
