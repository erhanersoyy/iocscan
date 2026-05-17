import httpx
import pytest

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Verdict
from iocscan.providers.spamhaus import Spamhaus


@pytest.fixture(autouse=True)
def _reset_spamhaus_cache():
    from iocscan.providers import spamhaus
    spamhaus._CACHE.clear()
    spamhaus._CACHE_TS.clear()
    yield


def _c(h):
    return httpx.AsyncClient(transport=httpx.MockTransport(h), timeout=5.0)


DROP_BODY = """; Spamhaus DROP list 2026-05-01
1.2.3.0/24 ; SBL12345
10.10.0.0/16 ; SBL99999
"""


async def test_ip_in_dropped_cidr_returns_malicious():
    async with _c(lambda req: httpx.Response(200, content=DROP_BODY)) as c:
        r = await Spamhaus().lookup("1.2.3.4", IOCType.IP, c, Config())
    assert r.verdict == Verdict.MALICIOUS
    assert "SBL12345" in r.score


async def test_unlisted_ip_clean():
    async with _c(lambda req: httpx.Response(200, content=DROP_BODY)) as c:
        r = await Spamhaus().lookup("8.8.8.8", IOCType.IP, c, Config())
    assert r.verdict == Verdict.CLEAN


async def test_domain_unsupported():
    async with _c(lambda req: httpx.Response(200, content=DROP_BODY)) as c:
        r = await Spamhaus().lookup("evil.com", IOCType.DOMAIN, c, Config())
    assert r.verdict == Verdict.UNKNOWN


async def test_error():
    async with _c(lambda req: httpx.Response(503)) as c:
        r = await Spamhaus().lookup("1.2.3.4", IOCType.IP, c, Config())
    assert r.verdict == Verdict.ERROR
