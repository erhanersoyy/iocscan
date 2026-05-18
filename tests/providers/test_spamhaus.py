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
    spamhaus._FAILED_UNTIL["ts"] = 0.0
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


async def test_spamhaus_response_too_large_rejected():
    """Content-Length > 50 MB should surface as Verdict.ERROR, not crash."""
    from iocscan.providers.spamhaus import MAX_BODY
    huge = str(MAX_BODY + 1)

    def handler(req):
        return httpx.Response(
            200,
            content=DROP_BODY,
            headers={"content-length": huge},
        )

    async with _c(handler) as c:
        r = await Spamhaus().lookup("1.2.3.4", IOCType.IP, c, Config())
    assert r.verdict == Verdict.ERROR
    assert "too large" in (r.error or "")


async def test_spamhaus_failure_backoff():
    """After a network error, a second request within 30 s must NOT fire another HTTP call."""
    from iocscan.providers import spamhaus

    call_count = {"n": 0}

    def failing_handler(req):
        call_count["n"] += 1
        raise httpx.ConnectError("simulated failure")

    async with _c(failing_handler) as c:
        r1 = await Spamhaus().lookup("1.2.3.4", IOCType.IP, c, Config())
    assert r1.verdict == Verdict.ERROR
    assert call_count["n"] == 1

    # Second call within the backoff window — must NOT issue another HTTP request
    async with _c(failing_handler) as c:
        r2 = await Spamhaus().lookup("1.2.3.4", IOCType.IP, c, Config())
    assert r2.verdict == Verdict.ERROR
    assert call_count["n"] == 1, (
        f"expected 1 HTTP call total (backoff), got {call_count['n']}"
    )
