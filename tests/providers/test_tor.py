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
    tor._FAILED_UNTIL["ts"] = 0.0
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


async def test_tor_response_too_large_rejected():
    """A response body exceeding MAX_BODY must surface as Verdict.ERROR.

    Updated to use an actually oversized body via httpx.ByteStream so that
    the streaming byte-counter (not the old header check) is exercised.
    """
    from iocscan.providers.tor import MAX_BODY

    oversized_body = b"x" * (MAX_BODY + 1)

    def handler(req):
        return httpx.Response(200, stream=httpx.ByteStream(oversized_body))

    async with _c(handler) as c:
        r = await Tor().lookup("1.2.3.4", IOCType.IP, c, Config())
    assert r.verdict == Verdict.ERROR
    assert "too large" in (r.error or "")


async def test_tor_response_no_content_length_still_capped():
    """Body > MAX_BODY with NO content-length header must still surface as Verdict.ERROR.

    The old header-based check would default content_length to 0 and skip the
    guard entirely (the bypass bug).  The streaming byte-counter must catch it
    regardless of whether content-length is present.
    """
    from iocscan.providers.tor import MAX_BODY

    oversized_body = b"x" * (MAX_BODY + 1)

    def handler(req):
        # httpx.ByteStream omits the auto-injected content-length header,
        # simulating a server/MitM that strips or never sends it.
        return httpx.Response(200, stream=httpx.ByteStream(oversized_body))

    async with _c(handler) as c:
        r = await Tor().lookup("1.2.3.4", IOCType.IP, c, Config())
    assert r.verdict == Verdict.ERROR
    assert "too large" in (r.error or "")


async def test_tor_failure_backoff():
    """After a network error, a second request within 30 s must NOT fire another HTTP call."""
    from iocscan.providers import tor

    call_count = {"n": 0}

    def failing_handler(req):
        call_count["n"] += 1
        raise httpx.ConnectError("simulated failure")

    async with _c(failing_handler) as c:
        r1 = await Tor().lookup("1.2.3.4", IOCType.IP, c, Config())
    assert r1.verdict == Verdict.ERROR
    assert call_count["n"] == 1

    # Second call within the backoff window — must NOT issue another HTTP request
    async with _c(failing_handler) as c:
        r2 = await Tor().lookup("1.2.3.4", IOCType.IP, c, Config())
    assert r2.verdict == Verdict.ERROR
    assert call_count["n"] == 1, (
        f"expected 1 HTTP call total (backoff), got {call_count['n']}"
    )
