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
    feodo._FAILED_UNTIL["ts"] = 0.0
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


async def test_feodo_response_too_large_rejected():
    """A response body exceeding MAX_BODY must surface as Verdict.ERROR.

    Updated to use an actually oversized body via httpx.ByteStream so that
    the streaming byte-counter (not the old header check) is exercised.
    """
    from iocscan.providers.feodo import MAX_BODY

    oversized_body = b"x" * (MAX_BODY + 1)

    def handler(req):
        return httpx.Response(200, stream=httpx.ByteStream(oversized_body))

    async with _c(handler) as c:
        r = await Feodo().lookup("1.2.3.4", IOCType.IP, c, Config())
    assert r.verdict == Verdict.ERROR
    assert "too large" in (r.error or "")


async def test_feodo_response_no_content_length_still_capped():
    """Body > MAX_BODY with NO content-length header must still surface as Verdict.ERROR.

    The old header-based check would default content_length to 0 and skip the
    guard entirely (the bypass bug).  The streaming byte-counter must catch it
    regardless of whether content-length is present.
    """
    from iocscan.providers.feodo import MAX_BODY

    oversized_body = b"x" * (MAX_BODY + 1)

    def handler(req):
        # httpx.ByteStream omits the auto-injected content-length header,
        # simulating a server/MitM that strips or never sends it.
        return httpx.Response(200, stream=httpx.ByteStream(oversized_body))

    async with _c(handler) as c:
        r = await Feodo().lookup("1.2.3.4", IOCType.IP, c, Config())
    assert r.verdict == Verdict.ERROR
    assert "too large" in (r.error or "")


async def test_feodo_failure_backoff():
    """After a network error, a second request within 30 s must NOT fire another HTTP call."""
    import asyncio
    from iocscan.providers import feodo

    call_count = {"n": 0}

    def failing_handler(req):
        call_count["n"] += 1
        raise httpx.ConnectError("simulated failure")

    async with _c(failing_handler) as c:
        r1 = await Feodo().lookup("1.2.3.4", IOCType.IP, c, Config())
    assert r1.verdict == Verdict.ERROR
    assert call_count["n"] == 1

    # Second call within the backoff window — must NOT issue another HTTP request
    async with _c(failing_handler) as c:
        r2 = await Feodo().lookup("1.2.3.4", IOCType.IP, c, Config())
    assert r2.verdict == Verdict.ERROR
    assert call_count["n"] == 1, (
        f"expected 1 HTTP call total (backoff), got {call_count['n']}"
    )


async def test_concurrent_load_calls_fetch_only_once(monkeypatch):
    """When 5 coroutines hit _load concurrently, only one HTTP request fires."""
    import asyncio
    from iocscan.providers import feodo
    feodo._CACHE.clear()
    feodo._CACHE_TS.clear()

    call_count = {"n": 0}
    body = '[{"ip_address": "1.2.3.4", "malware": "Emotet"}]'

    async def slow_handler(req):
        call_count["n"] += 1
        await asyncio.sleep(0.05)  # simulate network delay
        return httpx.Response(200, content=body)

    async with httpx.AsyncClient(transport=httpx.MockTransport(slow_handler), timeout=5.0) as c:
        provider = feodo.Feodo()
        from iocscan.core.config import Config
        from iocscan.providers.base import IOCType
        results = await asyncio.gather(*[
            provider.lookup("1.2.3.4", IOCType.IP, c, Config()) for _ in range(5)
        ])

    assert call_count["n"] == 1, f"expected 1 HTTP call, got {call_count['n']}"
    assert all(r.verdict.value == "malicious" for r in results)
