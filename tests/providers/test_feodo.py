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
