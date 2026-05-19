from __future__ import annotations

import httpx

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Verdict
from iocscan.providers.urlscan import URLScan


def _c(h):
    return httpx.AsyncClient(transport=httpx.MockTransport(h), timeout=5.0)


async def test_zero_results_returns_clean():
    async with _c(lambda req: httpx.Response(200, json={"results": [], "total": 0})) as c:
        r = await URLScan().lookup("https://safe.com/", IOCType.URL, c, Config())
    assert r.verdict == Verdict.CLEAN
    assert r.score == "—"


async def test_any_malicious_returns_malicious():
    def h(req):
        return httpx.Response(200, json={
            "results": [
                {"verdicts": {"overall": {"malicious": True}}},
                {"verdicts": {"overall": {"malicious": False}}},
                {"verdicts": {"overall": {"malicious": True}}},
            ],
            "total": 3,
        })
    async with _c(h) as c:
        r = await URLScan().lookup("https://evil.com/", IOCType.URL, c, Config())
    assert r.verdict == Verdict.MALICIOUS
    assert r.score == "3 scans (2 malicious)"


async def test_results_without_malicious_returns_suspicious():
    def h(req):
        return httpx.Response(200, json={
            "results": [
                {"verdicts": {"overall": {"malicious": False}}},
                {"verdicts": {}},
            ],
            "total": 2,
        })
    async with _c(h) as c:
        r = await URLScan().lookup("https://meh.com/", IOCType.URL, c, Config())
    assert r.verdict == Verdict.SUSPICIOUS
    assert r.score == "2 scans"


async def test_query_includes_page_url_filter():
    captured = {}
    def h(req):
        captured["url"] = str(req.url)
        return httpx.Response(200, json={"results": [], "total": 0})
    async with _c(h) as c:
        await URLScan().lookup("https://target.example.com/path", IOCType.URL, c, Config())
    assert "q=page.url" in captured["url"]
    assert "target.example.com" in captured["url"]


async def test_api_key_header_when_configured():
    captured = {}
    def h(req):
        captured["auth"] = req.headers.get("API-Key")
        return httpx.Response(200, json={"results": [], "total": 0})
    async with _c(h) as c:
        cfg = Config(keys={"urlscan": "KEY"})
        await URLScan().lookup("https://x.com/", IOCType.URL, c, cfg)
    assert captured["auth"] == "KEY"


async def test_null_total_treated_as_zero():
    """API edge: `total: null` must not raise; fall back to len(results)."""
    async with _c(lambda req: httpx.Response(200, json={"results": [], "total": None})) as c:
        r = await URLScan().lookup("https://x.com/", IOCType.URL, c, Config())
    assert r.verdict == Verdict.CLEAN


async def test_429_rate_limit():
    async with _c(lambda req: httpx.Response(429)) as c:
        r = await URLScan().lookup("https://x.com/", IOCType.URL, c, Config())
    assert r.verdict == Verdict.ERROR
    assert "429" in r.error


async def test_401_auth_failed():
    async with _c(lambda req: httpx.Response(401)) as c:
        cfg = Config(keys={"urlscan": "BAD"})
        r = await URLScan().lookup("https://x.com/", IOCType.URL, c, cfg)
    assert r.verdict == Verdict.ERROR
    assert "auth" in r.error
