from __future__ import annotations

import json

import httpx

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Verdict
from iocscan.providers.yaraify import YARAify


def _c(h):
    return httpx.AsyncClient(transport=httpx.MockTransport(h), timeout=5.0)


async def test_hit_returns_malicious_with_rule_name():
    def h(req):
        assert req.url.path == "/api/v1/"
        assert req.headers.get("Auth-Key") == "ABCKEY"
        body = json.loads(req.content.decode())
        assert body == {
            "query": "lookup_hash",
            "search_term": "d41d8cd98f00b204e9800998ecf8427e",
        }
        return httpx.Response(200, json={
            "query_status": "ok",
            "data": {"tasks": [{"static_results": [{"rule_name": "Win.Malware.Emotet"}]}]},
        })
    async with _c(h) as c:
        cfg = Config(keys={"abusech": "ABCKEY"})
        r = await YARAify().lookup(
            "d41d8cd98f00b204e9800998ecf8427e", IOCType.HASH_MD5, c, cfg,
        )
    assert r.verdict == Verdict.MALICIOUS
    assert r.score == "Win.Malware.Emotet"


async def test_hit_without_rule_name_uses_fallback():
    def h(req):
        return httpx.Response(200, json={
            "query_status": "ok",
            "data": {"tasks": [{"static_results": []}]},
        })
    async with _c(h) as c:
        cfg = Config(keys={"abusech": "ABCKEY"})
        r = await YARAify().lookup(
            "d41d8cd98f00b204e9800998ecf8427e", IOCType.HASH_MD5, c, cfg,
        )
    assert r.verdict == Verdict.MALICIOUS
    assert r.score == "yara match"


async def test_miss_returns_clean():
    def h(req):
        return httpx.Response(200, json={"query_status": "no_results"})
    async with _c(h) as c:
        cfg = Config(keys={"abusech": "ABCKEY"})
        r = await YARAify().lookup(
            "d41d8cd98f00b204e9800998ecf8427e", IOCType.HASH_MD5, c, cfg,
        )
    assert r.verdict == Verdict.CLEAN
    assert r.score == "—"


async def test_401_auth_failed():
    async with _c(lambda req: httpx.Response(401)) as c:
        cfg = Config(keys={"abusech": "BAD"})
        r = await YARAify().lookup(
            "d41d8cd98f00b204e9800998ecf8427e", IOCType.HASH_MD5, c, cfg,
        )
    assert r.verdict == Verdict.ERROR
    assert "auth" in r.error


async def test_429_rate_limit():
    async with _c(lambda req: httpx.Response(429)) as c:
        cfg = Config(keys={"abusech": "K"})
        r = await YARAify().lookup(
            "d41d8cd98f00b204e9800998ecf8427e", IOCType.HASH_MD5, c, cfg,
        )
    assert r.verdict == Verdict.ERROR
    assert "429" in r.error
