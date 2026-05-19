from __future__ import annotations

import httpx
import pytest

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Verdict
from iocscan.providers.crtsh import CrtSh


def _c(h):
    return httpx.AsyncClient(transport=httpx.MockTransport(h), timeout=5.0)


async def test_hit_returns_clean_with_count_and_oldest():
    def h(req):
        assert req.url.host == "crt.sh"
        assert req.url.params.get("q") == "example.com"
        assert req.url.params.get("output") == "json"
        return httpx.Response(200, json=[
            {"id": 1, "not_before": "2022-04-12T00:00:00"},
            {"id": 2, "not_before": "2018-04-12T00:00:00"},
            {"id": 3, "not_before": "2020-07-01T00:00:00"},
        ])
    async with _c(h) as c:
        r = await CrtSh().lookup("example.com", IOCType.DOMAIN, c, Config())
    assert r.verdict == Verdict.CLEAN
    assert r.score == "3 certs (oldest 2018-04-12)"
    assert r.raw == {"count": 3, "oldest_not_before": "2018-04-12T00:00:00"}


async def test_empty_list_returns_unknown():
    async with _c(lambda req: httpx.Response(200, json=[])) as c:
        r = await CrtSh().lookup("example.com", IOCType.DOMAIN, c, Config())
    assert r.verdict == Verdict.UNKNOWN
    assert r.score == "—"


async def test_429_returns_error():
    async with _c(lambda req: httpx.Response(429)) as c:
        r = await CrtSh().lookup("example.com", IOCType.DOMAIN, c, Config())
    assert r.verdict == Verdict.ERROR
    assert "429" in r.error


async def test_500_returns_error():
    async with _c(lambda req: httpx.Response(500)) as c:
        r = await CrtSh().lookup("example.com", IOCType.DOMAIN, c, Config())
    assert r.verdict == Verdict.ERROR
    assert "500" in r.error


async def test_parse_error_returns_error():
    async with _c(lambda req: httpx.Response(200, content=b"not json")) as c:
        r = await CrtSh().lookup("example.com", IOCType.DOMAIN, c, Config())
    assert r.verdict == Verdict.ERROR
    assert "parse" in r.error


async def test_network_error_returns_error():
    def h(req):
        raise httpx.ConnectError("boom")
    async with _c(h) as c:
        r = await CrtSh().lookup("example.com", IOCType.DOMAIN, c, Config())
    assert r.verdict == Verdict.ERROR
    assert "network" in r.error


async def test_missing_not_before_in_some_entries_still_picks_real_oldest():
    """If a cert entry lacks `not_before`, it must not poison the min()."""
    def h(req):
        return httpx.Response(200, json=[
            {"id": 1, "not_before": "2019-01-01T00:00:00"},
            {"id": 2},  # no not_before
        ])
    async with _c(h) as c:
        r = await CrtSh().lookup("example.com", IOCType.DOMAIN, c, Config())
    assert r.verdict == Verdict.CLEAN
    assert "2019-01-01" in r.score


async def test_enrichment_only_flag_set():
    assert CrtSh().enrichment_only is True


async def test_supports_only_domain():
    assert CrtSh().supports == {IOCType.DOMAIN}


def test_permalink_domain():
    assert CrtSh().permalink("example.com", IOCType.DOMAIN) == "https://crt.sh/?q=example.com"


def test_permalink_quotes_special_characters():
    # `+` is in the default safe="" exclusion list -> percent-encoded.
    pl = CrtSh().permalink("foo+bar.com", IOCType.DOMAIN)
    assert pl == "https://crt.sh/?q=foo%2Bbar.com"


def test_permalink_non_domain_returns_none():
    assert CrtSh().permalink("1.2.3.4", IOCType.IP) is None
