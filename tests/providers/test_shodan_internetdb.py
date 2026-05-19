from __future__ import annotations

import httpx

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Verdict
from iocscan.providers.shodan_internetdb import ShodanInternetDB


def _c(h):
    return httpx.AsyncClient(transport=httpx.MockTransport(h), timeout=5.0)


async def test_hit_with_vulns_returns_suspicious():
    def h(req):
        assert req.url.path == "/1.2.3.4"
        return httpx.Response(200, json={
            "ip": "1.2.3.4",
            "ports": [22, 80, 443],
            "vulns": ["CVE-2021-44228"],
            "hostnames": ["target.example.com"],
            "cpes": [],
            "tags": [],
        })
    async with _c(h) as c:
        r = await ShodanInternetDB().lookup("1.2.3.4", IOCType.IP, c, Config())
    assert r.verdict == Verdict.SUSPICIOUS
    assert r.score == "3 ports, 1 vulns"


async def test_hit_without_vulns_returns_clean():
    def h(req):
        return httpx.Response(200, json={
            "ip": "1.2.3.4", "ports": [80], "vulns": [],
            "hostnames": [], "cpes": [], "tags": [],
        })
    async with _c(h) as c:
        r = await ShodanInternetDB().lookup("1.2.3.4", IOCType.IP, c, Config())
    assert r.verdict == Verdict.CLEAN
    assert r.score == "1 ports"


async def test_empty_response_returns_clean_dash():
    def h(req):
        return httpx.Response(200, json={
            "ip": "1.2.3.4", "ports": [], "vulns": [],
            "hostnames": [], "cpes": [], "tags": [],
        })
    async with _c(h) as c:
        r = await ShodanInternetDB().lookup("1.2.3.4", IOCType.IP, c, Config())
    assert r.verdict == Verdict.CLEAN
    assert r.score == "—"


async def test_404_returns_unknown():
    """Not in Shodan's last-30-days scan corpus."""
    async with _c(lambda req: httpx.Response(404)) as c:
        r = await ShodanInternetDB().lookup("10.0.0.1", IOCType.IP, c, Config())
    assert r.verdict == Verdict.UNKNOWN
    assert r.score == "—"


async def test_429_rate_limit():
    async with _c(lambda req: httpx.Response(429)) as c:
        r = await ShodanInternetDB().lookup("1.2.3.4", IOCType.IP, c, Config())
    assert r.verdict == Verdict.ERROR
    assert "429" in r.error


async def test_enrichment_only_flag_set():
    """Spec: ShodanInternetDB must not vote in verdict aggregation."""
    p = ShodanInternetDB()
    assert p.enrichment_only is True


async def test_supports_only_ip():
    p = ShodanInternetDB()
    assert p.supports == {IOCType.IP}
