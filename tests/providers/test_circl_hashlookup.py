from __future__ import annotations

import httpx

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Verdict
from iocscan.providers.circl_hashlookup import CIRCLHashlookup


def _c(h):
    return httpx.AsyncClient(transport=httpx.MockTransport(h), timeout=5.0)


async def test_404_returns_unknown():
    async with _c(lambda req: httpx.Response(404, json={"message": "Non existing"})) as c:
        r = await CIRCLHashlookup().lookup(
            "c30c94f98826253b0019559ac95b72667682ff6934371607b861cbb0b4ae9e52",
            IOCType.HASH_SHA256, c, Config(),
        )
    assert r.verdict == Verdict.UNKNOWN


async def test_nsrl_known_good_returns_clean():
    def h(req):
        assert req.url.path == "/lookup/md5/8ed4b4ed952526d89899e723f3488de4"
        return httpx.Response(200, json={
            "FileName": "notepad.exe",
            "FileSize": "2520",
            "MD5": "8ED4B4ED952526D89899E723F3488DE4",
            "source": "NSRL",
        })
    async with _c(h) as c:
        r = await CIRCLHashlookup().lookup(
            "8ed4b4ed952526d89899e723f3488de4", IOCType.HASH_MD5, c, Config(),
        )
    assert r.verdict == Verdict.CLEAN
    assert r.score == "known good"
    assert "file: notepad.exe" in r.details
    assert "source: NSRL" in r.details


async def test_known_malicious_list_returns_malicious():
    def h(req):
        return httpx.Response(200, json={
            "FileName": "evil.exe",
            "KnownMalicious": ["abuse.ch", "malshare"],
        })
    async with _c(h) as c:
        r = await CIRCLHashlookup().lookup(
            "a" * 64, IOCType.HASH_SHA256, c, Config(),
        )
    assert r.verdict == Verdict.MALICIOUS
    assert "abuse.ch" in r.score and "malshare" in r.score


async def test_sha1_path_routes_correctly():
    captured: dict = {}

    def h(req):
        captured["path"] = req.url.path
        return httpx.Response(404)

    async with _c(h) as c:
        await CIRCLHashlookup().lookup("a" * 40, IOCType.HASH_SHA1, c, Config())
    assert captured["path"].startswith("/lookup/sha1/")


async def test_429_returns_error():
    async with _c(lambda req: httpx.Response(429)) as c:
        r = await CIRCLHashlookup().lookup("a" * 64, IOCType.HASH_SHA256, c, Config())
    assert r.verdict == Verdict.ERROR
    assert "429" in r.error


async def test_500_returns_error():
    async with _c(lambda req: httpx.Response(503)) as c:
        r = await CIRCLHashlookup().lookup("a" * 64, IOCType.HASH_SHA256, c, Config())
    assert r.verdict == Verdict.ERROR
    assert "503" in r.error


async def test_parse_error_on_non_json():
    async with _c(lambda req: httpx.Response(200, content=b"not json")) as c:
        r = await CIRCLHashlookup().lookup("a" * 64, IOCType.HASH_SHA256, c, Config())
    assert r.verdict == Verdict.ERROR
    assert "parse" in r.error


async def test_200_without_nsrl_source_is_unknown():
    """200 with neither KnownMalicious nor an NSRL source marker → UNKNOWN.
    Earlier behaviour was 'CLEAN known good', which incorrectly voted CLEAN
    for ambiguous-provenance records."""
    def h(req):
        return httpx.Response(200, json={"FileName": "x.bin", "source": "custom-feed"})
    async with _c(h) as c:
        r = await CIRCLHashlookup().lookup("a" * 64, IOCType.HASH_SHA256, c, Config())
    assert r.verdict == Verdict.UNKNOWN
    assert "file: x.bin" in r.details


async def test_empty_known_malicious_falls_through_to_unknown():
    """Empty KnownMalicious=[] means 'feed checked, no flags' — not 'known good'."""
    def h(req):
        return httpx.Response(200, json={"FileName": "x.bin", "KnownMalicious": []})
    async with _c(h) as c:
        r = await CIRCLHashlookup().lookup("a" * 64, IOCType.HASH_SHA256, c, Config())
    assert r.verdict == Verdict.UNKNOWN


async def test_nsrl_source_as_list_returns_clean():
    """`source` may arrive as a list — match 'NSRL' case-insensitively in any element."""
    def h(req):
        return httpx.Response(200, json={"source": ["NSRL", "MalwareBazaar"]})
    async with _c(h) as c:
        r = await CIRCLHashlookup().lookup("a" * 64, IOCType.HASH_SHA256, c, Config())
    assert r.verdict == Verdict.CLEAN
    assert r.score == "known good"


async def test_known_malicious_as_dict_uses_keys_as_sources():
    def h(req):
        return httpx.Response(200, json={
            "KnownMalicious": {"abuse.ch": {"first_seen": "2024"}, "malshare": {}},
        })
    async with _c(h) as c:
        r = await CIRCLHashlookup().lookup("a" * 64, IOCType.HASH_SHA256, c, Config())
    assert r.verdict == Verdict.MALICIOUS
    assert "abuse.ch" in r.score and "malshare" in r.score


async def test_filesize_zero_is_preserved_in_details():
    """`is not None` filter must keep legitimate 0/'' values."""
    def h(req):
        return httpx.Response(200, json={
            "FileName": "stub", "FileSize": 0, "source": "NSRL",
        })
    async with _c(h) as c:
        r = await CIRCLHashlookup().lookup("a" * 64, IOCType.HASH_SHA256, c, Config())
    assert "size: 0" in r.details


async def test_permalink_returns_none():
    """CIRCL has no human UI — permalink must not point at the raw JSON endpoint."""
    p = CIRCLHashlookup().permalink("a" * 64, IOCType.HASH_SHA256)
    assert p is None


async def test_unsupported_ioc_type_returns_error_not_raises():
    """Provider contract: `lookup` must never raise. Direct call with a
    non-hash IOCType must return ERROR, not propagate a KeyError."""
    async with _c(lambda req: httpx.Response(200)) as c:
        r = await CIRCLHashlookup().lookup("1.2.3.4", IOCType.IP, c, Config())
    assert r.verdict == Verdict.ERROR
    assert "unsupported" in r.error
