import time

from iocscan.core.cache import Cache
from iocscan.providers.base import ProviderResult, Verdict


def _r(p="x", v=Verdict.CLEAN):
    return ProviderResult(p, v, "—", {"a": 1}, None, 12)


def test_cache_miss_returns_empty(tmp_home):
    c = Cache(tmp_home / "cache.db", ttl_seconds=60)
    assert c.get("1.2.3.4") == {}


def test_cache_roundtrip(tmp_home):
    c = Cache(tmp_home / "cache.db", ttl_seconds=60)
    c.put("1.2.3.4", [_r("vt"), _r("abuseipdb")])
    got = c.get("1.2.3.4")
    assert set(got.keys()) == {"vt", "abuseipdb"}
    assert got["vt"].verdict == Verdict.CLEAN
    assert got["vt"].raw == {"a": 1}


def test_cache_expired_entries_excluded(tmp_home):
    c = Cache(tmp_home / "cache.db", ttl_seconds=1)
    c.put("1.2.3.4", [_r("vt")])
    time.sleep(1.1)
    assert c.get("1.2.3.4") == {}


def test_cache_partial_hit(tmp_home):
    c = Cache(tmp_home / "cache.db", ttl_seconds=60)
    c.put("1.2.3.4", [_r("vt"), _r("otx")])
    got = c.get("1.2.3.4")
    assert set(got.keys()) == {"vt", "otx"}


def test_cache_clear(tmp_home):
    c = Cache(tmp_home / "cache.db", ttl_seconds=60)
    c.put("1.2.3.4", [_r("vt")])
    c.clear()
    assert c.get("1.2.3.4") == {}


def test_cache_stats(tmp_home):
    c = Cache(tmp_home / "cache.db", ttl_seconds=60)
    c.put("1.2.3.4", [_r("vt"), _r("otx")])
    c.put("5.6.7.8", [_r("vt")])
    stats = c.stats()
    assert stats["rows"] == 3
    assert stats["iocs"] == 2


def test_cache_stats_includes_size_and_oldest(tmp_home):
    c = Cache(tmp_home / "cache.db", ttl_seconds=60)
    c.put("1.2.3.4", [_r("vt")])
    stats = c.stats()
    assert "size_bytes" in stats and stats["size_bytes"] > 0
    assert "oldest_epoch" in stats and stats["oldest_epoch"] > 0
