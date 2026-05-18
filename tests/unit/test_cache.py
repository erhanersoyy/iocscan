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


# --- Security hardening tests (Findings #1b, #8, #9, #10) ---

import os
import stat
from pathlib import Path


def test_cache_directory_mode_is_0700(tmp_path):
    """Finding #1b: cache parent directory must be restricted to owner-only (0o700)."""
    db_path = tmp_path / "subdir" / "cache.db"
    c = Cache(db_path, ttl_seconds=60)
    c.close()
    mode = stat.S_IMODE(os.stat(db_path.parent).st_mode)
    assert mode == 0o700, f"Expected 0o700, got {oct(mode)}"


def test_cache_db_mode_is_0600(tmp_path):
    """Finding #10: cache.db must be restricted to owner-only read/write (0o600)."""
    db_path = tmp_path / "cache.db"
    c = Cache(db_path, ttl_seconds=60)
    c.close()
    mode = stat.S_IMODE(os.stat(db_path).st_mode)
    assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"


def test_cache_wal_mode_enabled(tmp_path):
    """Finding #8: WAL journal mode must be enabled for concurrent access."""
    db_path = tmp_path / "cache.db"
    c = Cache(db_path, ttl_seconds=60)
    row = c._conn.execute("PRAGMA journal_mode").fetchone()
    c.close()
    assert row[0] == "wal", f"Expected 'wal', got {row[0]!r}"


def test_cache_rejects_symlink(tmp_path):
    """Finding #9: Cache must refuse to open a symlink at the cache path."""
    real_file = tmp_path / "real.db"
    real_file.touch()
    symlink_path = tmp_path / "cache.db"
    symlink_path.symlink_to(real_file)
    import pytest
    with pytest.raises(ValueError, match="symlink"):
        Cache(symlink_path, ttl_seconds=60)
