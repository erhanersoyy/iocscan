from __future__ import annotations

import sqlite3
from pathlib import Path

from iocscan.core.observability import SCHEMA, record_results
from iocscan.providers.base import ProviderResult, Verdict


def _populate_db(home: Path) -> None:
    cache_path = home / ".iocscan" / "cache.db"
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(cache_path)
    conn.executescript(SCHEMA)
    record_results(
        conn,
        [
            ProviderResult("vt", Verdict.CLEAN, "0/70", None, None, 200),
            ProviderResult("vt", Verdict.ERROR, "", None, "429 rate limit", 50),
            ProviderResult("otx", Verdict.CLEAN, "0 pulses", None, None, 300),
        ],
    )
    conn.commit()
    conn.close()


def test_health_subcommand_renders_table(tmp_home, capsys):
    """Pre-populate the observability table, then run `iocscan health`."""
    _populate_db(tmp_home)
    from iocscan.cli import main

    rc = main(["health"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "vt" in out
    assert "otx" in out
    # error % should appear; vt has 1 error of 2 samples = 50.0
    assert "50.0" in out


def test_health_subcommand_no_data(tmp_home, capsys):
    from iocscan.cli import main

    rc = main(["health"])
    err = capsys.readouterr().err
    assert "no observations" in err
    assert rc == 0


def test_health_subcommand_respects_days(tmp_home, capsys):
    """--days controls the lookback window."""
    import time

    cache_path = tmp_home / ".iocscan" / "cache.db"
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(cache_path)
    conn.executescript(SCHEMA)
    # Old row outside any reasonable lookback.
    old = int(time.time()) - 100 * 86400
    conn.execute(
        "INSERT INTO observability (provider, event_at, verdict, error, latency_ms) "
        "VALUES (?, ?, ?, ?, ?)",
        ("ancient", old, "clean", None, 100),
    )
    conn.commit()
    conn.close()

    from iocscan.cli import main

    rc = main(["health", "--days", "7"])
    err = capsys.readouterr().err
    assert rc == 0
    assert "no observations" in err
