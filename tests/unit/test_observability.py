from __future__ import annotations

import sqlite3
import time

from iocscan.core.observability import (
    SCHEMA,
    _percentile,
    health_report,
    record_results,
)
from iocscan.providers.base import ProviderResult, Verdict


def _mkconn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.executescript(SCHEMA)
    return conn


def test_record_and_report_round_trip():
    conn = _mkconn()
    results = [
        ProviderResult("vt", Verdict.MALICIOUS, "12/70", None, None, 300),
        ProviderResult("vt", Verdict.ERROR, "", None, "429 rate limit", 100),
        ProviderResult("otx", Verdict.CLEAN, "0", None, None, 250),
    ]
    record_results(conn, results)
    rows = list(
        conn.execute(
            "SELECT provider, verdict, error, latency_ms "
            "FROM observability ORDER BY provider, event_at, rowid"
        )
    )
    assert rows[0] == ("otx", "clean", None, 250)
    assert rows[1][0] == "vt" and rows[1][1] == "malicious"
    assert rows[2][1] == "error" and "429" in rows[2][2]


def test_health_report_aggregates_per_provider():
    conn = _mkconn()
    results = [
        ProviderResult("vt", Verdict.CLEAN, "", None, None, 100),
        ProviderResult("vt", Verdict.CLEAN, "", None, None, 200),
        ProviderResult("vt", Verdict.ERROR, "", None, "429 rate limit", 50),
        ProviderResult("vt", Verdict.ERROR, "", None, "500 server", 0),
    ]
    record_results(conn, results)
    report = health_report(conn)
    assert len(report) == 1
    vt = report[0]
    assert vt.provider == "vt"
    assert vt.samples == 4
    assert vt.error_count == 2
    assert 0.49 < vt.error_rate < 0.51
    assert vt.last_429_at is not None
    assert vt.last_5xx_at is not None


def test_health_report_respects_lookback():
    conn = _mkconn()
    # Insert an old row manually with a timestamp well in the past.
    old = int(time.time()) - 100 * 86400
    conn.execute(
        "INSERT INTO observability (provider, event_at, verdict, error, latency_ms) "
        "VALUES (?, ?, ?, ?, ?)",
        ("old_provider", old, "clean", None, 100),
    )
    conn.commit()
    record_results(
        conn,
        [ProviderResult("new_provider", Verdict.CLEAN, "", None, None, 100)],
    )
    report = health_report(conn, lookback_seconds=7 * 86400)
    names = [r.provider for r in report]
    assert "new_provider" in names
    assert "old_provider" not in names


def test_record_results_empty_is_noop():
    conn = _mkconn()
    record_results(conn, [])
    rows = list(conn.execute("SELECT COUNT(*) FROM observability"))
    assert rows[0][0] == 0


def test_5xx_classifier_does_not_match_arbitrary_digit_substrings():
    """Latency or count-like errors must NOT trigger last_5xx_at."""
    conn = _mkconn()
    record_results(conn, [
        ProviderResult("vt", Verdict.ERROR, "", None, "latency 5004ms", 5004),
        ProviderResult("otx", Verdict.ERROR, "", None, "got 5006 results", 100),
    ])
    report = health_report(conn)
    by_name = {p.provider: p for p in report}
    assert by_name["vt"].last_5xx_at is None
    assert by_name["otx"].last_5xx_at is None


def test_5xx_classifier_matches_leading_status_code_and_server_token():
    conn = _mkconn()
    record_results(conn, [
        ProviderResult("a", Verdict.ERROR, "", None, "503 server", 0),
        ProviderResult("b", Verdict.ERROR, "", None, "502", 0),
        ProviderResult("c", Verdict.ERROR, "", None, "server timeout", 0),
    ])
    report = health_report(conn)
    by_name = {p.provider: p for p in report}
    assert by_name["a"].last_5xx_at is not None
    assert by_name["b"].last_5xx_at is not None
    assert by_name["c"].last_5xx_at is not None


def test_percentile_helper():
    assert _percentile([], 95) == 0
    assert _percentile([10, 20, 30, 40, 50, 60, 70, 80, 90, 100], 95) == 100
    assert _percentile([10, 20, 30, 40, 50, 60, 70, 80, 90, 100], 50) == 60
