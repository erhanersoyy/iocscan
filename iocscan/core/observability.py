"""Per-provider observability — last-error / p95-latency / error-rate.

Recorded after every provider lookup (driven from `cli._run_scan` alongside
the existing result cache). Stored in the same SQLite file as the result
cache so we keep a single DB.

The schema is intentionally append-only and best-effort: a failed insert
must never block a scan. Aggregation (`health_report`) reads everything
back, groups by provider, and surfaces last-error / last-429 / last-5xx
timestamps plus p95 latency and error rate — enough to answer "which
provider is failing right now?" without parsing per-response headers.
"""
from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from typing import Iterable

from iocscan.providers.base import ProviderResult, Verdict

SCHEMA = """
CREATE TABLE IF NOT EXISTS observability (
  provider     TEXT NOT NULL,
  event_at     INTEGER NOT NULL,
  verdict      TEXT NOT NULL,
  error        TEXT,
  latency_ms   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS observability_provider_event_at
  ON observability(provider, event_at DESC);
"""


def record_results(conn: sqlite3.Connection, results: Iterable[ProviderResult]) -> None:
    """Append one row per result. Best-effort; sqlite errors are swallowed.

    Observability is non-critical telemetry — a write failure must never
    propagate up and fail a scan, so we catch sqlite3.Error broadly here.
    """
    now = int(time.time())
    rows = [
        (r.provider, now, r.verdict.value, r.error, int(r.latency_ms))
        for r in results
    ]
    if not rows:
        return
    try:
        with conn:
            conn.executemany(
                "INSERT INTO observability "
                "(provider, event_at, verdict, error, latency_ms) "
                "VALUES (?, ?, ?, ?, ?)",
                rows,
            )
    except sqlite3.Error:
        pass


@dataclass(frozen=True)
class ProviderHealth:
    provider: str
    samples: int
    error_count: int
    error_rate: float  # 0.0..1.0
    last_error_at: int | None
    last_429_at: int | None
    last_5xx_at: int | None
    p95_latency_ms: int | None


import re

# Providers emit 5xx errors in two stable shapes:
#   "{code} server"       (when status_code >= 500)
#   "{code}"              (other 4xx/5xx fallback)
# Match the leading 5xx code with a word boundary so "latency 5004ms" or
# "5006 results" don't trip the heuristic. The trailing "server" alt is
# kept for the verbose form.
_5XX_RE = re.compile(r"(?:^|\s)5\d{2}\b|\bserver\b", re.IGNORECASE)


def health_report(
    conn: sqlite3.Connection, *, lookback_seconds: int = 7 * 86400
) -> list[ProviderHealth]:
    """Aggregate the last N seconds of observations into per-provider stats.

    Rows are scanned once and grouped in Python — at typical volumes (a few
    thousand rows per week) this is faster than equivalent SQL group-bys and
    avoids the need for window functions.
    """
    cutoff = int(time.time()) - lookback_seconds
    cur = conn.execute(
        "SELECT provider, event_at, verdict, error, latency_ms "
        "FROM observability WHERE event_at >= ? "
        "ORDER BY provider, event_at",
        (cutoff,),
    )
    by_provider: dict[str, list[tuple]] = {}
    for row in cur.fetchall():
        by_provider.setdefault(row[0], []).append(row)

    out: list[ProviderHealth] = []
    for provider, rows in by_provider.items():
        latencies = [r[4] for r in rows]
        errors = [r for r in rows if r[2] == Verdict.ERROR.value]
        last_429 = next(
            (
                r[1]
                for r in reversed(rows)
                if r[2] == Verdict.ERROR.value and r[3] and "429" in r[3]
            ),
            None,
        )
        last_5xx = next(
            (
                r[1]
                for r in reversed(rows)
                if r[2] == Verdict.ERROR.value
                and r[3]
                and _5XX_RE.search(r[3])
            ),
            None,
        )
        last_error = errors[-1][1] if errors else None
        out.append(
            ProviderHealth(
                provider=provider,
                samples=len(rows),
                error_count=len(errors),
                error_rate=(len(errors) / len(rows)) if rows else 0.0,
                last_error_at=last_error,
                last_429_at=last_429,
                last_5xx_at=last_5xx,
                p95_latency_ms=_percentile(latencies, 95) if latencies else None,
            )
        )
    out.sort(key=lambda p: p.provider)
    return out


def _percentile(values: list[int], p: int) -> int:
    """Nearest-rank percentile. Returns 0 for empty input."""
    if not values:
        return 0
    s = sorted(values)
    k = int(len(s) * p / 100)
    k = min(k, len(s) - 1)
    return s[k]
