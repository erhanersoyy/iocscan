from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path

from iocscan.providers.base import ProviderResult, Verdict

SCHEMA = """
CREATE TABLE IF NOT EXISTS results (
  ioc        TEXT NOT NULL,
  provider   TEXT NOT NULL,
  fetched_at INTEGER NOT NULL,
  verdict    TEXT NOT NULL,
  score      TEXT NOT NULL,
  error      TEXT,
  raw_json   TEXT,
  latency_ms INTEGER NOT NULL,
  PRIMARY KEY (ioc, provider)
);
"""


class Cache:
    def __init__(self, path: Path, ttl_seconds: int):
        self.path = Path(path)
        self.ttl = int(ttl_seconds)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass  # best-effort; e.g., if parent is not owned by us
        if self.path.is_symlink():
            raise ValueError(f"refusing to open symlink: {self.path}")
        self._conn = sqlite3.connect(self.path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=3000")
        self._conn.executescript(SCHEMA)
        self._conn.commit()
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def get(self, ioc: str) -> dict[str, ProviderResult]:
        cutoff = int(time.time()) - self.ttl
        rows = self._conn.execute(
            "SELECT provider, verdict, score, error, raw_json, latency_ms "
            "FROM results WHERE ioc = ? AND fetched_at > ?",
            (ioc, cutoff),
        ).fetchall()
        out: dict[str, ProviderResult] = {}
        for provider, verdict, score, error, raw_json, latency in rows:
            out[provider] = ProviderResult(
                provider=provider,
                verdict=Verdict(verdict),
                score=score,
                raw=json.loads(raw_json) if raw_json else None,
                error=error,
                latency_ms=latency,
            )
        return out

    def put(self, ioc: str, results: list[ProviderResult]) -> None:
        now = int(time.time())
        with self._conn:
            self._conn.executemany(
                "INSERT OR REPLACE INTO results "
                "(ioc, provider, fetched_at, verdict, score, error, raw_json, latency_ms) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (ioc, r.provider, now, r.verdict.value, r.score, r.error,
                     json.dumps(r.raw) if r.raw is not None else None, r.latency_ms)
                    for r in results
                ],
            )

    def clear(self) -> None:
        with self._conn:
            self._conn.execute("DELETE FROM results")

    def stats(self) -> dict:
        rows = self._conn.execute("SELECT COUNT(*), COUNT(DISTINCT ioc) FROM results").fetchone()
        size_bytes = self.path.stat().st_size if self.path.exists() else 0
        oldest_row = self._conn.execute("SELECT MIN(fetched_at) FROM results").fetchone()
        oldest_epoch = oldest_row[0] if oldest_row and oldest_row[0] is not None else None
        return {
            "rows": rows[0],
            "iocs": rows[1],
            "path": str(self.path),
            "size_bytes": size_bytes,
            "oldest_epoch": oldest_epoch,
        }

    def close(self) -> None:
        self._conn.close()
