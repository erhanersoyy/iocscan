"""Tranco top-1K mini-fetcher with on-disk cache.

Tranco is a research-grade popularity ranking of internet domains aggregated
from multiple sources (Cisco Umbrella, Cloudflare Radar, Majestic Million,
Farsight, CrUX). See https://tranco-list.eu.

Usage:
    fetch_and_save()        # fetch + save to ~/.iocscan/tranco-1k.txt
    load_cache()            # return set of domains from disk (or empty)
    cache_age_days()        # how old is the cache (None if missing)
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

TRANCO_API_BASE = "https://tranco-list.eu"
TRANCO_TOP_N = 1000
CACHE_PATH = Path.home() / ".iocscan" / "tranco-1k.txt"
MAX_BODY = 50 * 1024 * 1024  # 50 MB — guard against OOM on hostile/MitM endpoints


def _latest_list_url() -> str:
    """Resolve today's or yesterday's list ID and return the download URL."""
    # Try today, fall back to yesterday, then 2-days-ago (list lags by 1 day usually)
    today = datetime.now(timezone.utc).date()
    for delta in range(0, 4):
        date_str = (today - timedelta(days=delta)).isoformat()
        meta_url = f"{TRANCO_API_BASE}/api/lists/date/{date_str}"
        meta_body = bytearray()
        with httpx.stream("GET", meta_url, timeout=15.0) as resp:
            if resp.status_code != 200:
                continue
            for chunk in resp.iter_bytes():
                meta_body.extend(chunk)
                if len(meta_body) > MAX_BODY:
                    raise ValueError(
                        f"response too large (>{MAX_BODY} bytes)"
                    )
        try:
            meta = json.loads(bytes(meta_body))
        except ValueError:
            continue
        if meta.get("available") and not meta.get("failed") and meta.get("list_id"):
            return f"{TRANCO_API_BASE}/download/{meta['list_id']}/{TRANCO_TOP_N}"
    raise ValueError("Tranco: no recent list available")


def fetch_and_save(*, path: Path = CACHE_PATH) -> int:
    """Fetch top-1K, write to cache file. Returns count of domains saved."""
    url = _latest_list_url()
    csv_body = bytearray()
    with httpx.stream("GET", url, timeout=30.0) as resp:
        if resp.status_code != 200:
            raise ValueError(f"Tranco download failed: HTTP {resp.status_code}")
        for chunk in resp.iter_bytes():
            csv_body.extend(chunk)
            if len(csv_body) > MAX_BODY:
                raise ValueError(
                    f"response too large (>{MAX_BODY} bytes)"
                )
    domains: list[str] = []
    for line in csv_body.decode("utf-8").splitlines():
        line = line.strip()
        if not line or "," not in line:
            continue
        _rank, domain = line.split(",", 1)
        domain = domain.strip().lower()
        if domain:
            domains.append(domain)
    if not domains:
        raise ValueError("Tranco: empty response")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text("\n".join(domains) + "\n")
    os.replace(tmp, path)
    return len(domains)


def load_cache(path: Path = CACHE_PATH) -> set[str]:
    """Read cache file. Returns empty set if missing or unreadable."""
    if not path.exists():
        return set()
    try:
        return {line.strip().lower() for line in path.read_text().splitlines() if line.strip()}
    except OSError:
        return set()


def cache_age_days(path: Path = CACHE_PATH) -> int | None:
    """How many full days old is the cache file. None if missing."""
    if not path.exists():
        return None
    age_seconds = time.time() - path.stat().st_mtime
    return int(age_seconds // 86400)
