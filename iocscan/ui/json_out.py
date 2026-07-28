from __future__ import annotations

import json
from datetime import datetime, timezone

from iocscan import __version__
from iocscan.core.ioc import to_defanged
from iocscan.core.scan import ScanResult
from iocscan.providers.base import Provider


def render_json(
    scans: list[ScanResult],
    min_coverage: int,
    defang: bool = False,
    providers: list[Provider] | None = None,
) -> str:
    by_name = {p.name: p for p in (providers or [])}
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    payload = {
        "scan": {
            "timestamp": timestamp,
            "tool_version": __version__,
            "min_coverage": min_coverage,
        },
        "results": [
            {
                "ioc": to_defanged(s.ioc) if defang else s.ioc,
                "type": s.ioc_type.value,
                "verdict": s.verdict.value,
                "whitelisted": s.whitelisted,
                "coverage": {"responding": s.responding, "total": s.total},
                "providers": {
                    r.provider: {
                        "verdict": r.verdict.value,
                        "score": r.score,
                        "error": r.error,
                        "latency_ms": r.latency_ms,
                        "details": list(r.details),
                        # Rows merged from the cache can be up to
                        # cache_ttl_hours old; without this the payload's
                        # single scan timestamp would imply every row was
                        # fetched just now.
                        "cached": r.fetched_at is not None,
                        "fetched_at": (
                            datetime.fromtimestamp(r.fetched_at, timezone.utc)
                            .isoformat().replace("+00:00", "Z")
                            if r.fetched_at is not None else timestamp
                        ),
                        "raw": r.raw,
                        "permalink": (
                            by_name[r.provider].permalink(s.ioc, s.ioc_type)
                            if r.provider in by_name else None
                        ),
                    }
                    for r in s.provider_results
                },
            }
            for s in scans
        ],
    }
    return json.dumps(payload, indent=2)
