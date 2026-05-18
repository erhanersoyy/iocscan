from __future__ import annotations

import json
from datetime import datetime, timezone

from iocscan import __version__
from iocscan.core.ioc import to_defanged
from iocscan.core.scan import ScanResult


def render_json(scans: list[ScanResult], min_coverage: int, defang: bool = False) -> str:
    payload = {
        "scan": {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
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
                        "raw": r.raw,
                    }
                    for r in s.provider_results
                },
            }
            for s in scans
        ],
    }
    return json.dumps(payload, indent=2)
