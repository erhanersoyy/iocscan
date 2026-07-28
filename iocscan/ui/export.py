"""Machine-readable export formats.

Pure stdlib — no tabulate dep. Each renderer returns a single string the
caller prints. Formats:

- jsonl     : one JSON object per line (streaming pipeline friendly)
- csv       : RFC 4180 via stdlib csv module
- markdown  : GitHub-flavored markdown table

`table` and `json` (pretty) are NOT handled here — they live in
ui/table.py and ui/json_out.py respectively. The CLI dispatcher
routes those formats to their own renderers.
"""
from __future__ import annotations

import csv as _csv
import io
import json

from iocscan.core.ioc import to_defanged
from iocscan.core.scan import ScanResult
from iocscan.ui.hunt import HUNT_FORMATS, render_hunt


EXPORT_FORMATS = ("jsonl", "csv", "markdown") + HUNT_FORMATS


def render_export(scans: list[ScanResult], fmt: str, *, defang: bool = False) -> str:
    if fmt in HUNT_FORMATS:
        # Hunt-query emitters don't defang — analysts paste the result
        # straight into a SIEM/EDR which expects the raw IOC form.
        return render_hunt(scans, fmt)
    if fmt == "jsonl":
        return _render_jsonl(scans, defang=defang)
    if fmt == "csv":
        return _render_csv(scans, defang=defang)
    if fmt == "markdown":
        return _render_markdown(scans, defang=defang)
    raise ValueError(f"unknown export format: {fmt!r}")


def _ioc(s: ScanResult, defang: bool) -> str:
    return to_defanged(s.ioc) if defang else s.ioc


def render_jsonl_line(scan: ScanResult, *, defang: bool = False) -> str:
    """Render one scan as a single JSONL record (no trailing newline).

    Shared by the buffered renderer and the CLI's streaming path so the two
    can never drift.
    """
    return json.dumps({
        "ioc": _ioc(scan, defang),
        "type": scan.ioc_type.value,
        "verdict": scan.verdict.value,
        "coverage": {"responding": scan.responding, "total": scan.total},
        "whitelisted": scan.whitelisted,
    })


def _render_jsonl(scans: list[ScanResult], *, defang: bool) -> str:
    return "\n".join(render_jsonl_line(s, defang=defang) for s in scans)


_CSV_INJECTION_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: object) -> object:
    # Defense-in-depth against spreadsheet formula injection (CVE class).
    # parse_iocs already strips most of these, but a defanged form like
    # `=cmd|...` could in principle survive a future regex relaxation.
    # Not applied to the TSV (`--quiet`) output, whose consumer is
    # grep/awk-style pipelines that would break on the leading apostrophe.
    if isinstance(value, str) and value.startswith(_CSV_INJECTION_PREFIXES):
        return "'" + value
    return value


def _render_csv(scans: list[ScanResult], *, defang: bool) -> str:
    buf = io.StringIO()
    w = _csv.writer(buf)
    w.writerow(["ioc", "type", "verdict", "responding", "total", "whitelisted"])
    for s in scans:
        w.writerow([
            _csv_safe(_ioc(s, defang)),
            s.ioc_type.value,
            s.verdict.value,
            s.responding,
            s.total,
            s.whitelisted,
        ])
    return buf.getvalue().rstrip("\r\n")


def _render_markdown(scans: list[ScanResult], *, defang: bool) -> str:
    headers = ["IOC", "type", "verdict", "coverage", "whitelisted"]
    sep = ["---"] * len(headers)
    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join(sep) + "|",
    ]
    for s in scans:
        lines.append("| " + " | ".join([
            _ioc(s, defang),
            s.ioc_type.value,
            s.verdict.value,
            f"{s.responding}/{s.total}",
            "yes" if s.whitelisted else "no",
        ]) + " |")
    return "\n".join(lines)
