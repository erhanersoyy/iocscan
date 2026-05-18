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


EXPORT_FORMATS = ("jsonl", "csv", "markdown")


def render_export(scans: list[ScanResult], fmt: str, *, defang: bool = False) -> str:
    if fmt == "jsonl":
        return _render_jsonl(scans, defang=defang)
    if fmt == "csv":
        return _render_csv(scans, defang=defang)
    if fmt == "markdown":
        return _render_markdown(scans, defang=defang)
    raise ValueError(f"unknown export format: {fmt!r}")


def _ioc(s: ScanResult, defang: bool) -> str:
    return to_defanged(s.ioc) if defang else s.ioc


def _render_jsonl(scans: list[ScanResult], *, defang: bool) -> str:
    lines = []
    for s in scans:
        lines.append(json.dumps({
            "ioc": _ioc(s, defang),
            "type": s.ioc_type.value,
            "verdict": s.verdict.value,
            "coverage": {"responding": s.responding, "total": s.total},
            "whitelisted": s.whitelisted,
        }))
    return "\n".join(lines)


def _render_csv(scans: list[ScanResult], *, defang: bool) -> str:
    buf = io.StringIO()
    w = _csv.writer(buf)
    w.writerow(["ioc", "type", "verdict", "responding", "total", "whitelisted"])
    for s in scans:
        w.writerow([
            _ioc(s, defang),
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
