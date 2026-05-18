from __future__ import annotations

from rich import box
from rich.console import Console
from rich.markup import escape as _escape
from rich.table import Table

from iocscan.core.scan import ScanResult
from iocscan.providers.base import Verdict
from iocscan.ui.glyph import (
    CELL_NA,
    CELL_NA_ASCII,
    CELL_NO_RECORD,
    CELL_NO_RECORD_ASCII,
    classify_error,
    classify_error_ascii,
    verdict_glyph,
    whitelist_glyph,
)

PROVIDER_ORDER = [
    "urlhaus", "threatfox", "feodo", "tor", "spamhaus",
    "virustotal", "abuseipdb", "otx", "greynoise",
]

# Display-only short labels for column headers. Internal provider names
# (PROVIDER_ORDER, config keys, verdict weights, cache rows) stay unchanged.
PROVIDER_LABELS = {
    "virustotal": "vt",
    "abuseipdb": "abuseip",
}

VERDICT_STYLES = {
    Verdict.MALICIOUS:  "verdict.malicious",
    Verdict.SUSPICIOUS: "verdict.suspicious",
    Verdict.CLEAN:      "verdict.clean",
    Verdict.UNKNOWN:    "verdict.unknown",
    Verdict.ERROR:      "verdict.error",
}

# Provider score columns whose body is numeric ratio / percent — render
# right-aligned so visual scan groups the digits.
_NUMERIC_PROVIDERS = {"virustotal", "abuseipdb", "otx"}


AUTO_NARROW_THRESHOLD = 100


def render_table(
    scans: list[ScanResult],
    console: Console,
    narrow: bool = False,
    wide: bool = False,
    ascii_only: bool = False,
) -> None:
    if wide:
        _render_wide(scans, console, ascii_only=ascii_only)
    elif narrow or console.width < AUTO_NARROW_THRESHOLD:
        _render_compact(scans, console, ascii_only=ascii_only)
    else:
        _render_wide(scans, console, ascii_only=ascii_only)


def _format_verdict_cell(s: ScanResult, *, ascii_only: bool) -> str:
    glyph = verdict_glyph(s.verdict, ascii_only=ascii_only)
    style = VERDICT_STYLES[s.verdict]
    text = f"[{style}]{glyph} {s.verdict.value}[/] ({s.responding}/{s.total})"
    if s.whitelisted:
        wl = whitelist_glyph(ascii_only=ascii_only)
        text += f" [verdict.whitelisted]{wl} whitelisted[/]"
    return text


def _format_provider_cell(result, *, ascii_only: bool) -> str:
    """Format a single provider result for the wide table."""
    if result.verdict == Verdict.ERROR:
        glyph = (classify_error_ascii if ascii_only else classify_error)(result.error)
        return f"[verdict.error]{glyph} {_escape(result.error) if result.error else 'err'}[/]"
    if not result.score or result.score == "—":
        # Provider ran but produced no score (blocklist miss, 0 detections).
        cell_no = CELL_NO_RECORD_ASCII if ascii_only else CELL_NO_RECORD
        return f"[{VERDICT_STYLES[result.verdict]}]{cell_no}[/]"
    return f"[{VERDICT_STYLES[result.verdict]}]{_escape(result.score)}[/]"


def _render_wide(scans: list[ScanResult], console: Console, *, ascii_only: bool) -> None:
    t = Table(
        box=box.HEAVY_HEAD,
        show_header=True,
        header_style="bold",
        padding=(0, 1),
    )
    t.add_column("IOC", overflow="fold")
    t.add_column("Verdict")
    for name in PROVIDER_ORDER:
        label = PROVIDER_LABELS.get(name, name)
        justify = "right" if name in _NUMERIC_PROVIDERS else "left"
        t.add_column(label, justify=justify, overflow="fold")

    cell_na = CELL_NA_ASCII if ascii_only else CELL_NA

    for s in scans:
        row = [_escape(s.ioc), _format_verdict_cell(s, ascii_only=ascii_only)]
        by_name = {r.provider: r for r in s.provider_results}
        for name in PROVIDER_ORDER:
            r = by_name.get(name)
            if r is None:
                # Provider not applicable to this IOC type.
                row.append(f"[muted]{cell_na}[/]")
            else:
                row.append(_format_provider_cell(r, ascii_only=ascii_only))
        t.add_row(*row)
    console.print(t)


def _render_compact(scans: list[ScanResult], console: Console, *, ascii_only: bool) -> None:
    t = Table(
        box=box.HEAVY_HEAD,
        show_header=True,
        header_style="bold",
        padding=(0, 1),
    )
    t.add_column("IOC", overflow="fold")
    t.add_column("Verdict")
    t.add_column("Details")

    cell_na = CELL_NA_ASCII if ascii_only else CELL_NA
    cell_no = CELL_NO_RECORD_ASCII if ascii_only else CELL_NO_RECORD

    for s in scans:
        verdict_text = _format_verdict_cell(s, ascii_only=ascii_only)
        by_name = {r.provider: r for r in s.provider_results}
        lines = []
        for name in PROVIDER_ORDER:
            label = PROVIDER_LABELS.get(name, name)
            r = by_name.get(name)
            if r is None:
                lines.append(f"[muted]{label}: {cell_na} n/a[/]")
            elif r.verdict == Verdict.ERROR:
                glyph = (classify_error_ascii if ascii_only else classify_error)(r.error)
                err = _escape(r.error) if r.error else "?"
                lines.append(f"[verdict.error]{label}: {glyph} {err}[/]")
            else:
                style = VERDICT_STYLES[r.verdict]
                score = _escape(r.score) if r.score and r.score != "—" else cell_no
                lines.append(f"[{style}]{label}: {score}[/]")
        t.add_row(_escape(s.ioc), verdict_text, "\n".join(lines))
    console.print(t)
