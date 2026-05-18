from __future__ import annotations

from rich.console import Console
from rich.markup import escape as _escape
from rich.table import Table

from iocscan.core.scan import ScanResult
from iocscan.providers.base import Verdict

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
    Verdict.MALICIOUS:  "bold red",
    Verdict.SUSPICIOUS: "yellow",
    Verdict.CLEAN:      "green",
    Verdict.UNKNOWN:    "dim",
    Verdict.ERROR:      "italic red",
}


AUTO_NARROW_THRESHOLD = 100


def render_table(
    scans: list[ScanResult],
    console: Console,
    narrow: bool = False,
    wide: bool = False,
) -> None:
    if wide:
        _render_wide(scans, console)
    elif narrow or console.width < AUTO_NARROW_THRESHOLD:
        _render_compact(scans, console)
    else:
        _render_wide(scans, console)


def _render_wide(scans: list[ScanResult], console: Console) -> None:
    t = Table(show_header=True, header_style="bold")
    t.add_column("IOC")
    t.add_column("Verdict")
    for name in PROVIDER_ORDER:
        t.add_column(PROVIDER_LABELS.get(name, name))
    for s in scans:
        verdict_text = f"[{VERDICT_STYLES[s.verdict]}]{s.verdict.value}[/] ({s.responding}/{s.total})"
        if s.whitelisted:
            verdict_text += " [dim](whitelisted)[/]"
        row = [_escape(s.ioc), verdict_text]
        by_name = {r.provider: r for r in s.provider_results}
        for name in PROVIDER_ORDER:
            r = by_name.get(name)
            if r is None:
                row.append("—")
            elif r.verdict == Verdict.ERROR:
                row.append(f"[italic red]err: {_escape(r.error) if r.error else '?'}[/]")
            else:
                style = VERDICT_STYLES[r.verdict]
                row.append(f"[{style}]{_escape(r.score) if r.score else '—'}[/]")
        t.add_row(*row)
    console.print(t)


def _render_compact(scans: list[ScanResult], console: Console) -> None:
    t = Table(show_header=True, header_style="bold")
    t.add_column("IOC")
    t.add_column("Verdict")
    t.add_column("Details")
    for s in scans:
        verdict_text = f"[{VERDICT_STYLES[s.verdict]}]{s.verdict.value}[/] ({s.responding}/{s.total})"
        if s.whitelisted:
            verdict_text += " [dim](whitelisted)[/]"
        by_name = {r.provider: r for r in s.provider_results}
        lines = []
        for name in PROVIDER_ORDER:
            label = PROVIDER_LABELS.get(name, name)
            r = by_name.get(name)
            if r is None:
                # Provider not applicable to this IOC type (e.g. IP-only on a domain)
                lines.append(f"[dim]{label}: n/a[/]")
            elif r.verdict == Verdict.ERROR:
                err = _escape(r.error) if r.error else "?"
                lines.append(f"[italic red]{label}: err ({err})[/]")
            else:
                style = VERDICT_STYLES[r.verdict]
                score = _escape(r.score) if r.score else "—"
                lines.append(f"[{style}]{label}: {score}[/]")
        t.add_row(_escape(s.ioc), verdict_text, "\n".join(lines))
    console.print(t)
