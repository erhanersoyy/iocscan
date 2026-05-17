from __future__ import annotations

from rich.console import Console
from rich.table import Table

from iocscan.core.scan import ScanResult
from iocscan.providers.base import Verdict

PROVIDER_ORDER = [
    "urlhaus", "threatfox", "feodo", "tor", "spamhaus",
    "virustotal", "abuseipdb", "otx", "greynoise",
]

VERDICT_STYLES = {
    Verdict.MALICIOUS:  "bold red",
    Verdict.SUSPICIOUS: "yellow",
    Verdict.CLEAN:      "green",
    Verdict.UNKNOWN:    "dim",
    Verdict.ERROR:      "italic red",
}


def render_table(scans: list[ScanResult], console: Console, narrow: bool = False) -> None:
    if narrow or console.width < 140:
        _render_compact(scans, console)
    else:
        _render_wide(scans, console)


def _render_wide(scans: list[ScanResult], console: Console) -> None:
    t = Table(show_header=True, header_style="bold")
    t.add_column("IOC")
    t.add_column("Type")
    t.add_column("Verdict")
    for name in PROVIDER_ORDER:
        t.add_column(name)
    for s in scans:
        verdict_text = f"[{VERDICT_STYLES[s.verdict]}]{s.verdict.value}[/] ({s.responding}/{s.total})"
        if s.whitelisted:
            verdict_text += " [dim](whitelisted)[/]"
        row = [s.ioc, s.ioc_type.value, verdict_text]
        by_name = {r.provider: r for r in s.provider_results}
        for name in PROVIDER_ORDER:
            r = by_name.get(name)
            if r is None:
                row.append("—")
            elif r.verdict == Verdict.ERROR:
                row.append(f"[italic red]err: {r.error or '?'}[/]")
            else:
                style = VERDICT_STYLES[r.verdict]
                row.append(f"[{style}]{r.score or '—'}[/]")
        t.add_row(*row)
    console.print(t)


def _render_compact(scans: list[ScanResult], console: Console) -> None:
    t = Table(show_header=True, header_style="bold")
    t.add_column("IOC")
    t.add_column("Type")
    t.add_column("Verdict")
    t.add_column("Details")
    for s in scans:
        verdict_text = f"[{VERDICT_STYLES[s.verdict]}]{s.verdict.value}[/] ({s.responding}/{s.total})"
        if s.whitelisted:
            verdict_text += " [dim](whitelisted)[/]"
        details = []
        for r in s.provider_results:
            if r.verdict == Verdict.MALICIOUS or r.verdict == Verdict.SUSPICIOUS:
                details.append(f"{r.provider}:{r.score}")
            elif r.verdict == Verdict.ERROR:
                details.append(f"{r.provider}:err")
        t.add_row(s.ioc, s.ioc_type.value, verdict_text, " | ".join(details) or "—")
    console.print(t)
