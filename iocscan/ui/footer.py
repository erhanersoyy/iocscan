"""Summary footer for multi-IOC scans.

Renders after the table in interactive (table + isatty + not --quiet)
mode. Suppressed under --json and --quiet so machine-readable output
stays clean.

Layout:
    ─── Summary ───────────────────────────────
      Scanned    N IOCs (Ki ip, Kd domain) in T s
      Verdicts   ● m malicious  ◐ s suspicious  ○ c clean  u unknown
      Providers  P responded · K errors
      Cache      H hits · F fresh
      Exit code  E (worst verdict: V)
    ───────────────────────────────────────────
"""
from __future__ import annotations

from rich.console import Console

from iocscan.core.scan import ScanResult
from iocscan.providers.base import IOCType, Verdict
from iocscan.ui.glyph import verdict_glyph


VERDICT_STYLES = {
    Verdict.MALICIOUS:  "verdict.malicious",
    Verdict.SUSPICIOUS: "verdict.suspicious",
    Verdict.CLEAN:      "verdict.clean",
    Verdict.UNKNOWN:    "verdict.unknown",
    Verdict.ERROR:      "verdict.error",
}


def render_summary(
    scans: list[ScanResult],
    elapsed_ms: int,
    exit_code: int,
    console: Console,
    *,
    cache_hits: int = 0,
    cache_fresh: int = 0,
    ascii_only: bool = False,
) -> None:
    if not scans:
        return

    n_ip     = sum(1 for s in scans if s.ioc_type == IOCType.IP)
    n_domain = sum(1 for s in scans if s.ioc_type == IOCType.DOMAIN)

    counts = {v: 0 for v in (Verdict.MALICIOUS, Verdict.SUSPICIOUS,
                             Verdict.CLEAN, Verdict.UNKNOWN)}
    for s in scans:
        if s.verdict in counts:
            counts[s.verdict] += 1

    providers_responded = sum(s.responding for s in scans)
    providers_errored   = sum(
        sum(1 for r in s.provider_results if r.verdict == Verdict.ERROR)
        for s in scans
    )

    worst = _worst_verdict(scans)

    rule = "─" * min(console.width or 60, 60)
    console.print(f"[table.border]{rule}[/]")
    console.print("[table.header]Summary[/]")
    console.print(f"  Scanned    {len(scans)} IOCs ({n_ip} ip, {n_domain} domain) in {elapsed_ms / 1000:.1f}s")

    parts = []
    for v in (Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.CLEAN, Verdict.UNKNOWN):
        if counts[v] > 0:
            g = verdict_glyph(v, ascii_only=ascii_only)
            gp = f"[{VERDICT_STYLES[v]}]{g}[/] " if g else ""
            parts.append(f"{gp}{counts[v]} {v.value}")
    if parts:
        console.print(f"  Verdicts   {'  '.join(parts)}")

    console.print(f"  Providers  {providers_responded} responded · {providers_errored} errored")

    if cache_hits or cache_fresh:
        console.print(f"  Cache      {cache_hits} hits · {cache_fresh} fresh")

    if worst is not None:
        console.print(f"  Exit code  {exit_code} (worst verdict: [{VERDICT_STYLES[worst]}]{worst.value}[/])")
    else:
        console.print(f"  Exit code  {exit_code}")

    console.print(rule)


def _worst_verdict(scans: list[ScanResult]) -> Verdict | None:
    """Return the most severe verdict present across scans."""
    order = [Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.UNKNOWN, Verdict.CLEAN]
    seen = {s.verdict for s in scans}
    for v in order:
        if v in seen:
            return v
    return None
