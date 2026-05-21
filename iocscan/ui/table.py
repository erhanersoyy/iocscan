from __future__ import annotations

from rich import box
from rich.console import Console
from rich.markup import escape as _escape
from rich.table import Table

from iocscan.core.ioc import to_defanged
from iocscan.core.scan import ScanResult
from iocscan.providers.base import Provider, Verdict
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
    "malwarebazaar", "yaraify",
    "urlscan",
    "shodan_internetdb",
    "team_cymru", "whois_age", "crtsh",
]

# Display-only short labels for column headers. Internal provider names
# (PROVIDER_ORDER, config keys, verdict weights, cache rows) stay unchanged.
PROVIDER_LABELS = {
    "virustotal": "vt",
    "abuseipdb": "abuseip",
    "malwarebazaar": "mb",
    "shodan_internetdb": "shodan",
    "team_cymru": "asn",
    "whois_age": "whois",
    "crtsh": "ct",
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

# Fallback gray when the active console has no `table.border` theme entry
# (e.g. bare Console() in tests). Picked to be visible-but-dim on both
# dark and light terminals.
_BORDER_FALLBACK = "grey70"


def _border_style(console: Console) -> str:
    """Resolve the table.border theme entry, with a literal-color fallback.

    Rich's Table accepts a style string for ``border_style`` but does not
    look it up against the console's theme — Style.parse() treats it as a
    raw color. So we resolve manually: if the console has a theme entry,
    return its color spec as a plain string; otherwise fall back to a
    dim gray that works on both light and dark backgrounds.
    """
    try:
        style = console.get_style("table.border")
    except Exception:
        return _BORDER_FALLBACK
    if style is None or style.color is None:
        return _BORDER_FALLBACK
    return str(style)


def render_table(
    scans: list[ScanResult],
    console: Console,
    narrow: bool = False,
    wide: bool = False,
    ascii_only: bool = False,
    defang: bool = False,
    providers: list[Provider] | None = None,
    links: bool = False,
) -> None:
    # Links default off: terminals add their own dotted underline to OSC 8
    # hyperlinks (terminal-rendered, not SGR-controllable), which clutters
    # the table. Opt-in via --links when click-through is needed.
    link_providers = providers if links else None
    if wide:
        _render_wide(scans, console, ascii_only=ascii_only, defang=defang, providers=link_providers)
    elif narrow or console.width < AUTO_NARROW_THRESHOLD:
        _render_compact(scans, console, ascii_only=ascii_only, defang=defang, providers=link_providers)
    else:
        _render_wide(scans, console, ascii_only=ascii_only, defang=defang, providers=link_providers)


def _display_ioc(ioc: str, *, defang: bool) -> str:
    return to_defanged(ioc) if defang else ioc


def _format_verdict_cell(s: ScanResult, *, ascii_only: bool) -> str:
    glyph = verdict_glyph(s.verdict, ascii_only=ascii_only)
    style = VERDICT_STYLES[s.verdict]
    text = f"[{style}]{glyph} {s.verdict.value}[/] ({s.responding}/{s.total})"
    if s.whitelisted:
        wl = whitelist_glyph(ascii_only=ascii_only)
        text += f" [verdict.whitelisted]{wl} 1k[/]"
    return text


def _format_provider_cell(result, *, ascii_only: bool, permalink: str | None = None) -> str:
    """Format a single provider result for the wide table.

    When ``permalink`` is supplied, wrap the cell in rich's ``[link=URL]…[/link]``
    markup so capable terminals emit an OSC 8 hyperlink. The URL is left as-is
    (provider templates use only ASCII-safe URL-encoded characters; ``]`` would
    break rich markup, so callers must keep templates clean). Terminals that
    render OSC 8 hyperlinks add their own underline that cannot be suppressed
    from the application side, so callers pass ``permalink=None`` to keep
    cells visually clean.

    If ``result.details`` is non-empty, each detail line is rendered below the
    score in a muted style — used today by Shodan to surface ports/hostnames/
    tags/vulns without polluting the short ``score`` summary.
    """
    if result.verdict == Verdict.ERROR:
        glyph = (classify_error_ascii if ascii_only else classify_error)(result.error)
        body = f"[verdict.error]{glyph} {_escape(result.error) if result.error else 'err'}[/]"
    elif not result.score or result.score == "—":
        # When details exist, drop the no-record placeholder so the cell
        # shows only the meaningful detail lines (used by shodan, whose
        # provider-side summary was removed in favor of per-category lines).
        if result.details:
            body = ""
        else:
            cell_no = CELL_NO_RECORD_ASCII if ascii_only else CELL_NO_RECORD
            body = f"[{VERDICT_STYLES[result.verdict]}]{cell_no}[/]"
    else:
        body = f"[{VERDICT_STYLES[result.verdict]}]{_escape(result.score)}[/]"
    if result.details:
        detail_lines = "\n".join(f"[muted]{_escape(line)}[/]" for line in result.details)
        body = f"{body}\n{detail_lines}" if body else detail_lines
    if permalink:
        return f"[link={permalink}]{body}[/link]"
    return body


def _render_wide(
    scans: list[ScanResult], console: Console, *, ascii_only: bool, defang: bool,
    providers: list[Provider] | None = None,
) -> None:
    t = Table(
        box=box.HEAVY_HEAD,
        show_header=True,
        header_style="bold",
        padding=(0, 1),
        show_lines=True,
        border_style=_border_style(console),
    )
    t.add_column("IOC", overflow="fold")
    t.add_column("Verdict")
    for name in PROVIDER_ORDER:
        label = PROVIDER_LABELS.get(name, name)
        justify = "right" if name in _NUMERIC_PROVIDERS else "left"
        t.add_column(label, justify=justify, overflow="fold")

    cell_na = CELL_NA_ASCII if ascii_only else CELL_NA
    provider_by_name = {p.name: p for p in (providers or [])}

    for s in scans:
        row = [_escape(_display_ioc(s.ioc, defang=defang)), _format_verdict_cell(s, ascii_only=ascii_only)]
        by_name = {r.provider: r for r in s.provider_results}
        for name in PROVIDER_ORDER:
            r = by_name.get(name)
            if r is None:
                # Provider not applicable to this IOC type.
                row.append(f"[muted]{cell_na}[/]")
            else:
                p = provider_by_name.get(name)
                link = p.permalink(s.ioc, s.ioc_type) if p else None
                row.append(_format_provider_cell(r, ascii_only=ascii_only, permalink=link))
        t.add_row(*row)
    console.print(t)


def _render_compact(
    scans: list[ScanResult], console: Console, *, ascii_only: bool, defang: bool,
    providers: list[Provider] | None = None,
) -> None:
    t = Table(
        box=box.HEAVY_HEAD,
        show_header=True,
        header_style="bold",
        padding=(0, 1),
        show_lines=True,
        border_style=_border_style(console),
    )
    t.add_column("IOC", overflow="fold")
    t.add_column("Verdict")
    t.add_column("Details")

    cell_na = CELL_NA_ASCII if ascii_only else CELL_NA
    cell_no = CELL_NO_RECORD_ASCII if ascii_only else CELL_NO_RECORD
    provider_by_name = {p.name: p for p in (providers or [])}

    for s in scans:
        verdict_text = _format_verdict_cell(s, ascii_only=ascii_only)
        by_name = {r.provider: r for r in s.provider_results}
        lines = []
        for name in PROVIDER_ORDER:
            label = PROVIDER_LABELS.get(name, name)
            r = by_name.get(name)
            if r is None:
                lines.append(f"[muted]{label}: {cell_na} n/a[/]")
                continue
            if r.verdict == Verdict.ERROR:
                glyph = (classify_error_ascii if ascii_only else classify_error)(r.error)
                err = _escape(r.error) if r.error else "?"
                line = f"[verdict.error]{label}: {glyph} {err}[/]"
            else:
                style = VERDICT_STYLES[r.verdict]
                score = _escape(r.score) if r.score and r.score != "—" else cell_no
                line = f"[{style}]{label}: {score}[/]"
            p = provider_by_name.get(name)
            link = p.permalink(s.ioc, s.ioc_type) if p else None
            if link:
                line = f"[link={link}]{line}[/link]"
            lines.append(line)
            for detail in (r.details or ()):
                lines.append(f"  [muted]{_escape(detail)}[/]")
        t.add_row(_escape(_display_ioc(s.ioc, defang=defang)), verdict_text, "\n".join(lines))
    console.print(t)
