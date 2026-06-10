from __future__ import annotations

from rich import box
from rich.console import Console
from rich.markup import escape as _escape
from rich.table import Table

from iocscan.core.ioc import to_defanged
from iocscan.core.scan import ScanResult
from iocscan.providers.base import Provider, Verdict
from iocscan.ui.glyph import (
    CELL_AUTH_FAIL,
    CELL_AUTH_FAIL_ASCII,
    CELL_NO_RECORD,
    CELL_NO_RECORD_ASCII,
    CELL_RATE_LIMITED,
    CELL_RATE_LIMITED_ASCII,
    CELL_UNKNOWN,
    CELL_UNKNOWN_ASCII,
    VERDICT_STYLES,
    classify_error,
    classify_error_ascii,
    verdict_glyph,
    verdict_label,
    whitelist_glyph,
)

PROVIDER_ORDER = [
    "urlhaus", "threatfox", "feodo", "tor", "spamhaus",
    "virustotal", "abuseipdb", "otx", "greynoise",
    "malwarebazaar", "yaraify", "circl_hashlookup",
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
    "circl_hashlookup": "circl",
    "shodan_internetdb": "shodan",
    "team_cymru": "asn",
    "whois_age": "whois",
    "crtsh": "ct",
}

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
    wide: bool = False,
    ascii_only: bool = False,
    defang: bool = False,
    providers: list[Provider] | None = None,
    links: bool = False,
) -> None:
    # Links default off: terminals add their own dotted underline to OSC 8
    # hyperlinks (terminal-rendered, not SGR-controllable), which clutters
    # the table. Opt-in via --links when click-through is needed.
    #
    # Compact is the universal default: it fits any width. --wide opts into the
    # transposed grid (providers as rows, IOCs as columns). The legacy
    # provider-per-column layout was retired — it overflowed past ~210 columns
    # once the provider count grew.
    link_providers = providers if links else None
    if wide:
        _render_transposed(scans, console, ascii_only=ascii_only, defang=defang, providers=link_providers)
    else:
        _render_compact(scans, console, ascii_only=ascii_only, defang=defang, providers=link_providers)


def _display_ioc(ioc: str, *, defang: bool) -> str:
    return to_defanged(ioc) if defang else ioc


def _format_verdict_cell(s: ScanResult, *, ascii_only: bool) -> str:
    style = VERDICT_STYLES[s.verdict]
    label = verdict_label(s.verdict, ascii_only=ascii_only)
    text = f"[{style}]{label}[/] ({s.responding}/{s.total})"
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
            style = VERDICT_STYLES[result.verdict]
            if result.verdict == Verdict.CLEAN:
                # README documents this cell as '— (no hit - clean)'.
                cell_no = CELL_NO_RECORD_ASCII if ascii_only else CELL_NO_RECORD
                body = f"[{style}]{cell_no}[/] [muted](no hit - clean)[/]"
            elif result.verdict == Verdict.UNKNOWN:
                # Provider responded but verdict is inconclusive — does not
                # count toward coverage.
                cell_unk = CELL_UNKNOWN_ASCII if ascii_only else CELL_UNKNOWN
                body = f"[{style}]{cell_unk}[/]"
            else:
                cell_no = CELL_NO_RECORD_ASCII if ascii_only else CELL_NO_RECORD
                body = f"[{style}]{cell_no}[/]"
    else:
        body = f"[{VERDICT_STYLES[result.verdict]}]{_escape(result.score)}[/]"
    if result.details:
        detail_lines = "\n".join(f"[muted]{_escape(line)}[/]" for line in result.details)
        body = f"{body}\n{detail_lines}" if body else detail_lines
    if permalink:
        return f"[link={permalink}]{body}[/link]"
    return body


def _render_transposed(
    scans: list[ScanResult], console: Console, *, ascii_only: bool, defang: bool,
    providers: list[Provider] | None = None,
) -> None:
    """Provider-per-row, IOC-per-column layout (the ``--wide`` view).

    Replaces the retired provider-per-column table, which overflowed past
    ~210 columns once the provider count grew and forced every cell to fold
    vertically. Transposing keeps each provider on its own row — 17 rows fit
    any terminal — and puts IOCs (usually only a handful) on the horizontal
    axis. The first body row carries the per-IOC verdict so the summary and the
    provider evidence read in the same column.
    """
    t = Table(
        box=box.HEAVY_HEAD,
        show_header=True,
        header_style="bold",
        padding=(0, 1),
        show_lines=True,
        border_style=_border_style(console),
    )
    t.add_column("Provider", no_wrap=True)
    for s in scans:
        t.add_column(_escape(_display_ioc(s.ioc, defang=defang)), overflow="fold")

    provider_by_name = {p.name: p for p in (providers or [])}
    by_name_per_scan = [{r.provider: r for r in s.provider_results} for s in scans]

    verdict_row = ["[table.header]Verdict[/]"]
    for s in scans:
        verdict_row.append(_format_verdict_cell(s, ascii_only=ascii_only))
    t.add_row(*verdict_row)

    for name in PROVIDER_ORDER:
        row = [f"[provider.name]{PROVIDER_LABELS.get(name, name)}[/]"]
        p = provider_by_name.get(name)
        for s, by_name in zip(scans, by_name_per_scan):
            r = by_name.get(name)
            if r is None:
                # Provider not applicable to this IOC type.
                row.append("[muted]n/a[/]")
            else:
                link = p.permalink(s.ioc, s.ioc_type) if p else None
                row.append(_format_provider_cell(r, ascii_only=ascii_only, permalink=link))
        t.add_row(*row)
    console.print(t)


# Single source of truth for every table glyph's appearance and meaning.
# Each entry: (unicode symbol, ascii symbol, theme style, word, description,
# in_legend). render_legend() emits the in_legend subset as a one-liner;
# render_glyph_reference() documents the full list. Defining a glyph once here
# keeps the two views from drifting. Order is the reference table's row order;
# the legend follows the same order, which reproduces its historical layout
# (verdict glyphs first, then cell/whitelist markers, with the word-only
# unknown / no-record / n/a entries skipped).
_GLYPH_ROWS: list[tuple[str, str, str, str, str, bool]] = [
    (verdict_glyph(Verdict.MALICIOUS), verdict_glyph(Verdict.MALICIOUS, ascii_only=True),
     "verdict.malicious", "malicious",
     "Confirmed malicious — authoritative blocklist hit or ≥ 30% weighted vote.", True),
    (verdict_glyph(Verdict.SUSPICIOUS), verdict_glyph(Verdict.SUSPICIOUS, ascii_only=True),
     "verdict.suspicious", "suspicious",
     "Flagged by some providers but below the malicious threshold.", True),
    (verdict_glyph(Verdict.CLEAN), verdict_glyph(Verdict.CLEAN, ascii_only=True),
     "verdict.clean", "clean",
     "No provider flagged the IOC.", True),
    ("unknown", "unknown", "verdict.unknown", "unknown",
     "Fewer than min-coverage providers responded — an honest ‘don't know’.", False),
    (verdict_glyph(Verdict.ERROR), verdict_glyph(Verdict.ERROR, ascii_only=True),
     "verdict.error", "error",
     "Provider call failed (network, parse, or 5xx).", True),
    (CELL_UNKNOWN, CELL_UNKNOWN_ASCII, "verdict.unknown", "inconclusive",
     "Provider responded but could not determine a verdict.", True),
    (CELL_NO_RECORD, CELL_NO_RECORD_ASCII, "muted", "no record",
     "Provider ran and saw nothing — counts as clean.", False),
    (CELL_RATE_LIMITED, CELL_RATE_LIMITED_ASCII, "verdict.suspicious", "rate-limit",
     "Provider returned HTTP 429 — retryable.", True),
    (CELL_AUTH_FAIL, CELL_AUTH_FAIL_ASCII, "verdict.error", "auth",
     "Provider auth failed (401/403) — fix the API key.", True),
    ("n/a", "n/a", "muted", "n/a",
     "Provider doesn't support this IOC type.", False),
    (whitelist_glyph(), whitelist_glyph(ascii_only=True), "verdict.whitelisted", "whitelist",
     "IOC is in the bundled/Tranco whitelist; verdict clamped to clean.", True),
]

# The legend uses "rate-limit"/"auth" wording for the cell markers; the
# reference reuses the same word column. Both read from _GLYPH_ROWS above.


def render_legend(console: Console, *, ascii_only: bool = False) -> None:
    """One-line glyph legend, printed under the table in interactive mode.

    Teaches the three-channel (glyph + color + word) encoding so a first-time
    reader can decode the table without external docs.
    """
    # Legend lists only glyph-bearing signals (in_legend). UNKNOWN, no-record,
    # and n/a render as plain words in the table (self-explanatory), so they
    # are intentionally omitted.
    parts = [
        f"[{style}]{asc if ascii_only else sym}[/] [muted]{word}[/]"
        for sym, asc, style, word, _desc, in_legend in _GLYPH_ROWS
        if in_legend
    ]
    console.print("  " + "  ".join(parts), highlight=False)


def render_glyph_reference(console: Console) -> None:
    """Full symbol reference as an ASCII-bordered table (``iocscan glyphs``).

    Lists every verdict glyph, cell-semantics marker, and the whitelist flag
    with its unicode form, ASCII fallback, and a one-line meaning — the single
    place a first-time user can decode the whole table vocabulary.
    """
    t = Table(
        box=box.ASCII,
        show_header=True,
        header_style="bold",
        padding=(0, 1),
        border_style=_border_style(console),
    )
    t.add_column("Symbol", justify="center")
    t.add_column("ASCII", justify="center")
    t.add_column("Meaning", no_wrap=True)
    t.add_column("Description")
    for sym, asc, style, meaning, desc, _in_legend in _GLYPH_ROWS:
        t.add_row(f"[{style}]{_escape(sym)}[/]", _escape(asc),
                  f"[{style}]{meaning}[/]", f"[muted]{desc}[/]")
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

    cell_no = CELL_NO_RECORD_ASCII if ascii_only else CELL_NO_RECORD
    cell_unk = CELL_UNKNOWN_ASCII if ascii_only else CELL_UNKNOWN
    provider_by_name = {p.name: p for p in (providers or [])}

    for s in scans:
        verdict_text = _format_verdict_cell(s, ascii_only=ascii_only)
        by_name = {r.provider: r for r in s.provider_results}
        lines = []
        for name in PROVIDER_ORDER:
            r = by_name.get(name)
            if r is None:
                continue  # provider doesn't support this IOC type — omit it
            if lines:
                lines.append("")  # blank line between providers for readability
            label = PROVIDER_LABELS.get(name, name)
            if r.verdict == Verdict.ERROR:
                glyph = (classify_error_ascii if ascii_only else classify_error)(r.error)
                err = _escape(r.error) if r.error else "?"
                line = f"[verdict.error]{label}: {glyph} {err}[/]"
            else:
                style = VERDICT_STYLES[r.verdict]
                if r.score and r.score != "—":
                    score = _escape(r.score)
                elif r.verdict == Verdict.UNKNOWN:
                    score = cell_unk
                else:
                    score = cell_no
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
