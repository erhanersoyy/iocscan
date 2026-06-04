from io import StringIO

from rich.console import Console

from iocscan.core.scan import ScanResult
from iocscan.providers.base import IOCType, ProviderResult, Verdict
from iocscan.ui.table import render_table

PROVIDERS = ["urlhaus", "threatfox", "feodo", "tor", "spamhaus",
             "virustotal", "abuseipdb", "otx", "greynoise",
             "malwarebazaar", "yaraify", "urlscan", "shodan_internetdb",
             "team_cymru", "whois_age", "crtsh"]


def _scan(verdict, **per_provider):
    results = [
        ProviderResult(name, per_provider.get(name, Verdict.UNKNOWN),
                       "x" if per_provider.get(name) else "—",
                       None, None, 10)
        for name in PROVIDERS
    ]
    responding = sum(1 for r in results if r.verdict not in (Verdict.ERROR, Verdict.UNKNOWN))
    return ScanResult("1.2.3.4", IOCType.IP, verdict, results, responding, len(PROVIDERS))


def _render(scans):
    buf = StringIO()
    console = Console(file=buf, width=200, force_terminal=False, color_system=None)
    render_table(scans, console)
    return buf.getvalue()


def test_table_shows_ioc_and_verdict_columns():
    out = _render([_scan(Verdict.CLEAN, urlhaus=Verdict.CLEAN, threatfox=Verdict.CLEAN,
                         feodo=Verdict.CLEAN, virustotal=Verdict.CLEAN)])
    assert "1.2.3.4" in out
    assert "clean" in out.lower()


def test_table_renames_virustotal_and_abuseipdb_headers():
    """Provider columns use short display labels (vt, abuseip) instead of full names."""
    out = _render([_scan(Verdict.CLEAN, virustotal=Verdict.CLEAN, abuseipdb=Verdict.CLEAN)])
    # Header labels switched
    assert " vt " in out or "vt\n" in out or out.count("vt") >= 1
    assert "abuseip" in out
    # Original long names must not appear as column headers in wide mode
    assert "virustotal" not in out
    # "abuseipdb" should not appear (abuseip is the only acceptable form)
    assert "abuseipdb" not in out


def test_table_shows_coverage_in_verdict_cell():
    out = _render([_scan(Verdict.CLEAN, urlhaus=Verdict.CLEAN, threatfox=Verdict.CLEAN,
                         feodo=Verdict.CLEAN, virustotal=Verdict.CLEAN)])
    assert "(4/16)" in out


def test_table_whitelist_flag_renders_as_1k():
    """Whitelisted rows show the '⚑ 1k' suffix in the verdict cell.

    '1k' is a deliberate shorthand: the whitelist combines a small bundle
    of critical-infra domains with the Tranco top-1K, and users wanted a
    compact tag that does not steal column width.
    """
    scan = ScanResult(
        "cloudflare.com", IOCType.DOMAIN, Verdict.CLEAN, [], 0, 16, whitelisted=True
    )
    out = _render([scan])
    assert "1k" in out
    assert "whitelisted" not in out
    assert "⚑" in out


def test_compact_default_uses_compact_layout():
    out = _render([_scan(Verdict.CLEAN, urlhaus=Verdict.CLEAN)])
    assert "urlhaus" in out
    # Compact mode now lists every provider on its own line, in PROVIDER_ORDER
    assert "greynoise" in out


def test_compact_default_lists_all_providers_in_order():
    """Compact layout shows every provider, one per line, in PROVIDER_ORDER."""
    out = _render([_scan(Verdict.CLEAN, urlhaus=Verdict.CLEAN, otx=Verdict.CLEAN)])
    # All 16 provider labels (using display labels) must appear, each as a
    # "<label>: " row prefix. Anchoring on ": " avoids accidental substring
    # matches like "ct" inside "Verdict".
    expected_labels = ["urlhaus", "threatfox", "feodo", "tor", "spamhaus",
                       "vt", "abuseip", "otx", "greynoise",
                       "mb", "yaraify", "urlscan", "shodan",
                       "asn", "whois", "ct"]
    positions = [out.find(f"{label}: ") for label in expected_labels]
    assert all(p >= 0 for p in positions), f"Missing labels: {[l for l, p in zip(expected_labels, positions) if p < 0]}"
    # Positions must be strictly increasing (i.e. labels appear in PROVIDER_ORDER)
    assert positions == sorted(positions), "Provider labels are not in PROVIDER_ORDER"


def test_compact_omits_providers_that_dont_support_the_ioc():
    """Default table drops providers with no result for this IOC (no 'n/a' rows)."""
    results = [
        ProviderResult("virustotal", Verdict.MALICIOUS, "10/70", None, None, 10),
        ProviderResult("malwarebazaar", Verdict.CLEAN, "—", None, None, 10),
    ]
    scan = ScanResult("44d88612fea8a8f36de82e1278abb02f", IOCType.HASH_MD5,
                      Verdict.MALICIOUS, results, 1, 2)
    out = _render([scan])
    assert "vt: " in out            # supported provider is shown
    assert "mb: " in out
    assert "n/a" not in out         # no not-applicable rows
    assert "feodo" not in out       # unsupported providers omitted entirely
    assert "spamhaus" not in out


def _capture(fn):
    from rich.console import Console
    buf = StringIO()
    fn(Console(file=buf, width=200, force_terminal=False, color_system=None))
    return buf.getvalue()


def test_render_legend_lists_glyph_entries_only():
    from iocscan.ui.table import render_legend
    out = _capture(render_legend)
    for word in ("malicious", "suspicious", "clean", "error",
                 "inconclusive", "rate-limit", "auth", "whitelist"):
        assert word in out, word
    # Word-only signals (glyph-less) are intentionally absent from the legend.
    assert "unknown" not in out
    assert "n/a" not in out


def test_render_glyph_reference_documents_every_symbol():
    from iocscan.ui.table import render_glyph_reference
    out = _capture(render_glyph_reference)
    for word in ("malicious", "suspicious", "clean", "unknown", "error",
                 "inconclusive", "no record", "rate-limit", "auth", "n/a",
                 "whitelist"):
        assert word in out, word


# ---------------------------------------------------------------------------
# Security: Rich markup injection via untrusted provider-controlled strings
# ---------------------------------------------------------------------------

def _make_scan_with_provider_result(ioc: str, provider_result: ProviderResult) -> ScanResult:
    """Build a ScanResult with a single custom ProviderResult."""
    return ScanResult(
        ioc=ioc,
        ioc_type=IOCType.IP,
        verdict=Verdict.MALICIOUS,
        provider_results=[provider_result],
        responding=1,
        total=1,
    )


def _render_no_color(scans, wide=False):
    """Render to plain text with no color/markup interpretation."""
    buf = StringIO()
    console = Console(file=buf, force_terminal=False, no_color=True, width=200)
    render_table(scans, console, wide=wide)
    return buf.getvalue()


def test_table_escapes_malicious_score():
    """r.score containing Rich markup must appear as literal text, not be rendered."""
    malicious_score = "[bold red]FAKE[/]"
    pr = ProviderResult(
        provider="urlhaus",
        verdict=Verdict.MALICIOUS,
        score=malicious_score,
        raw=None,
        error=None,
        latency_ms=10,
    )
    scan = _make_scan_with_provider_result("1.2.3.4", pr)

    # Wide (transposed) layout: score appears in the per-provider row
    out_wide = _render_no_color([scan], wide=True)
    # The literal bracket characters must be present
    assert "[bold red]FAKE[/]" in out_wide, (
        "Malicious score markup was rendered rather than escaped in wide layout"
    )

    # Compact layout (default): malicious scores appear in the Details column
    out_compact = _render_no_color([scan])
    assert "[bold red]FAKE[/]" in out_compact, (
        "Malicious score markup was rendered rather than escaped in compact layout"
    )


def test_table_escapes_malicious_error():
    """r.error containing Rich link tags must appear as literal text, not be rendered."""
    malicious_error = "[link=file:///etc/passwd]click[/]"
    pr = ProviderResult(
        provider="urlhaus",
        verdict=Verdict.ERROR,
        score="",
        raw=None,
        error=malicious_error,
        latency_ms=10,
    )
    scan = _make_scan_with_provider_result("1.2.3.4", pr)

    out = _render_no_color([scan], wide=True)
    # The literal markup text must appear verbatim in output
    assert "[link=file:///etc/passwd]click[/]" in out, (
        "Malicious error markup was rendered rather than escaped"
    )


def test_table_escapes_ioc_brackets():
    """s.ioc containing bracket characters must appear as literal text."""
    malicious_ioc = "evil[bracket].com"
    pr = ProviderResult(
        provider="urlhaus",
        verdict=Verdict.CLEAN,
        score="clean",
        raw=None,
        error=None,
        latency_ms=10,
    )
    scan = ScanResult(
        ioc=malicious_ioc,
        ioc_type=IOCType.DOMAIN,
        verdict=Verdict.CLEAN,
        provider_results=[pr],
        responding=1,
        total=1,
    )

    out_wide = _render_no_color([scan], wide=True)
    assert "evil[bracket].com" in out_wide, (
        "IOC bracket characters were not preserved as literals in wide layout"
    )

    out_compact = _render_no_color([scan])
    assert "evil[bracket].com" in out_compact, (
        "IOC bracket characters were not preserved as literals in compact layout"
    )


# --- Compact-by-default + --wide override (layout policy) ---

def _render_with_width(scans, console_width, wide=False):
    buf = StringIO()
    console = Console(file=buf, width=console_width, force_terminal=False, color_system=None)
    render_table(scans, console, wide=wide)
    return buf.getvalue()


def test_default_renders_compact_at_wide_terminal():
    """The legacy auto-wide selection was retired: compact is the universal
    default regardless of width (the transposed grid is opt-in via --wide)."""
    scan = _scan(Verdict.CLEAN, urlhaus=Verdict.CLEAN)
    out = _render_with_width([scan], console_width=200)
    # Compact emits the 3-column header (IOC / Verdict / Details).
    assert "Details" in out
    assert "urlhaus" in out
    assert "greynoise" in out


def test_wide_flag_renders_transposed_grid():
    """--wide renders the transposed layout: a 'Provider' header column plus
    one column per IOC, a leading Verdict row, and every provider as a row."""
    scan = _scan(Verdict.CLEAN, urlhaus=Verdict.CLEAN)
    out = _render_with_width([scan], console_width=200, wide=True)
    assert "Provider" in out      # header of the transposed first column
    assert "Verdict" in out       # leading per-IOC verdict row
    assert "1.2.3.4" in out       # IOC is now a column header
    assert "Details" not in out   # not the compact layout
    assert "urlhaus" in out
    assert "greynoise" in out


def test_wide_flag_works_at_narrow_terminal():
    """--wide forces the transposed grid even when the terminal is narrow;
    with only one IOC there are just two columns, so it fits comfortably."""
    scan = _scan(Verdict.CLEAN, urlhaus=Verdict.CLEAN)
    out = _render_with_width([scan], console_width=60, wide=True)
    assert "Provider" in out
    assert "Details" not in out


# ---------------------------------------------------------------------------
# Deeplinks: provider cells wrap in OSC 8 hyperlinks when providers passed
# ---------------------------------------------------------------------------

def _make_scan(ioc, ioc_type, verdict, results):
    """Tiny helper to build a ScanResult from a list of ProviderResults."""
    responding = sum(1 for r in results if r.verdict not in (Verdict.ERROR, Verdict.UNKNOWN))
    return ScanResult(ioc, ioc_type, verdict, results, responding, len(results))


def test_render_table_wraps_cells_in_link_markup_when_opted_in():
    """Wide layout emits OSC 8 hyperlinks only when ``links=True`` is set."""
    from iocscan.providers.virustotal import VirusTotal

    buf = StringIO()
    console = Console(file=buf, force_terminal=True, width=200, legacy_windows=False)
    scan = _make_scan("1.2.3.4", IOCType.IP, Verdict.MALICIOUS, [
        ProviderResult("virustotal", Verdict.MALICIOUS, "12/70", None, None, 100),
    ])
    render_table([scan], console, providers=[VirusTotal()], links=True)
    out = buf.getvalue()
    # OSC 8 hyperlink: \x1b]8;; ... \x1b\\
    assert "\x1b]8;" in out, "expected OSC 8 hyperlink escape in output"
    assert "virustotal.com/gui/ip-address/1.2.3.4" in out


def test_render_table_compact_wraps_in_link_markup_when_opted_in():
    """Compact layout also emits OSC 8 hyperlinks only when ``links=True``."""
    from iocscan.providers.virustotal import VirusTotal

    buf = StringIO()
    console = Console(file=buf, force_terminal=True, width=80, legacy_windows=False)
    scan = _make_scan("1.2.3.4", IOCType.IP, Verdict.MALICIOUS, [
        ProviderResult("virustotal", Verdict.MALICIOUS, "12/70", None, None, 100),
    ])
    render_table([scan], console, providers=[VirusTotal()], links=True)
    out = buf.getvalue()
    assert "\x1b]8;" in out
    assert "virustotal.com/gui/ip-address/1.2.3.4" in out


def test_render_table_omits_link_markup_by_default():
    """Default behavior: even when providers are supplied, no OSC 8 escapes.

    Terminals render OSC 8 with a dotted underline that the application
    cannot suppress, so links are off by default to keep the table clean.
    Opt-in with ``links=True`` (or the ``--cell-links`` CLI flag).
    """
    from iocscan.providers.virustotal import VirusTotal

    buf = StringIO()
    console = Console(file=buf, force_terminal=True, width=200, legacy_windows=False)
    scan = _make_scan("1.2.3.4", IOCType.IP, Verdict.MALICIOUS, [
        ProviderResult("virustotal", Verdict.MALICIOUS, "12/70", None, None, 100),
    ])
    render_table([scan], console, providers=[VirusTotal()])
    out = buf.getvalue()
    assert "\x1b]8;" not in out


def test_render_table_no_link_when_providers_not_supplied():
    """Backwards-compat: omitting providers means no OSC 8 escape codes."""
    buf = StringIO()
    console = Console(file=buf, force_terminal=True, width=200, legacy_windows=False)
    scan = _make_scan("1.2.3.4", IOCType.IP, Verdict.MALICIOUS, [
        ProviderResult("virustotal", Verdict.MALICIOUS, "12/70", None, None, 100),
    ])
    render_table([scan], console)
    out = buf.getvalue()
    assert "\x1b]8;" not in out
