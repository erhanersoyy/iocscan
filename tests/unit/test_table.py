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


def _render(scans, narrow=False):
    buf = StringIO()
    console = Console(file=buf, width=200, force_terminal=False, color_system=None)
    render_table(scans, console, narrow=narrow)
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


def test_narrow_mode_uses_compact_layout():
    out = _render([_scan(Verdict.CLEAN, urlhaus=Verdict.CLEAN)], narrow=True)
    assert "urlhaus" in out
    # Compact mode now lists every provider on its own line, in PROVIDER_ORDER
    assert "greynoise" in out


def test_narrow_mode_lists_all_providers_in_order():
    """Compact layout shows every provider, one per line, in PROVIDER_ORDER."""
    out = _render([_scan(Verdict.CLEAN, urlhaus=Verdict.CLEAN, otx=Verdict.CLEAN)], narrow=True)
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


def _render_no_color(scans, narrow=False):
    """Render to plain text with no color/markup interpretation."""
    buf = StringIO()
    console = Console(file=buf, force_terminal=False, no_color=True, width=200)
    render_table(scans, console, narrow=narrow)
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

    # Wide layout: score appears in individual provider column
    out_wide = _render_no_color([scan], narrow=False)
    # The literal bracket characters must be present
    assert "[bold red]FAKE[/]" in out_wide, (
        "Malicious score markup was rendered rather than escaped in wide layout"
    )

    # Compact layout: malicious scores appear in the Details column
    out_compact = _render_no_color([scan], narrow=True)
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

    out = _render_no_color([scan], narrow=False)
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

    out_wide = _render_no_color([scan], narrow=False)
    assert "evil[bracket].com" in out_wide, (
        "IOC bracket characters were not preserved as literals in wide layout"
    )

    out_compact = _render_no_color([scan], narrow=True)
    assert "evil[bracket].com" in out_compact, (
        "IOC bracket characters were not preserved as literals in compact layout"
    )


# --- Auto-narrow threshold + --wide override (PR for "narrow vermedim narrow geldi") ---

def _render_with_width(scans, console_width, narrow=False, wide=False):
    buf = StringIO()
    console = Console(file=buf, width=console_width, force_terminal=False, color_system=None)
    render_table(scans, console, narrow=narrow, wide=wide)
    return buf.getvalue()


def test_auto_narrow_kicks_in_below_threshold():
    """Terminals narrower than 100 columns auto-render compact."""
    scan = _scan(Verdict.CLEAN, urlhaus=Verdict.CLEAN)
    out = _render_with_width([scan], console_width=99)
    # Compact mode emits a 3-column header (IOC / Verdict / Details)
    assert "Details" in out


def test_auto_wide_above_threshold():
    """Terminals at or above 100 columns auto-render wide."""
    scan = _scan(Verdict.CLEAN, urlhaus=Verdict.CLEAN)
    # 200 cols comfortably fits 17 provider labels in full.
    out = _render_with_width([scan], console_width=200)
    # Wide mode shows every provider column header
    assert "urlhaus" in out
    assert "greynoise" in out
    # No "Details" column header in wide mode
    assert "Details" not in out


def test_wide_layout_renders_at_common_160_col_width():
    """At 160 cols (a common wide-terminal width) the wide layout must not
    crash and must keep enough columns visible — even if some are truncated.
    This catches regressions where adding a column breaks rendering, not
    where it merely shrinks header text."""
    scan = _scan(Verdict.CLEAN, urlhaus=Verdict.CLEAN)
    out = _render_with_width([scan], console_width=160)
    assert "Details" not in out
    # All 19 column joins must still render (header rule integrity).
    assert out.count("┳") >= 18


def test_wide_flag_overrides_narrow_terminal():
    """--wide forces the wide layout even when terminal is narrow."""
    scan = _scan(Verdict.CLEAN, urlhaus=Verdict.CLEAN)
    out = _render_with_width([scan], console_width=60, wide=True)
    # Wide mode has many columns and no "Details" column;
    # provider names may be Rich-truncated at this width.
    assert "Details" not in out
    # 19 columns (IOC + Verdict + 17 providers) → 18 "┳" joins in the header rule
    assert out.count("┳") >= 18


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
    render_table([scan], console, narrow=True, providers=[VirusTotal()], links=True)
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
