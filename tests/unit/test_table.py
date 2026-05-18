from io import StringIO

from rich.console import Console

from iocscan.core.scan import ScanResult
from iocscan.providers.base import IOCType, ProviderResult, Verdict
from iocscan.ui.table import render_table

PROVIDERS = ["urlhaus", "threatfox", "feodo", "tor", "spamhaus",
             "virustotal", "abuseipdb", "otx", "greynoise"]


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


def test_table_shows_ioc_type_verdict_columns():
    out = _render([_scan(Verdict.CLEAN, urlhaus=Verdict.CLEAN, threatfox=Verdict.CLEAN,
                         feodo=Verdict.CLEAN, virustotal=Verdict.CLEAN)])
    assert "1.2.3.4" in out
    assert "ip" in out.lower()
    assert "clean" in out.lower()


def test_table_shows_coverage_in_verdict_cell():
    out = _render([_scan(Verdict.CLEAN, urlhaus=Verdict.CLEAN, threatfox=Verdict.CLEAN,
                         feodo=Verdict.CLEAN, virustotal=Verdict.CLEAN)])
    assert "(4/9)" in out


def test_narrow_mode_uses_compact_layout():
    out = _render([_scan(Verdict.CLEAN, urlhaus=Verdict.CLEAN)], narrow=True)
    assert "urlhaus" in out or "—" in out
    assert "greynoise" not in out or "|" in out


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
