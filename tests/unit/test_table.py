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
