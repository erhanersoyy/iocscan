from io import StringIO

from rich.console import Console

from iocscan.core.scan import ScanResult
from iocscan.providers.base import IOCType, ProviderResult, Verdict
from iocscan.ui.footer import render_summary


def _result(name, verdict):
    return ProviderResult(name, verdict, "x", None, None, 10)


def _scan(ioc, verdict, ioc_type=IOCType.IP, providers=None):
    providers = providers or [_result("vt", Verdict.CLEAN), _result("otx", Verdict.CLEAN)]
    responding = sum(1 for r in providers if r.verdict not in (Verdict.ERROR, Verdict.UNKNOWN))
    return ScanResult(ioc, ioc_type, verdict, providers, responding, len(providers))


def _render(scans, **kw):
    buf = StringIO()
    console = Console(file=buf, width=120, force_terminal=False, color_system=None)
    render_summary(scans, **{"elapsed_ms": 4300, "exit_code": 0, "console": console, **kw})
    return buf.getvalue()


def test_footer_includes_summary_header():
    out = _render([_scan("1.1.1.1", Verdict.CLEAN)])
    assert "Summary" in out


def test_footer_shows_ioc_type_breakdown():
    out = _render([
        _scan("1.1.1.1", Verdict.CLEAN, ioc_type=IOCType.IP),
        _scan("evil.com", Verdict.MALICIOUS, ioc_type=IOCType.DOMAIN),
    ])
    assert "2 IOCs" in out
    assert "1 ip" in out
    assert "1 domain" in out


def test_footer_shows_elapsed_seconds():
    out = _render([_scan("1.1.1.1", Verdict.CLEAN)], elapsed_ms=4300)
    assert "4.3s" in out


def test_footer_counts_each_verdict_kind():
    out = _render([
        _scan("a", Verdict.MALICIOUS),
        _scan("b", Verdict.MALICIOUS),
        _scan("c", Verdict.CLEAN),
        _scan("d", Verdict.UNKNOWN),
    ])
    # Verdict glyph + count appear
    assert "2 malicious" in out
    assert "1 clean" in out
    assert "1 unknown" in out


def test_footer_shows_exit_code_with_worst_verdict():
    out = _render([_scan("a", Verdict.MALICIOUS)], exit_code=1)
    assert "Exit code  1" in out
    assert "malicious" in out


def test_footer_shows_cache_counts_when_nonzero():
    out = _render([_scan("a", Verdict.CLEAN)], cache_hits=3, cache_fresh=5)
    assert "3 hits" in out
    assert "5 fresh" in out


def test_footer_hides_cache_line_when_zero():
    out = _render([_scan("a", Verdict.CLEAN)], cache_hits=0, cache_fresh=0)
    assert "Cache" not in out


def test_footer_skips_when_no_scans():
    out = _render([])
    assert out == ""


def test_footer_counts_provider_errors():
    pr = [_result("vt", Verdict.ERROR), _result("otx", Verdict.CLEAN)]
    out = _render([_scan("a", Verdict.CLEAN, providers=pr)])
    assert "1 errored" in out
