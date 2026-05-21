from __future__ import annotations

from io import StringIO

from rich.console import Console

from iocscan.core.scan import ScanResult
from iocscan.providers.base import IOCType, ProviderResult, Verdict
from iocscan.ui.table import render_table


def _capture_wide(scan: ScanResult) -> str:
    buf = StringIO()
    console = Console(file=buf, width=200, force_terminal=False, color_system=None)
    render_table([scan], console, wide=True)
    return buf.getvalue()


def _make_scan_with_shodan_details() -> ScanResult:
    shodan = ProviderResult(
        "shodan_internetdb", Verdict.CLEAN, "2 ports",
        None, None, 50,
        details=("ports: 22, 80", "hostnames: a.example.com", "tags: cdn"),
    )
    return ScanResult(
        ioc="1.2.3.4", ioc_type=IOCType.IP, verdict=Verdict.CLEAN,
        provider_results=[shodan], responding=1, total=1,
    )


def test_wide_cell_contains_score_and_detail_lines():
    out = _capture_wide(_make_scan_with_shodan_details())
    assert "2 ports" in out
    assert "ports: 22, 80" in out
    assert "hostnames: a.example.com" in out
    assert "tags: cdn" in out


def test_wide_cell_omits_details_when_empty():
    r = ProviderResult("virustotal", Verdict.CLEAN, "0/90", None, None, 10, details=())
    scan = ScanResult(
        ioc="1.2.3.4", ioc_type=IOCType.IP, verdict=Verdict.CLEAN,
        provider_results=[r], responding=1, total=1,
    )
    out = _capture_wide(scan)
    assert "0/90" in out
    assert "ports:" not in out
