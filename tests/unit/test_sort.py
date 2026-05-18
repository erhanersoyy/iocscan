import pytest

from iocscan.core.scan import ScanResult, sort_scans
from iocscan.providers.base import IOCType, Verdict


def _scan(ioc, verdict, responding=5, total=9):
    return ScanResult(ioc, IOCType.IP, verdict, [], responding, total)


def test_sort_input_preserves_order():
    a = _scan("a", Verdict.CLEAN)
    b = _scan("b", Verdict.MALICIOUS)
    c = _scan("c", Verdict.SUSPICIOUS)
    result = sort_scans([a, b, c], "input")
    assert [s.ioc for s in result] == ["a", "b", "c"]


def test_sort_verdict_puts_malicious_first():
    a = _scan("clean1", Verdict.CLEAN)
    b = _scan("susp1", Verdict.SUSPICIOUS)
    c = _scan("mal1", Verdict.MALICIOUS)
    d = _scan("unknown1", Verdict.UNKNOWN)
    result = sort_scans([a, b, c, d], "verdict")
    assert [s.ioc for s in result] == ["mal1", "susp1", "unknown1", "clean1"]


def test_sort_coverage_puts_most_responding_first():
    a = _scan("a", Verdict.CLEAN, responding=2, total=9)
    b = _scan("b", Verdict.CLEAN, responding=8, total=9)
    c = _scan("c", Verdict.CLEAN, responding=5, total=9)
    result = sort_scans([a, b, c], "coverage")
    assert [s.ioc for s in result] == ["b", "c", "a"]


def test_sort_coverage_breaks_ties_with_ratio():
    """Two scans with equal `responding` but different totals → higher ratio wins."""
    a = _scan("low_ratio", Verdict.CLEAN, responding=5, total=9)
    b = _scan("high_ratio", Verdict.CLEAN, responding=5, total=6)
    result = sort_scans([a, b], "coverage")
    assert [s.ioc for s in result] == ["high_ratio", "low_ratio"]


def test_sort_raises_on_unknown_key():
    with pytest.raises(ValueError, match="unknown sort key"):
        sort_scans([_scan("a", Verdict.CLEAN)], "weird")


def test_sort_returns_new_list_not_inplace():
    """sort_scans must not mutate the input list."""
    original = [
        _scan("a", Verdict.CLEAN),
        _scan("b", Verdict.MALICIOUS),
    ]
    snapshot = list(original)
    sort_scans(original, "verdict")
    assert [s.ioc for s in original] == [s.ioc for s in snapshot]
