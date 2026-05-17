from iocscan.core.verdict import aggregate, MIN_COVERAGE_DEFAULT
from iocscan.providers.base import ProviderResult, Verdict


def _r(provider: str, verdict: Verdict) -> ProviderResult:
    return ProviderResult(provider, verdict, "", None, None, 0)


def test_all_clean_meets_coverage_returns_clean():
    results = [_r(f"p{i}", Verdict.CLEAN) for i in range(5)]
    assert aggregate(results) == Verdict.CLEAN


def test_majority_malicious_returns_malicious():
    results = [
        _r("a", Verdict.MALICIOUS), _r("b", Verdict.MALICIOUS),
        _r("c", Verdict.MALICIOUS), _r("d", Verdict.CLEAN),
        _r("e", Verdict.CLEAN),
    ]
    assert aggregate(results) == Verdict.MALICIOUS


def test_mal_plus_suspect_majority_returns_suspicious():
    results = [
        _r("a", Verdict.MALICIOUS), _r("b", Verdict.SUSPICIOUS),
        _r("c", Verdict.SUSPICIOUS), _r("d", Verdict.CLEAN),
        _r("e", Verdict.CLEAN),
    ]
    assert aggregate(results) == Verdict.SUSPICIOUS


def test_below_min_coverage_returns_unknown():
    results = [_r("a", Verdict.CLEAN), _r("b", Verdict.CLEAN)]
    assert aggregate(results) == Verdict.UNKNOWN


def test_errors_and_unknowns_do_not_count_toward_coverage():
    results = [
        _r("a", Verdict.ERROR), _r("b", Verdict.UNKNOWN),
        _r("c", Verdict.CLEAN), _r("d", Verdict.CLEAN),
    ]
    assert aggregate(results) == Verdict.UNKNOWN


def test_exact_tie_falls_back_to_clean():
    results = [
        _r("a", Verdict.MALICIOUS), _r("b", Verdict.MALICIOUS),
        _r("c", Verdict.CLEAN), _r("d", Verdict.CLEAN),
        _r("e", Verdict.CLEAN),
    ]
    assert aggregate(results) == Verdict.CLEAN


def test_min_coverage_override():
    results = [_r("a", Verdict.CLEAN), _r("b", Verdict.CLEAN)]
    assert aggregate(results, min_coverage=2) == Verdict.CLEAN


def test_default_min_coverage_is_three():
    assert MIN_COVERAGE_DEFAULT == 3
