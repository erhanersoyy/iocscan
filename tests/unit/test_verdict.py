from iocscan.core.verdict import aggregate, coverage, MIN_COVERAGE_DEFAULT
from iocscan.providers.base import ProviderResult, Verdict


def _r(provider: str, verdict: Verdict) -> ProviderResult:
    return ProviderResult(provider, verdict, "", None, None, 0)


def test_all_clean_meets_coverage_returns_clean():
    results = [_r(f"p{i}", Verdict.CLEAN) for i in range(5)]
    assert aggregate(results) == Verdict.CLEAN


def test_30pct_malicious_threshold_returns_malicious():
    """3 of 5 malicious = 60% >= 30% -> MALICIOUS."""
    results = [
        _r("a", Verdict.MALICIOUS), _r("b", Verdict.MALICIOUS),
        _r("c", Verdict.MALICIOUS), _r("d", Verdict.CLEAN),
        _r("e", Verdict.CLEAN),
    ]
    assert aggregate(results) == Verdict.MALICIOUS


def test_mal_plus_suspect_majority_returns_suspicious():
    """1 mal + 2 susp of 5 = combined 60% >= 30% suspicious threshold."""
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


def test_two_of_five_now_passes_30pct_threshold():
    """2 of 5 malicious = 40% >= 30% -> now MALICIOUS under new threshold."""
    results = [
        _r("a", Verdict.MALICIOUS), _r("b", Verdict.MALICIOUS),
        _r("c", Verdict.CLEAN), _r("d", Verdict.CLEAN),
        _r("e", Verdict.CLEAN),
    ]
    assert aggregate(results) == Verdict.MALICIOUS


def test_min_coverage_override():
    results = [_r("a", Verdict.CLEAN), _r("b", Verdict.CLEAN)]
    assert aggregate(results, min_coverage=2) == Verdict.CLEAN


def test_default_min_coverage_is_three():
    assert MIN_COVERAGE_DEFAULT == 3


def test_authoritative_spamhaus_overrides_majority():
    """Single Spamhaus MALICIOUS hit triggers MALICIOUS even if all others are clean."""
    results = [
        _r("spamhaus", Verdict.MALICIOUS),
        _r("feodo", Verdict.CLEAN),
        _r("tor", Verdict.CLEAN),
        _r("urlhaus", Verdict.CLEAN),
        _r("greynoise", Verdict.CLEAN),
    ]
    assert aggregate(results) == Verdict.MALICIOUS


def test_authoritative_feodo_overrides_majority():
    results = [
        _r("feodo", Verdict.MALICIOUS),
        _r("spamhaus", Verdict.CLEAN),
        _r("vt", Verdict.CLEAN),
        _r("tor", Verdict.CLEAN),
        _r("urlhaus", Verdict.CLEAN),
    ]
    assert aggregate(results) == Verdict.MALICIOUS


def test_vt_otx_weighted_double():
    """VT+OTX malicious + 7 clean: 4 weighted / 11 total = 36% >= 30% -> MALICIOUS."""
    results = [
        _r("virustotal", Verdict.MALICIOUS),
        _r("otx", Verdict.MALICIOUS),
        _r("spamhaus", Verdict.CLEAN),  # not authoritative when clean
        _r("feodo", Verdict.CLEAN),
        _r("tor", Verdict.CLEAN),
        _r("urlhaus", Verdict.CLEAN),
        _r("threatfox", Verdict.CLEAN),
        _r("abuseipdb", Verdict.CLEAN),
        _r("greynoise", Verdict.CLEAN),
    ]
    assert aggregate(results) == Verdict.MALICIOUS


def test_below_30pct_threshold_returns_clean():
    """Only AbuseIPDB malicious (1 weight) vs 8 clean (9 weight) = 1/10 = 10% < 30% -> CLEAN."""
    results = [
        _r("abuseipdb", Verdict.MALICIOUS),
        _r("virustotal", Verdict.CLEAN),
        _r("otx", Verdict.CLEAN),
        _r("spamhaus", Verdict.CLEAN),
        _r("feodo", Verdict.CLEAN),
        _r("tor", Verdict.CLEAN),
        _r("urlhaus", Verdict.CLEAN),
        _r("threatfox", Verdict.CLEAN),
        _r("greynoise", Verdict.CLEAN),
    ]
    assert aggregate(results) == Verdict.CLEAN


def test_aggregate_ignores_enrichment_only_providers():
    # An enrichment-only MALICIOUS row must not flip the verdict.
    results = [
        ProviderResult("a", Verdict.CLEAN, "x", None, None, 0),
        ProviderResult("b", Verdict.CLEAN, "x", None, None, 0),
        ProviderResult("c", Verdict.CLEAN, "x", None, None, 0),
        ProviderResult("shodan", Verdict.MALICIOUS, "x", None, None, 0),
    ]
    assert aggregate(results, enrichment_only={"shodan"}) == Verdict.CLEAN


def test_coverage_ignores_enrichment_only_providers():
    results = [
        ProviderResult("a", Verdict.CLEAN, "x", None, None, 0),
        ProviderResult("b", Verdict.UNKNOWN, "", None, None, 0),
        ProviderResult("shodan", Verdict.CLEAN, "x", None, None, 0),
    ]
    responding, total = coverage(results, enrichment_only={"shodan"})
    assert responding == 1  # 'a' only; 'b' UNKNOWN doesn't count
    assert total == 2       # 'a' + 'b'; 'shodan' excluded from total
