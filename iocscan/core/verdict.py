from __future__ import annotations

from iocscan.providers.base import ProviderResult, Verdict

MIN_COVERAGE_DEFAULT = 3

# Authoritative blocklists — single MALICIOUS = final MALICIOUS.
# Membership criterion: the feed lists an IOC only after curated verification
# (a served payload, a confirmed C2, a submitted sample), not by heuristic
# scoring. URLhaus is the only such source that covers URLs and domains —
# without it those IOC types have no authoritative path at all, and the
# largest single weight (2) cannot reach the 30% bar in a 7-weight URL pool.
AUTHORITATIVE = {"spamhaus", "feodo", "malwarebazaar", "urlhaus"}

# Tier 2 weights (multi-engine / multi-source providers count more)
WEIGHTS = {
    "virustotal": 2,
    "otx": 2,
    # others default to 1
}

# A lone weight-1 vote can clear the 30% bar at minimum coverage (1/3 = 33%),
# but a single weak source must not decide MALICIOUS by itself: require one
# multi-engine provider or two independent sources. Below this the floor in
# aggregate() still surfaces the vote as SUSPICIOUS.
MIN_MALICIOUS_WEIGHT = 2

VOTE_THRESHOLD_PCT = 30


def meets_threshold(weight: int, total: int) -> bool:
    """Integer-safe `weight / total >= VOTE_THRESHOLD_PCT%` (no float rounding)."""
    return weight * 100 >= total * VOTE_THRESHOLD_PCT


def _voters(
    results: list[ProviderResult], enrichment_only: set[str] | None
) -> list[ProviderResult]:
    """Non-enrichment providers that returned a usable verdict."""
    enrichment_only = enrichment_only or set()
    return [
        r for r in results
        if r.provider not in enrichment_only
        and r.verdict not in (Verdict.ERROR, Verdict.UNKNOWN)
    ]


def _weigh(responding: list[ProviderResult]) -> tuple[int, int, int]:
    mal_w = sum(WEIGHTS.get(r.provider, 1) for r in responding if r.verdict == Verdict.MALICIOUS)
    susp_w = sum(WEIGHTS.get(r.provider, 1) for r in responding if r.verdict == Verdict.SUSPICIOUS)
    total_w = sum(WEIGHTS.get(r.provider, 1) for r in responding)
    return mal_w, susp_w, total_w


def vote_weights(
    results: list[ProviderResult],
    *,
    enrichment_only: set[str] | None = None,
) -> tuple[int, int, int]:
    """(malicious, suspicious, total) voting weights — the single source of
    truth for the tier-2 math, also rendered by `iocscan explain`."""
    return _weigh(_voters(results, enrichment_only))


def aggregate(
    results: list[ProviderResult],
    *,
    min_coverage: int = MIN_COVERAGE_DEFAULT,
    enrichment_only: set[str] | None = None,
) -> Verdict:
    responding = _voters(results, enrichment_only)

    # Tier 1: authoritative blocklist hit. Checked BEFORE the coverage gate —
    # curated-list membership is decisive on its own, whereas min_coverage
    # exists to block verdicts built on thin heuristic evidence. The
    # whitelist clamp (applied after aggregation) still guards the FP side.
    for r in responding:
        if r.provider in AUTHORITATIVE and r.verdict == Verdict.MALICIOUS:
            return Verdict.MALICIOUS

    # Gate floored at 1: zero voters is zero evidence — min_coverage=0 would
    # otherwise let the degenerate 0 >= 0 threshold conjure a verdict.
    if len(responding) < max(min_coverage, 1):
        return Verdict.UNKNOWN

    # Tier 2: weighted voting at >= VOTE_THRESHOLD_PCT
    mal_w, susp_w, total_w = _weigh(responding)

    if mal_w >= MIN_MALICIOUS_WEIGHT and meets_threshold(mal_w, total_w):
        return Verdict.MALICIOUS
    # A malicious vote below the bar is still evidence. Blocklists cast CLEAN
    # for mere absence from their feed, so a fresh threat seen by one real
    # engine can be outvoted — surface it as SUSPICIOUS, never silent CLEAN.
    if mal_w or meets_threshold(mal_w + susp_w, total_w):
        return Verdict.SUSPICIOUS
    return Verdict.CLEAN


def coverage(
    results: list[ProviderResult],
    *,
    enrichment_only: set[str] | None = None,
) -> tuple[int, int]:
    voting = [r for r in results if r.provider not in (enrichment_only or set())]
    return len(_voters(results, enrichment_only)), len(voting)
