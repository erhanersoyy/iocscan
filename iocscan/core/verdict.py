from __future__ import annotations

from iocscan.providers.base import ProviderResult, Verdict

MIN_COVERAGE_DEFAULT = 3

# Authoritative blocklists — single MALICIOUS = final MALICIOUS
AUTHORITATIVE = {"spamhaus", "feodo"}

# Tier 2 weights (multi-engine / multi-source providers count more)
WEIGHTS = {
    "virustotal": 2,
    "otx": 2,
    # others default to 1
}


def aggregate(
    results: list[ProviderResult],
    *,
    min_coverage: int = MIN_COVERAGE_DEFAULT,
    enrichment_only: set[str] | None = None,
) -> Verdict:
    enrichment_only = enrichment_only or set()
    voting = [r for r in results if r.provider not in enrichment_only]
    responding = [
        r for r in voting
        if r.verdict not in (Verdict.ERROR, Verdict.UNKNOWN)
    ]
    if len(responding) < min_coverage:
        return Verdict.UNKNOWN

    # Tier 1: authoritative blocklist hit
    for r in responding:
        if r.provider in AUTHORITATIVE and r.verdict == Verdict.MALICIOUS:
            return Verdict.MALICIOUS

    # Tier 2: weighted voting at >=30% threshold
    mal_w = sum(WEIGHTS.get(r.provider, 1) for r in responding if r.verdict == Verdict.MALICIOUS)
    susp_w = sum(WEIGHTS.get(r.provider, 1) for r in responding if r.verdict == Verdict.SUSPICIOUS)
    total_w = sum(WEIGHTS.get(r.provider, 1) for r in responding)

    # Integer-safe >=30% check: mal_w * 10 >= total_w * 3
    if mal_w * 10 >= total_w * 3:
        return Verdict.MALICIOUS
    if (mal_w + susp_w) * 10 >= total_w * 3:
        return Verdict.SUSPICIOUS
    return Verdict.CLEAN


def coverage(
    results: list[ProviderResult],
    *,
    enrichment_only: set[str] | None = None,
) -> tuple[int, int]:
    enrichment_only = enrichment_only or set()
    voting = [r for r in results if r.provider not in enrichment_only]
    responding = sum(
        1 for r in voting
        if r.verdict not in (Verdict.ERROR, Verdict.UNKNOWN)
    )
    return responding, len(voting)
