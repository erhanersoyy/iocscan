from __future__ import annotations

from iocscan.providers.base import ProviderResult, Verdict

MIN_COVERAGE_DEFAULT = 3


def aggregate(
    results: list[ProviderResult], *, min_coverage: int = MIN_COVERAGE_DEFAULT
) -> Verdict:
    responding = [
        r for r in results
        if r.verdict not in (Verdict.ERROR, Verdict.UNKNOWN)
    ]
    if len(responding) < min_coverage:
        return Verdict.UNKNOWN
    malicious  = sum(1 for r in responding if r.verdict == Verdict.MALICIOUS)
    suspicious = sum(1 for r in responding if r.verdict == Verdict.SUSPICIOUS)
    n = len(responding)
    if malicious * 2 > n:
        return Verdict.MALICIOUS
    if (malicious + suspicious) * 2 > n:
        return Verdict.SUSPICIOUS
    return Verdict.CLEAN


def coverage(results: list[ProviderResult]) -> tuple[int, int]:
    responding = sum(
        1 for r in results
        if r.verdict not in (Verdict.ERROR, Verdict.UNKNOWN)
    )
    return responding, len(results)
