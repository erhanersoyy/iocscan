"""Whitelist of well-known infrastructure and CDN domains.

If an IOC matches an entry exactly — or is a subdomain of a suffix-trusted
entry (see _domain_sets: PSL-suffix entries match exact only) — any
MALICIOUS/SUSPICIOUS verdict is overridden to CLEAN. This filters out
common false positives from high-traffic domains that appear in TI feeds
as collateral.
"""
from __future__ import annotations

from functools import lru_cache

from iocscan.core.psl import EXTRACT as _EXTRACT
from iocscan.core.tranco import WHITELIST_TOP_N, load_cache
from iocscan.providers.base import IOCType

WHITELIST_DOMAINS = frozenset({
    # DNS / search / big tech
    "google.com", "googleapis.com", "googleusercontent.com", "gstatic.com",
    "youtube.com", "ytimg.com",
    "microsoft.com", "live.com", "office.com", "outlook.com", "office365.com",
    "windows.com", "windowsupdate.com", "msftncsi.com",
    "apple.com", "icloud.com", "mzstatic.com",
    "amazon.com",
    "facebook.com", "fbcdn.net", "instagram.com",
    "twitter.com", "x.com",
    "linkedin.com",
    "github.com",
    "wikipedia.org",
    # CDNs
    "cloudflare.com", "cloudflare-dns.com", "cloudflareresolve.com",
    "akamai.com", "akamaihd.net", "akamaiedge.net", "akamaized.net",
    "fastly.net", "fastlylb.net",
    "azure.com",
    # Public DNS
    "one.one.one.one",
    "dns.google",
    "opendns.com",
})


@lru_cache(maxsize=1)
def _tranco_ranks() -> dict[str, int]:
    """Load Tranco {domain: rank} once per process."""
    from iocscan.core import tranco as _tranco_mod
    return load_cache(_tranco_mod.CACHE_PATH) or load_cache(_tranco_mod.legacy_path())


@lru_cache(maxsize=1)
def _tranco_cache() -> frozenset[str]:
    """Top-1K slice of the Tranco cache — the only part that whitelists."""
    return frozenset(d for d, r in _tranco_ranks().items() if r <= WHITELIST_TOP_N)


@lru_cache(maxsize=1)
def _domain_sets(tranco: frozenset[str]) -> tuple[frozenset[str], frozenset[str]]:
    """(exact, suffix) whitelist sets for a given Tranco snapshot.

    Every entry matches exactly, but only entries that are not PSL suffixes
    extend trust to subdomains — regardless of who curated them. Suffix
    apexes (github.io, blogspot.com from Tranco; googleapis.com,
    akamaihd.net from the bundled list) host tenant content, so their
    subdomains are third-party-controlled and must not inherit the
    whitelist. Extends bd5fa7c, which removed amazonaws.com/cloudfront.net
    outright; keeping these exact-only preserves apex FP suppression.

    Keyed on the Tranco snapshot so a reloaded cache recomputes both sets.
    """
    exact = WHITELIST_DOMAINS | tranco
    suffix_ok = frozenset(
        d for d in exact if _EXTRACT(d, include_psl_private_domains=True).domain
    )
    return exact, suffix_ok


def is_whitelisted(ioc: str, ioc_type: IOCType) -> bool:
    """True if domain IOC matches or is a subdomain of a whitelisted domain."""
    if ioc_type != IOCType.DOMAIN:
        return False
    ioc_low = ioc.lower().strip()
    exact, suffix_ok = _domain_sets(_tranco_cache())
    if ioc_low in exact:
        return True
    parts = ioc_low.split(".")
    # Try every parent suffix (sub.example.com -> example.com)
    return any(".".join(parts[i:]) in suffix_ok for i in range(1, len(parts)))


def reload() -> None:
    """Drop the per-process Tranco caches (after `whitelist update`, in tests)."""
    _tranco_ranks.cache_clear()
    _tranco_cache.cache_clear()


def tranco_tier(ioc: str, ioc_type: IOCType) -> str | None:
    """Display-only popularity bucket: "1k", "10k", "20k", or None.

    Looks up the host, then its registrable domain (api.github.com -> github.com).
    Private PSL suffixes stay their own registrable domain, so foo.github.io
    never inherits github.io's rank. Never affects the verdict.
    """
    if ioc_type != IOCType.DOMAIN:
        return None
    ranks = _tranco_ranks()
    host = ioc.lower().strip()
    reg = _EXTRACT(host, include_psl_private_domains=True).top_domain_under_public_suffix
    rank = ranks.get(host) or ranks.get(reg)
    if rank is None:
        return None
    return "1k" if rank <= 1000 else "10k" if rank <= 10000 else "20k"
