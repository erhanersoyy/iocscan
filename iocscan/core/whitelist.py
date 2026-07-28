"""Whitelist of well-known infrastructure and CDN domains.

If an IOC matches an entry exactly — or is a subdomain of a suffix-trusted
entry (see _domain_sets: public-suffix Tranco entries match exact only) —
any MALICIOUS/SUSPICIOUS verdict is overridden to CLEAN. This filters out
common false positives from high-traffic domains that appear in TI feeds
as collateral.
"""
from __future__ import annotations

from functools import lru_cache

from iocscan.core.psl import EXTRACT as _EXTRACT
from iocscan.core.tranco import load_cache
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
def _tranco_cache() -> frozenset[str]:
    """Load Tranco cache once per process."""
    from iocscan.core import tranco as _tranco_mod
    return frozenset(load_cache(_tranco_mod.CACHE_PATH))


@lru_cache(maxsize=1)
def _domain_sets(tranco: frozenset[str]) -> tuple[frozenset[str], frozenset[str]]:
    """(exact, suffix) whitelist sets for a given Tranco snapshot.

    Every entry matches exactly. Subdomain (suffix) trust is narrower:
    bundled entries are hand-curated so all qualify — including the few that
    are themselves private-PSL suffixes (googleapis.com, akamaihd.net) —
    but a Tranco entry qualifies only if it is not a public suffix: the
    ranking includes user-content apexes (github.io, blogspot.com) whose
    subdomains are attacker-controlled.

    Keyed on the Tranco snapshot so a reloaded cache recomputes both sets.
    """
    suffix_ok = WHITELIST_DOMAINS | frozenset(
        d for d in tranco if _EXTRACT(d, include_psl_private_domains=True).domain
    )
    return WHITELIST_DOMAINS | tranco, suffix_ok


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
