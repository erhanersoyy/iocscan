"""Whitelist of well-known infrastructure and CDN domains.

If an IOC matches (exact or subdomain), any MALICIOUS/SUSPICIOUS verdict is
overridden to CLEAN. This filters out common false positives from
high-traffic domains that appear in TI feeds as collateral.
"""
from __future__ import annotations

from functools import lru_cache

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


def _combined() -> frozenset[str]:
    return WHITELIST_DOMAINS | _tranco_cache()


def is_whitelisted(ioc: str, ioc_type: IOCType) -> bool:
    """True if domain IOC matches or is a subdomain of a whitelisted domain."""
    if ioc_type != IOCType.DOMAIN:
        return False
    ioc_low = ioc.lower().strip()
    combined = _combined()
    if ioc_low in combined:
        return True
    parts = ioc_low.split(".")
    # Try every suffix (sub.example.com -> example.com, com)
    for i in range(1, len(parts)):
        suffix = ".".join(parts[i:])
        if suffix in combined:
            return True
    return False
