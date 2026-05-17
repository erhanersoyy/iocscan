"""Whitelist of well-known infrastructure and CDN domains.

If an IOC matches (exact or subdomain), any MALICIOUS/SUSPICIOUS verdict is
overridden to CLEAN. This filters out common false positives from
high-traffic domains that appear in TI feeds as collateral.
"""
from __future__ import annotations

from iocscan.providers.base import IOCType

WHITELIST_DOMAINS = frozenset({
    # DNS / search / big tech
    "google.com", "googleapis.com", "googleusercontent.com", "gstatic.com",
    "youtube.com", "ytimg.com",
    "microsoft.com", "live.com", "office.com", "outlook.com", "office365.com",
    "windows.com", "windowsupdate.com", "msftncsi.com",
    "apple.com", "icloud.com", "mzstatic.com",
    "amazon.com", "amazonaws.com",
    "facebook.com", "fbcdn.net", "instagram.com",
    "twitter.com", "x.com",
    "linkedin.com",
    "github.com", "githubusercontent.com",
    "wikipedia.org",
    # CDNs
    "cloudflare.com", "cloudflare-dns.com", "cloudflareresolve.com",
    "akamai.com", "akamaihd.net", "akamaiedge.net", "akamaized.net",
    "fastly.net", "fastlylb.net",
    "cloudfront.net",
    "azure.com", "azureedge.net", "azurewebsites.net",
    # Public DNS
    "one.one.one.one",
    "dns.google",
    "opendns.com",
})


def is_whitelisted(ioc: str, ioc_type: IOCType) -> bool:
    """True if domain IOC matches or is a subdomain of a whitelisted domain."""
    if ioc_type != IOCType.DOMAIN:
        return False
    ioc_low = ioc.lower().strip()
    if ioc_low in WHITELIST_DOMAINS:
        return True
    parts = ioc_low.split(".")
    # Try every suffix (sub.example.com -> example.com, com)
    for i in range(1, len(parts)):
        suffix = ".".join(parts[i:])
        if suffix in WHITELIST_DOMAINS:
            return True
    return False
