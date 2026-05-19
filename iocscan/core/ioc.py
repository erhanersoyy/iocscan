from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse, urlunparse

from iocscan.providers.base import IOCType

_DEFANG_MAP = [
    (r"\[\.\]",   "."),
    (r"\(\.\)",   "."),
    (r"\[dot\]",  "."),
    (r"\(dot\)",  "."),
    (r"hxxp",     "http"),
    (r"hxxps",    "https"),
]
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
_HEX_RE = re.compile(r"^[0-9a-f]+$", re.IGNORECASE)
_HASH_LEN_TO_TYPE = {
    32: IOCType.HASH_MD5,
    40: IOCType.HASH_SHA1,
    64: IOCType.HASH_SHA256,
}


def _detect_hash(value: str) -> IOCType | None:
    """Classify hex strings of length 32/40/64 as MD5/SHA-1/SHA-256.

    Rejects all-same-char strings (e.g. "0"*32, "f"*64) which are
    sentinel placeholders, not real hashes.
    """
    if not _HEX_RE.match(value):
        return None
    ioc_type = _HASH_LEN_TO_TYPE.get(len(value))
    if ioc_type is None:
        return None
    if len(set(value.lower())) == 1:
        return None
    return ioc_type


def defang(s: str) -> str:
    """Refang a user-pasted defanged IOC back to its canonical form.

    Despite the name (kept for backward compatibility), this function turns
    `evil[.]com`, `1.2.3[.]4`, `hxxp://...` etc. *back* into normal strings
    that the rest of the pipeline can parse. See `to_defanged()` for the
    inverse operation used on output.
    """
    out = s.strip()
    for pat, repl in _DEFANG_MAP:
        out = re.sub(pat, repl, out, flags=re.IGNORECASE)
    return out


def to_defanged(s: str) -> str:
    """Render a canonical IOC in the standard defanged form: every `.` → `[.]`.

    Used when the caller passes `--defang` so output (table, JSON, TSV) is
    safe to paste into Slack / email / Confluence without auto-linking.
    Cache keys and the canonical "ioc" used by scan logic stay refanged.
    """
    return s.replace(".", "[.]")


def _detect_url(refanged: str) -> bool:
    """True if value is a well-formed http(s) URL with a host."""
    if "://" not in refanged:
        return False
    try:
        p = urlparse(refanged)
    except ValueError:
        return False
    return p.scheme in ("http", "https") and bool(p.netloc)


def detect_type(value: str) -> IOCType | None:
    if not value:
        return None
    refanged = defang(value).strip()
    if _detect_url(refanged):
        return IOCType.URL
    # A value containing `://` but failing _detect_url (e.g. non-http scheme,
    # missing host) is rejected outright rather than falling back to the
    # legacy "strip scheme, classify host" behavior — that path is now only
    # for bare IOCs without a scheme.
    if "://" in refanged:
        return None
    candidate = refanged.lower()
    if not candidate:
        return None
    try:
        ipaddress.ip_address(candidate)
        return IOCType.IP
    except ValueError:
        pass
    if _DOMAIN_RE.match(candidate):
        return IOCType.DOMAIN
    return _detect_hash(candidate)


def _normalize(value: str) -> str:
    refanged = defang(value).strip()
    if _detect_url(refanged):
        # RFC 3986: scheme + host are case-insensitive; path / query /
        # fragment are case-sensitive (e.g. /Resources vs /resources may
        # be two distinct endpoints). Lowercase only scheme + netloc.
        p = urlparse(refanged)
        normalized = p._replace(scheme=p.scheme.lower(), netloc=p.netloc.lower())
        return urlunparse(normalized)
    return refanged.lower()


def parse_iocs(
    raw: list[str], return_warnings: bool = False
) -> list[tuple[str, IOCType]] | tuple[list[tuple[str, IOCType]], list[str]]:
    seen: set[str] = set()
    out: list[tuple[str, IOCType]] = []
    warnings: list[str] = []
    for r in raw:
        t = detect_type(r)
        if t is None:
            warnings.append(f"skipped invalid IOC: {r!r}")
            continue
        norm = _normalize(r)
        if norm in seen:
            continue
        seen.add(norm)
        out.append((norm, t))
    if return_warnings:
        return out, warnings
    return out
