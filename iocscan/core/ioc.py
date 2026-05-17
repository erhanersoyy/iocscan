from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

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


def defang(s: str) -> str:
    out = s.strip()
    for pat, repl in _DEFANG_MAP:
        out = re.sub(pat, repl, out, flags=re.IGNORECASE)
    return out


def _strip_url(s: str) -> str:
    if "://" in s:
        parsed = urlparse(s)
        return parsed.hostname or ""
    return s


def detect_type(value: str) -> IOCType | None:
    if not value:
        return None
    candidate = _strip_url(defang(value)).lower()
    if not candidate:
        return None
    try:
        ipaddress.ip_address(candidate)
        return IOCType.IP
    except ValueError:
        pass
    if _DOMAIN_RE.match(candidate):
        return IOCType.DOMAIN
    return None


def _normalize(value: str) -> str:
    return _strip_url(defang(value)).lower()


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
