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
