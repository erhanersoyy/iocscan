from __future__ import annotations

import statistics
import time
from urllib.parse import quote

import httpx

from iocscan.core.config import Config
from iocscan.providers.base import HASH_TYPES, IOCType, Provider, ProviderResult, Verdict, err_result as _err

BASE = "https://otx.alienvault.com/api/v1/indicators"

# OTX's canonical whitelist sources. We trust only these in the response's
# "validation" list — a spoofed/MitM response could otherwise inject an
# arbitrary entry to force CLEAN and suppress a malicious verdict (OTX votes
# with weight 2 in aggregation).
_TRUSTED_VALIDATION_SOURCES = {"majestic", "alexa", "whitelist", "akamai"}

# Largest pulse that still counts as attribution. A pulse naming half a
# million indicators is a bulk OSINT dump: the IOC merely co-occurs with
# malicious things instead of being reported as one. Live calibration
# (2026-08): pulses that genuinely attribute a domain carry 135-571
# indicators while bulk feeds start at 2,135, so 1000 sits in the empty gap
# between the two populations.
SPECIFICITY_MAX = 1000

# Longest pulse tag / pulse name rendered into a result row.
_MAX_TAG = 32
_MAX_NAME = 80

# Tags that describe the sample rather than the threat, compared lowercased
# with punctuation stripped. They crowd the family name out of the top three:
# moonlighthathel.org's were OTX indicator types ("filehashsha256, ..."), and
# gaiadeqi.com's URLhaus pulses tag Mozi alongside 32-bit / elf / mips at the
# same count, so the family lost the tie on list order. OTX's structured
# malware_families field is empty on those automated pulses (live, 2026-09).
_NOISE_TAGS = frozenset({
    # OTX indicator types
    "ipv4", "ipv6", "domain", "hostname", "url", "uri", "email", "cidr",
    "filehashmd5", "filehashsha1", "filehashsha256", "filehashpehash", "filehashimphash",
    "filepath", "mutex", "cve", "yara", "ja3", "bitcoinaddress", "sslcertfingerprint",
    # CPU architectures
    "32bit", "64bit", "x86", "x64", "x8664", "amd64", "i386", "i686", "arm", "arm4",
    "arm5", "arm6", "arm7", "arm64", "aarch64", "mips", "mipsel", "mpsl", "sh4",
    "sparc", "m68k", "powerpc", "ppc",
    # File formats and URLhaus delivery descriptors
    "elf", "exe", "dll", "apk", "msi", "lnk", "iso", "zip", "rar", "7z", "jar", "js",
    "vbs", "hta", "ps1", "bat", "sh", "doc", "docx", "xls", "xlsx", "pdf", "uawget",
})


def _pl(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def _root_pulses(pulses: list[dict]) -> list[dict]:
    """Collapse OTX clone chains — a pulse cloned N times is one report, not
    N. Clones nest (A cloned into B cloned into C), so walk back to the root.
    """
    by_id = {p["id"]: p for p in pulses if p.get("id")}
    roots: dict[str, dict] = {}
    for i, p in enumerate(pulses):
        seen: set[str] = set()
        while (c := p.get("cloned_from")) and c in by_id and c not in seen:
            seen.add(c)
            p = by_id[c]
        roots[p.get("id") or f"#{i}"] = p
    return list(roots.values())


def _attributes(pulse: dict) -> bool:
    """An unknown pulse size is not evidence of bulkiness: only a pulse we
    know to be huge is demoted, so missing data can never hide a real hit."""
    n = pulse.get("indicator_count")
    return not isinstance(n, int) or n <= SPECIFICITY_MAX


def _clip(text: object, limit: int) -> str:
    """Tags and names are free text written by pulse authors. The UI escapes
    markup but neither whitespace nor control characters: a tag of 30 newlines
    rendered as 30 blank rows in one cell, and Rich passes ESC through, so a
    pulse name could move the cursor and overwrite the verdict. Blank out every
    non-printable character, then collapse the runs before clipping."""
    if not isinstance(text, str):
        return ""
    text = " ".join("".join(c if c.isprintable() else " " for c in text).split())
    return text[:limit - 1] + "\u2026" if len(text) > limit else text


def _top_tags(pulses: list[dict], limit: int = 3) -> list[str]:
    counts: dict[str, int] = {}
    for p in pulses:
        tags = p.get("tags")
        if not isinstance(tags, list):
            continue
        for t in tags:
            t = _clip(t, _MAX_TAG)
            if t and "".join(filter(str.isalnum, t.lower())) not in _NOISE_TAGS:
                counts[t] = counts.get(t, 0) + 1
    return [t for t, _ in sorted(counts.items(), key=lambda kv: -kv[1])][:limit]


def _most_specific(pulses: list[dict]) -> str | None:
    """Name the smallest named pulse: the fewer indicators a report carries,
    the more directly it is about this IOC. Pooled tags are no stand-in —
    moonlighthathel.org showed a 749-indicator dump's type labels
    ("filehashsha256") while the untagged 8-indicator campaign report that
    actually named the domain stayed invisible."""
    named = [(p, n) for p in pulses if (n := _clip(p.get("name"), _MAX_NAME))]
    if not named:
        return None

    def size(pn: tuple[dict, str]) -> float:
        n = pn[0].get("indicator_count")
        return n if isinstance(n, int) else float("inf")

    p, name = min(named, key=size)
    n = p.get("indicator_count")
    return f"most specific pulse: {name}" + (f" ({_pl(n, 'indicator')})" if isinstance(n, int) else "")


class OTX(Provider):
    name = "otx"
    supports = {IOCType.IP, IOCType.DOMAIN, IOCType.URL, *HASH_TYPES}
    requires_key = True
    max_rps = 5.0

    async def lookup(self, ioc: str, ioc_type: IOCType, client: httpx.AsyncClient, config: Config) -> ProviderResult:
        key = config.key_for(self.name)
        if not key:
            return ProviderResult(self.name, Verdict.ERROR, "", None, "key required", 0)
        if ioc_type == IOCType.IP:
            path_prefix = "IPv4"
        elif ioc_type == IOCType.DOMAIN:
            path_prefix = "domain"
        elif ioc_type == IOCType.URL:
            path_prefix = "url"
        else:
            path_prefix = "file"   # hash variants
        # URL indicators contain slashes/query chars — percent-encode them
        # into a single path segment (same encoding permalink() uses). Other
        # IOC types are charset-validated upstream and safe to embed raw.
        ioc_path = quote(ioc, safe="") if ioc_type == IOCType.URL else ioc
        url = f"{BASE}/{path_prefix}/{ioc_path}/general"
        start = time.perf_counter()
        try:
            resp = await client.get(url, headers={"X-OTX-API-KEY": key})
        except httpx.HTTPError as e:
            return _err(self.name, f"network: {e.__class__.__name__}", start)
        latency = int((time.perf_counter() - start) * 1000)
        if resp.status_code == 429:
            return ProviderResult(self.name, Verdict.ERROR, "", None, "429 rate limit", latency)
        if resp.status_code in (401, 403):
            return ProviderResult(self.name, Verdict.ERROR, "", None, "auth failed", latency)
        if resp.status_code == 404:
            # OTX returns 404 for indicators it has never seen (observed for
            # hash lookups; URL lookups return 200 with pulse count 0 —
            # verified live 2026-07). No data is not an error.
            return ProviderResult(self.name, Verdict.UNKNOWN, "—", None, None, latency)
        if resp.status_code >= 400:
            return ProviderResult(self.name, Verdict.ERROR, "", None, f"{resp.status_code}", latency)
        try:
            data = resp.json()
            # OTX's own validation list (majestic / alexa / whitelist / akamai
            # popular-domain rankings) marks the
            # indicator as known-good. It wins over pulse count: popular legit
            # domains accrue pulses from phishing reports that impersonate them.
            # Trust only canonical sources so a spoofed response can't inject an
            # arbitrary entry to force CLEAN.
            validation = data.get("validation")
            matched = [
                v.get("source") for v in validation
                if isinstance(v, dict) and v.get("source") in _TRUSTED_VALIDATION_SOURCES
            ] if isinstance(validation, list) else []
            info = data.get("pulse_info", {})
            count = int(info.get("count", 0))
            if matched:
                # The clamp turns a weight-2 vote CLEAN. Say so out loud: an
                # analyst must be able to see that N pulses were overridden and
                # by which list, rather than reading a bare "whitelisted".
                lines = [f"whitelisted by OTX source: {', '.join(sorted(set(matched)))}"]
                if count:
                    lines.append(f"suppressed pulse count: {count}")
                return ProviderResult(
                    self.name, Verdict.CLEAN, "whitelisted", data, None, latency,
                    details=tuple(lines),
                )
            listed = info.get("pulses")
            listed = [p for p in listed if isinstance(p, dict)] if isinstance(listed, list) else []
            roots = _root_pulses(listed)
            clones = len(listed) - len(roots)
            lines = []
            if clones:
                lines.append(f"{_pl(clones, 'clone')} collapsed into {_pl(len(roots), 'root pulse')}")
            sized = any(isinstance(p.get("indicator_count"), int) for p in roots)
            if not sized:
                # No pulse sizes to judge by. Fall back to OTX's own total,
                # minus only the duplicates we could actually prove.
                n = count - clones
                score = _pl(n, "pulse") + (f" ({count} raw)" if clones else "")
            else:
                # Sizes are known, so attribution can be told apart from mere
                # co-occurrence. Pulses past OTX's page stay uninspected and
                # are counted as neither — unknown evidence is not malicious
                # evidence, and treating it as such nullified this filter for
                # every IOC with more pulses than the page holds.
                attributing = [p for p in roots if _attributes(p)]
                bulk = [p for p in roots if not _attributes(p)]
                n = len(attributing)
                score = f"{n}/{len(roots)} attributing" + (
                    f" ({count} raw)" if count > len(roots) else "")
                if bulk:
                    sizes = sorted(p["indicator_count"] for p in bulk)
                    lines.append(
                        f"{_pl(len(bulk), 'bulk feed')} ignored: smallest {sizes[0]:,} "
                        f"indicators, median {int(statistics.median(sizes)):,}"
                    )
                # Both lines: automated feed pulses are named by date, so the
                # name alone would drop the malware family their tags carry.
                if line := _most_specific(attributing):
                    lines.append(line)
                if tags := _top_tags(attributing or bulk):
                    lines.append(
                        f"{'attributing' if attributing else 'bulk-feed'} tags: {', '.join(tags)}"
                    )
            details = tuple(lines)
        except (ValueError, KeyError, AttributeError, TypeError):
            return ProviderResult(self.name, Verdict.ERROR, "", None, "parse error", latency)

        if n >= 3:
            v = Verdict.MALICIOUS
        elif n >= 1:
            v = Verdict.SUSPICIOUS
        elif sized:
            # OTX holds pulses it cannot attribute to this IOC. That is
            # evidence we cannot classify, not a clean bill of health: an
            # affirmative weight-2 CLEAN would dilute another provider's hit.
            return ProviderResult(
                self.name, Verdict.UNKNOWN, score, data, None, latency, details=details,
            )
        elif ioc_type == IOCType.URL:
            # OTX's URL indicator corpus is far thinner than its domain/IP/hash
            # coverage, so zero pulses on a URL means "no record", not "known
            # good" — and a weight-2 CLEAN would dilute another provider's hit.
            return ProviderResult(self.name, Verdict.UNKNOWN, "no URL record", data, None, latency)
        else:
            v = Verdict.CLEAN
        return ProviderResult(self.name, v, score, data, None, latency, details=details)

    def permalink(self, ioc: str, ioc_type: IOCType) -> str | None:
        if ioc_type == IOCType.IP:
            return f"https://otx.alienvault.com/indicator/ip/{ioc}"
        if ioc_type == IOCType.DOMAIN:
            return f"https://otx.alienvault.com/indicator/domain/{ioc}"
        if ioc_type == IOCType.URL:
            return f"https://otx.alienvault.com/indicator/url/{quote(ioc, safe='')}"
        return f"https://otx.alienvault.com/indicator/file/{ioc}"
