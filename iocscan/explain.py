"""`iocscan explain <ioc>` — per-provider rationale + aggregation math.

Runs the same scan pipeline a normal `iocscan` run uses (cache + concurrent
provider lookups), then renders one rich Panel per provider plus a final
"aggregation math" panel that shows how the verdict was computed.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

from rich.console import Console
from rich.markup import escape as _escape
from rich.panel import Panel

from iocscan.core.cache import Cache
from iocscan.core.config import Config
from iocscan.core.ioc import detect_type
from iocscan.core.scan import _apply_whitelist, scan_ioc
from iocscan.core.verdict import AUTHORITATIVE, WEIGHTS, aggregate, coverage
from iocscan.providers import ALL_PROVIDERS
from iocscan.providers.base import IOCType, Provider, ProviderResult, Verdict
from iocscan.ui.console import make_console
from iocscan.ui.glyph import verdict_glyph

# Cap raw response so a chatty provider can't drown the panel.
_RAW_LIMIT = 500


def _render_raw(raw: object) -> list[str]:
    """Render a provider's raw payload, lifting WHOIS onto its own stacked lines.

    VirusTotal returns the whole WHOIS record as one newline-delimited string at
    data.attributes.whois. json.dumps escapes those newlines to a literal "\\n",
    collapsing the record onto one unreadable line — so pull whois out and print
    each field on its own line, then dump the remaining payload as before.
    """
    whois = ""
    if isinstance(raw, dict):
        attrs = raw.get("data")
        attrs = attrs.get("attributes") if isinstance(attrs, dict) else None
        if isinstance(attrs, dict) and isinstance(attrs.get("whois"), str):
            whois = attrs["whois"]
            slim = {k: v for k, v in attrs.items() if k != "whois"}
            raw = {**raw, "data": {**raw["data"], "attributes": slim}}

    raw_str = json.dumps(raw, indent=2, default=str)
    if len(raw_str) > _RAW_LIMIT:
        raw_str = raw_str[:_RAW_LIMIT] + "…"
    lines = ["raw:", _escape(raw_str)]

    if whois:
        lines.append("whois:")
        lines.extend(f"  {_escape(w.strip())}" for w in whois.splitlines() if w.strip())
    return lines


def _provider_panel(
    result: ProviderResult, provider: Provider, ioc: str, ioc_type: IOCType,
) -> Panel:
    glyph = verdict_glyph(result.verdict, ascii_only=False)
    # Provider-controlled strings (score, error, raw) are escaped before
    # being handed to rich — a hostile WHOIS field could otherwise smuggle
    # `[link=file://…]` or `[red]` markup into the panel.
    lines: list[str] = [f"score:     {_escape(result.score or '—')}"]
    if result.error:
        lines.append(f"error:     {_escape(result.error)}")
    lines.append(f"latency:   {result.latency_ms} ms")

    permalink = provider.permalink(ioc, ioc_type)
    if permalink:
        lines.append(f"link:      [link={permalink}]{permalink}[/link]")

    if provider.enrichment_only:
        lines.append("note:      enrichment-only (does not vote)")
    elif provider.name in AUTHORITATIVE:
        lines.append("weight:    authoritative")
    else:
        lines.append(f"weight:    {WEIGHTS.get(provider.name, 1)}")

    if result.details:
        lines.append("details:")
        for d in result.details:
            lines.append(f"  {_escape(d)}")

    if result.raw is not None:
        lines.extend(_render_raw(result.raw))

    return Panel(
        "\n".join(lines),
        title=f"{provider.name}  {glyph} {result.verdict.value}",
        expand=False,
    )


def _math_panel(
    merged: list[ProviderResult], ioc: str, ioc_type: IOCType, min_coverage: int,
) -> Panel:
    enrichment_only = {p.name for p in ALL_PROVIDERS if p.enrichment_only}
    responding = [
        r for r in merged
        if r.verdict not in (Verdict.ERROR, Verdict.UNKNOWN)
        and r.provider not in enrichment_only
    ]
    mal_w = sum(WEIGHTS.get(r.provider, 1) for r in responding if r.verdict == Verdict.MALICIOUS)
    susp_w = sum(WEIGHTS.get(r.provider, 1) for r in responding if r.verdict == Verdict.SUSPICIOUS)
    total_w = sum(WEIGHTS.get(r.provider, 1) for r in responding)
    raw_verdict = aggregate(merged, min_coverage=min_coverage, enrichment_only=enrichment_only)
    # Match `_run_scan`'s post-aggregation clamp so the math panel agrees
    # with what `iocscan <ioc>` prints for whitelisted hosts.
    final, whitelisted = _apply_whitelist(ioc, ioc_type, raw_verdict)
    resp_count, total_count = coverage(merged, enrichment_only=enrichment_only)

    lines: list[str] = []
    auth_hit = next(
        (r for r in responding
         if r.provider in AUTHORITATIVE and r.verdict == Verdict.MALICIOUS),
        None,
    )
    if auth_hit:
        lines.append(
            f"authoritative hit: {auth_hit.provider} -> MALICIOUS "
            f"(short-circuits weighted vote)"
        )
    lines.append(f"voting: {resp_count}/{total_count} providers responding "
                 f"(min_coverage={min_coverage})")
    lines.append(f"weights: malicious={mal_w}  suspicious={susp_w}  total={total_w}")
    if total_w:
        mal_pct = mal_w / total_w * 100
        ms_pct = (mal_w + susp_w) / total_w * 100
        lines.append(f"malicious share:    {mal_w}/{total_w} = {mal_pct:.1f}% (threshold 30%)")
        lines.append(f"+ suspicious share: {mal_w + susp_w}/{total_w} = {ms_pct:.1f}%")
    if whitelisted and raw_verdict != final:
        lines.append(f"whitelisted: yes  ({raw_verdict.value.upper()} -> {final.value.upper()})")
    lines.append(f"final verdict: {final.value.upper()}")
    return Panel("\n".join(lines), title="aggregation math", expand=False)


async def _run(ioc: str, ioc_type: IOCType, config: Config, console: Console) -> int:
    # Local import to avoid a circular dependency: cli imports explain on demand.
    from iocscan.cli import _make_client

    cache_path = Path(os.path.expanduser("~")) / ".iocscan" / "cache.db"
    cache = Cache(cache_path, ttl_seconds=config.cache_ttl_hours * 3600)
    try:
        cached = cache.get(ioc) or {}
        async with _make_client(config.timeout_seconds) as client:
            providers_to_query = [
                p for p in ALL_PROVIDERS
                if p.name not in cached and ioc_type in p.supports
            ]
            scan = await scan_ioc(ioc, ioc_type, providers_to_query, client, config)

        merged = list(cached.values()) + scan.provider_results
        cache.put(ioc, scan.provider_results)

        by_name = {p.name: p for p in ALL_PROVIDERS}
        # Stable order: follow ALL_PROVIDERS so output is reproducible
        # regardless of asyncio scheduling.
        ordered = sorted(
            (r for r in merged if r.provider in by_name),
            key=lambda r: list(by_name).index(r.provider),
        )
        for r in ordered:
            console.print(_provider_panel(r, by_name[r.provider], ioc, ioc_type))

        console.print(_math_panel(merged, ioc, ioc_type, config.min_coverage))
        return 0
    finally:
        cache.close()


def explain_main(args, config: Config) -> int:
    ioc = args.ioc
    ioc_type = detect_type(ioc)
    if ioc_type is None:
        print(f"explain: invalid IOC: {ioc!r}", file=sys.stderr)
        return 3
    console = make_console()
    return asyncio.run(_run(ioc, ioc_type, config, console))
