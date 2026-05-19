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

import httpx
from rich.console import Console
from rich.panel import Panel

from iocscan.core.cache import Cache
from iocscan.core.config import Config
from iocscan.core.ioc import detect_type
from iocscan.core.scan import scan_ioc
from iocscan.core.verdict import AUTHORITATIVE, WEIGHTS, aggregate, coverage
from iocscan.providers import ALL_PROVIDERS
from iocscan.providers.base import Verdict
from iocscan.ui.console import make_console
from iocscan.ui.glyph import verdict_glyph

# Cap raw response so a chatty provider can't drown the panel.
_RAW_LIMIT = 500


def _provider_panel(result, provider, ioc: str, ioc_type) -> Panel:
    glyph = verdict_glyph(result.verdict, ascii_only=False)
    lines: list[str] = [f"score:     {result.score or '—'}"]
    if result.error:
        lines.append(f"error:     {result.error}")
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

    if result.raw is not None:
        raw_str = json.dumps(result.raw, indent=2, default=str)
        if len(raw_str) > _RAW_LIMIT:
            raw_str = raw_str[:_RAW_LIMIT] + "…"
        lines.append("raw:")
        lines.append(raw_str)

    return Panel(
        "\n".join(lines),
        title=f"{provider.name}  {glyph} {result.verdict.value}",
        expand=False,
    )


def _math_panel(merged, min_coverage: int) -> Panel:
    enrichment_only = {p.name for p in ALL_PROVIDERS if p.enrichment_only}
    responding = [
        r for r in merged
        if r.verdict not in (Verdict.ERROR, Verdict.UNKNOWN)
        and r.provider not in enrichment_only
    ]
    mal_w = sum(WEIGHTS.get(r.provider, 1) for r in responding if r.verdict == Verdict.MALICIOUS)
    susp_w = sum(WEIGHTS.get(r.provider, 1) for r in responding if r.verdict == Verdict.SUSPICIOUS)
    total_w = sum(WEIGHTS.get(r.provider, 1) for r in responding)
    final = aggregate(merged, min_coverage=min_coverage, enrichment_only=enrichment_only)
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
    lines.append(f"final verdict: {final.value.upper()}")
    return Panel("\n".join(lines), title="aggregation math", expand=False)


async def _run(ioc: str, ioc_type, config: Config, console: Console) -> int:
    cache_path = Path(os.path.expanduser("~")) / ".iocscan" / "cache.db"
    cache = Cache(cache_path, ttl_seconds=config.cache_ttl_hours * 3600)
    try:
        cached = cache.get(ioc) or {}
        async with httpx.AsyncClient(
            http2=True, timeout=httpx.Timeout(config.timeout_seconds)
        ) as client:
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

        console.print(_math_panel(merged, config.min_coverage))
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
