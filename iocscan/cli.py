from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path

import httpx

from iocscan.core.cache import Cache
from iocscan.core.config import load_config
from iocscan.core.ioc import parse_iocs, to_defanged
from iocscan.core.scan import ScanResult, _apply_whitelist, scan_ioc, sort_scans
from iocscan.core.verdict import aggregate, coverage
from iocscan.providers import ALL_PROVIDERS
from iocscan.providers.base import ProviderResult, Verdict
from iocscan.ui.console import make_console
from iocscan.ui.footer import render_summary
from iocscan.ui.json_out import render_json
from iocscan.ui.table import render_table
from iocscan.ui.themes import DEFAULT_THEME, list_theme_names


def _make_client(timeout: int) -> httpx.AsyncClient:
    return httpx.AsyncClient(http2=True, timeout=httpx.Timeout(timeout))


def _read_inputs(args) -> list[str]:
    items: list[str] = []
    items.extend(args.iocs)
    if args.file:
        for line in Path(args.file).read_text().splitlines():
            s = line.strip()
            if s and not s.startswith("#"):
                items.append(s)
    if not items and not sys.stdin.isatty():
        for line in sys.stdin:
            s = line.strip()
            if s and not s.startswith("#"):
                items.append(s)
    return items


_SUBCOMMANDS = {"config", "cache", "providers", "whitelist"}


def _build_scan_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="iocscan",
        description="Consolidated TI verdict for IPs and domains.",
        epilog="Security note: passing API keys via --*-key flags exposes them to other local users (visible in 'ps'). Prefer IOCSCAN_*_KEY env vars or 'iocscan config set <provider> <value>'."
    )
    p.add_argument("iocs", nargs="*", help="IPs or domains to scan")
    p.add_argument("-f", "--file", help="read IOCs from file (one per line, # comments)")
    p.add_argument("--json", action="store_true", help="emit JSON instead of table")
    p.add_argument("--no-cache", action="store_true", help="bypass cache for this run")
    p.add_argument("--debug", action="store_true", help="verbose stderr (HTTP, errors)")
    p.add_argument("--narrow", action="store_true", help="force compact table layout")
    p.add_argument("--wide", action="store_true", help="force wide table layout (overrides terminal-width auto-detect)")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors (equivalent to NO_COLOR=1)")
    p.add_argument("--ascii", action="store_true", help="use ASCII glyphs ([!], [~], [ ], …) instead of Unicode")
    p.add_argument(
        "--theme",
        choices=list_theme_names(),
        default=os.environ.get("IOCSCAN_THEME", DEFAULT_THEME),
        help=f"color theme (default: {DEFAULT_THEME}; env: IOCSCAN_THEME)",
    )
    p.add_argument("--list-themes", action="store_true", help="show one-line preview of each theme then exit")
    p.add_argument("--defang", action="store_true", help="render IOCs in defanged form (1.2.3[.]4) in table/JSON/TSV output")
    p.add_argument("--quiet", "-q", action="store_true", help="suppress table + footer; emit TSV one line per IOC (IOC\\tverdict\\tcoverage)")
    p.add_argument(
        "--sort",
        choices=("input", "verdict", "coverage"),
        default="input",
        help="output order (default: input; verdict = worst-first; coverage = most-evidence-first)",
    )
    p.add_argument("--abusech-key", help="Abuse.ch API key (INSECURE: visible via 'ps'. Prefer IOCSCAN_ABUSECH_KEY env var)")
    p.add_argument("--vt-key", help="VirusTotal API key (INSECURE: visible via 'ps'. Prefer IOCSCAN_VT_KEY env var)")
    p.add_argument("--abuseipdb-key", help="AbuseIPDB API key (INSECURE: visible via 'ps'. Prefer IOCSCAN_ABUSEIPDB_KEY env var)")
    p.add_argument("--otx-key", help="OTX API key (INSECURE: visible via 'ps'. Prefer IOCSCAN_OTX_KEY env var)")
    p.add_argument("--greynoise-key", help="GreyNoise API key (INSECURE: visible via 'ps'. Prefer IOCSCAN_GREYNOISE_KEY env var)")
    return p


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="iocscan",
                                description="Consolidated TI verdict for IPs and domains.")
    sub = p.add_subparsers(dest="cmd")

    config_p = sub.add_parser("config", help="manage configuration")
    cfg_sub = config_p.add_subparsers(dest="config_cmd")
    set_p = cfg_sub.add_parser("set")
    set_p.add_argument("provider")
    set_p.add_argument("value")
    cfg_sub.add_parser("show")
    cfg_sub.add_parser("path")

    cache_p = sub.add_parser("cache", help="manage cache")
    cache_sub = cache_p.add_subparsers(dest="cache_cmd")
    cache_sub.add_parser("clear")
    cache_sub.add_parser("stats")

    sub.add_parser("providers", help="list providers and their status")

    wl_p = sub.add_parser("whitelist", help="manage Tranco top-1K whitelist cache")
    wl_sub = wl_p.add_subparsers(dest="wl_cmd")
    wl_sub.add_parser("update", help="fetch latest Tranco top-1K and cache it")
    wl_sub.add_parser("stats", help="show whitelist cache status")
    return p


def main(argv: list[str] | None = None) -> int:
    # Route to subcommand parser or scan parser based on first positional arg
    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    first_pos = next((a for a in raw_argv if not a.startswith("-")), None)

    if first_pos in _SUBCOMMANDS:
        parser = _build_arg_parser()
        args = parser.parse_args(raw_argv)
        # Fill in scan-parser defaults so attribute access is uniform
        args.iocs = []
        args.file = None
        args.json = False
        args.no_cache = False
        args.debug = False
        args.narrow = False
        args.wide = False
        args.no_color = False
        args.ascii = False
        args.theme = os.environ.get("IOCSCAN_THEME", DEFAULT_THEME)
        args.list_themes = False
        args.defang = False
        args.quiet = False
        args.sort = "input"
        args.abusech_key = None
        args.vt_key = None
        args.abuseipdb_key = None
        args.otx_key = None
        args.greynoise_key = None
    else:
        parser = _build_scan_parser()
        args = parser.parse_args(raw_argv)
        args.cmd = None

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(asctime)s %(name)s %(levelname)s: %(message)s",
        stream=sys.stderr,
        force=True,
    )

    cli_keys = {
        "abusech": args.abusech_key,
        "virustotal": args.vt_key,
        "abuseipdb": args.abuseipdb_key,
        "otx": args.otx_key,
        "greynoise": args.greynoise_key,
    }
    try:
        config = load_config(cli_keys=cli_keys)
    except ValueError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 3

    if args.cmd == "config":
        return _cmd_config(args, config)
    if args.cmd == "cache":
        return _cmd_cache(args, config)
    if args.cmd == "providers":
        return _cmd_providers(config)
    if args.cmd == "whitelist":
        return _cmd_whitelist(args)
    if args.list_themes:
        return _cmd_list_themes(args)

    raw = _read_inputs(args)
    if not raw:
        print("no IOCs provided (positional, -f, or stdin)", file=sys.stderr)
        return 3

    parsed, warnings = parse_iocs(raw, return_warnings=True)
    for w in warnings:
        print(w, file=sys.stderr)
    if not parsed:
        print("no valid IOCs after parsing", file=sys.stderr)
        return 3

    return asyncio.run(_run_scan(parsed, config, args))


async def _run_scan(parsed, config, args) -> int:
    import time
    cache_path = Path(os.path.expanduser("~")) / ".iocscan" / "cache.db"
    cache = None if args.no_cache else Cache(cache_path, ttl_seconds=config.cache_ttl_hours * 3600)
    cache_hits = 0
    cache_fresh = 0
    start_wall = time.perf_counter()
    try:
        scans = []
        async with _make_client(config.timeout_seconds) as client:
            for ioc, ioc_type in parsed:
                cached = cache.get(ioc) if cache else {}
                if cached:
                    cache_hits += 1
                else:
                    cache_fresh += 1
                providers_to_query = [p for p in ALL_PROVIDERS if p.name not in cached]
                scan = await scan_ioc(ioc, ioc_type, providers_to_query, client, config)
                if cached:
                    merged_results = list(cached.values()) + scan.provider_results
                    v = aggregate(merged_results, min_coverage=config.min_coverage)
                    resp, tot = coverage(merged_results)
                    final_verdict, whitelisted = _apply_whitelist(ioc, ioc_type, v)
                    scan = ScanResult(ioc, ioc_type, final_verdict, merged_results, resp, tot, whitelisted=whitelisted)
                if cache:
                    cache.put(ioc, scan.provider_results)
                scans.append(scan)

        elapsed_ms = int((time.perf_counter() - start_wall) * 1000)

        has_malicious = any(s.verdict == Verdict.MALICIOUS for s in scans)
        has_suspicious = any(s.verdict == Verdict.SUSPICIOUS for s in scans)
        all_unknown = all(s.verdict == Verdict.UNKNOWN for s in scans)
        all_errors = all(
            all(r.verdict == Verdict.ERROR for r in s.provider_results)
            for s in scans
        )
        if all_errors:
            exit_code = 4
        elif has_malicious:
            exit_code = 1
        elif has_suspicious:
            exit_code = 2
        elif all_unknown:
            exit_code = 5
        else:
            exit_code = 0

        # --sort: input order unchanged unless explicit. For --json, the
        # rule is that machine output stays in input order unless the user
        # opts in — so we apply the same sort to both human and machine
        # output: only when --sort != "input".
        scans_out = sort_scans(scans, args.sort) if args.sort != "input" else scans

        if args.quiet:
            _emit_quiet(scans_out, defang=args.defang)
        elif args.json:
            print(render_json(scans_out, min_coverage=config.min_coverage, defang=args.defang))
        else:
            console = make_console(no_color=args.no_color, ascii_only=args.ascii, theme=args.theme)
            render_table(
                scans_out, console,
                narrow=args.narrow, wide=args.wide,
                ascii_only=args.ascii, defang=args.defang,
            )
            if console.is_terminal and len(scans_out) > 0:
                render_summary(
                    scans_out, elapsed_ms, exit_code, console,
                    cache_hits=cache_hits, cache_fresh=cache_fresh,
                    ascii_only=args.ascii,
                )

        return exit_code
    finally:
        if cache is not None:
            cache.close()


def _cmd_config(args, config) -> int:
    if args.config_cmd == "set":
        config.set_key(args.provider, args.value)
        print(f"set {args.provider} key in {config.path}")
        return 0
    if args.config_cmd == "show":
        for k, v in config.keys.items():
            masked = v[:3] + "…" + v[-2:] if len(v) > 12 else "***"
            print(f"{k} = {masked}")
        return 0
    if args.config_cmd == "path":
        print(config.path)
        return 0
    print("usage: iocscan config {set <provider> <value>|show|path}", file=sys.stderr)
    return 3


def _cmd_cache(args, config) -> int:
    cache_path = Path(os.path.expanduser("~")) / ".iocscan" / "cache.db"
    cache = Cache(cache_path, ttl_seconds=config.cache_ttl_hours * 3600)
    try:
        if args.cache_cmd == "clear":
            cache.clear()
            print("cache cleared")
            return 0
        if args.cache_cmd == "stats":
            s = cache.stats()
            print(f"path: {s['path']}")
            print(f"rows: {s['rows']}")
            print(f"iocs: {s['iocs']}")
            print(f"size: {s['size_bytes']} bytes")
            if s.get("oldest_epoch"):
                import datetime
                age = datetime.datetime.fromtimestamp(s['oldest_epoch']).isoformat()
                print(f"oldest: {age}")
            else:
                print("oldest: (empty)")
            return 0
        print("usage: iocscan cache {clear|stats}", file=sys.stderr)
        return 3
    finally:
        cache.close()


def _cmd_whitelist(args) -> int:
    from iocscan.core import tranco
    if args.wl_cmd == "update":
        try:
            n = tranco.fetch_and_save()
        except (httpx.HTTPError, ValueError) as e:
            print(f"whitelist update failed: {e}", file=sys.stderr)
            return 4
        print(f"saved {n} domains to {tranco.CACHE_PATH}")
        return 0
    if args.wl_cmd == "stats":
        age = tranco.cache_age_days()
        cached = tranco.load_cache()
        if age is None:
            print("tranco cache: not present (run 'iocscan whitelist update')")
        else:
            print(f"tranco cache: {len(cached)} domains, {age} days old at {tranco.CACHE_PATH}")
        from iocscan.core.whitelist import WHITELIST_DOMAINS
        print(f"bundled whitelist: {len(WHITELIST_DOMAINS)} domains")
        return 0
    print("usage: iocscan whitelist {update|stats}", file=sys.stderr)
    return 3


def _cmd_providers(config) -> int:
    for p in ALL_PROVIDERS:
        status = "active" if p.has_key(config) else "missing key"
        kinds = ",".join(sorted(t.value for t in p.supports))
        print(f"{p.name:12} [{kinds:>10}] {status}")
    return 0


def _emit_quiet(scans, *, defang: bool) -> None:
    """One TSV line per IOC: IOC\\tverdict\\tresponding/total. No color, no header."""
    for s in scans:
        ioc = to_defanged(s.ioc) if defang else s.ioc
        print(f"{ioc}\t{s.verdict.value}\t{s.responding}/{s.total}")


def _cmd_list_themes(args) -> int:
    """One-line preview of every theme, then exit."""
    for name in list_theme_names():
        console = make_console(no_color=args.no_color, theme=name)
        marker = " (default)" if name == DEFAULT_THEME else ""
        console.print(
            f"[table.header]{name}[/]{marker}: "
            f"[verdict.malicious]● malicious[/] "
            f"[verdict.suspicious]◐ suspicious[/] "
            f"[verdict.clean]○ clean[/] "
            f"[verdict.unknown]· unknown[/] "
            f"[verdict.error]✗ error[/]"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
