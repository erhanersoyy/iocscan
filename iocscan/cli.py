from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path

import httpx
from rich.console import Console

from iocscan.core.cache import Cache
from iocscan.core.config import load_config
from iocscan.core.ioc import parse_iocs
from iocscan.core.scan import scan_ioc
from iocscan.providers import ALL_PROVIDERS
from iocscan.providers.base import ProviderResult, Verdict
from iocscan.ui.json_out import render_json
from iocscan.ui.table import render_table


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


_SUBCOMMANDS = {"config", "cache", "providers"}


def _build_scan_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="iocscan",
                                description="Consolidated TI verdict for IPs and domains.")
    p.add_argument("iocs", nargs="*", help="IPs or domains to scan")
    p.add_argument("-f", "--file", help="read IOCs from file (one per line, # comments)")
    p.add_argument("--json", action="store_true", help="emit JSON instead of table")
    p.add_argument("--no-cache", action="store_true", help="bypass cache for this run")
    p.add_argument("--debug", action="store_true", help="verbose stderr (HTTP, errors)")
    p.add_argument("--narrow", action="store_true", help="force compact table layout")
    p.add_argument("--vt-key")
    p.add_argument("--abuseipdb-key")
    p.add_argument("--otx-key")
    p.add_argument("--greynoise-key")
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
    cache_path = Path(os.path.expanduser("~")) / ".iocscan" / "cache.db"
    cache = None if args.no_cache else Cache(cache_path, ttl_seconds=config.cache_ttl_hours * 3600)
    try:
        scans = []
        async with _make_client(config.timeout_seconds) as client:
            for ioc, ioc_type in parsed:
                cached = cache.get(ioc) if cache else {}
                providers_to_query = [p for p in ALL_PROVIDERS if p.name not in cached]
                scan = await scan_ioc(ioc, ioc_type, providers_to_query, client, config)
                if cached:
                    merged_results = list(cached.values()) + scan.provider_results
                    from iocscan.core.scan import ScanResult
                    from iocscan.core.verdict import aggregate, coverage
                    v = aggregate(merged_results, min_coverage=config.min_coverage)
                    resp, tot = coverage(merged_results)
                    scan = ScanResult(ioc, ioc_type, v, merged_results, resp, tot)
                if cache:
                    cache.put(ioc, scan.provider_results)
                scans.append(scan)

        if args.json:
            print(render_json(scans, min_coverage=config.min_coverage))
        else:
            render_table(scans, Console(), narrow=args.narrow)

        has_malicious = any(s.verdict == Verdict.MALICIOUS for s in scans)
        has_suspicious = any(s.verdict == Verdict.SUSPICIOUS for s in scans)
        all_unknown = all(s.verdict == Verdict.UNKNOWN for s in scans)
        all_errors = all(
            all(r.verdict == Verdict.ERROR for r in s.provider_results)
            for s in scans
        )

        if all_errors:
            return 4
        if has_malicious:
            return 1
        if has_suspicious:
            return 2
        if all_unknown:
            return 5
        return 0
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


def _cmd_providers(config) -> int:
    for p in ALL_PROVIDERS:
        status = "active" if p.has_key(config) else "missing key"
        kinds = ",".join(sorted(t.value for t in p.supports))
        print(f"{p.name:12} [{kinds:>10}] {status}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
