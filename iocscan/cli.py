from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sqlite3
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
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from iocscan.ui.console import make_console
from iocscan.ui.export import EXPORT_FORMATS, render_export
from iocscan.ui.footer import render_summary
from iocscan.ui.json_out import render_json
from iocscan.ui.table import render_table
from iocscan.ui.themes import DEFAULT_THEME, list_theme_names

FORMAT_CHOICES = ("table", "json", *EXPORT_FORMATS)


def _make_client(timeout: int) -> httpx.AsyncClient:
    return httpx.AsyncClient(http2=True, timeout=httpx.Timeout(timeout))


_MAX_INPUT_BYTES = 50 * 1024 * 1024  # 50 MiB — same cap as bulk-blocklist providers


def _read_inputs(args) -> list[str]:
    items: list[str] = []
    items.extend(args.iocs)
    if args.file:
        try:
            path = Path(args.file)
            # Symlink rejection mirrors the cache.db guard: never follow a link
            # for user-supplied paths (could be re-pointed to a sensitive file
            # like ~/.iocscan/config.toml between checks).
            if path.is_symlink():
                raise ValueError(f"input file is a symlink (refused): {args.file}")
            size = path.stat().st_size
            if size > _MAX_INPUT_BYTES:
                raise ValueError(
                    f"input file too large ({size} bytes > {_MAX_INPUT_BYTES} limit): {args.file}"
                )
            content = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            raise ValueError(f"input file not found: {args.file}") from None
        except IsADirectoryError:
            raise ValueError(f"input path is not a file (is a directory): {args.file}") from None
        except PermissionError:
            raise ValueError(f"input file unreadable (permission denied): {args.file}") from None
        except UnicodeDecodeError:
            raise ValueError(f"input file is not valid UTF-8 text: {args.file}") from None
        for line in content.splitlines():
            s = line.strip()
            if s and not s.startswith("#"):
                items.append(s)
    if not items and not sys.stdin.isatty():
        for line in sys.stdin:
            s = line.strip()
            if s and not s.startswith("#"):
                items.append(s)
    return items


_SUBCOMMANDS = {"config", "cache", "providers", "whitelist", "explain", "health"}


def _build_scan_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="iocscan",
        description="Consolidated TI verdict for IPs and domains.",
        epilog="Security note: passing API keys via --*-key flags exposes them to other local users (visible in 'ps'). Prefer IOCSCAN_*_KEY env vars or 'iocscan config set <provider> <value>'."
    )
    p.add_argument("iocs", nargs="*", help="IPs or domains to scan")
    p.add_argument("-f", "--file", help="read IOCs from file (one per line, # comments)")
    p.add_argument(
        "-F", "--format",
        choices=FORMAT_CHOICES,
        default="table",
        help="output format (default: table). table/json render as before; jsonl/csv/markdown are flat summary exports.",
    )
    p.add_argument("--json", action="store_true", help="deprecated alias for --format json")
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
    p.add_argument(
        "--cell-links", action="store_true",
        help="emit OSC 8 hyperlinks on provider cells (terminal adds an underline); off by default",
    )
    p.add_argument("--quiet", "-q", action="store_true", help="suppress table + footer; emit TSV one line per IOC (IOC\\tverdict\\tcoverage)")
    p.add_argument(
        "--links-only", action="store_true",
        help="emit IOC\\tprovider\\tpermalink TSV (only rows with a permalink); suppresses table/JSON",
    )
    p.add_argument(
        "--sort",
        choices=("input", "verdict", "coverage"),
        default="input",
        help="output order (default: input; verdict = worst-first; coverage = most-evidence-first)",
    )
    p.add_argument(
        "--include",
        default="",
        help=(
            "JSON output only: comma-separated dot-paths to keep "
            "(`*` matches any list index). "
            "Example: 'results.*.ioc,results.*.verdict'."
        ),
    )
    p.add_argument(
        "--exclude",
        default="",
        help=(
            "JSON output only: comma-separated dot-paths to drop. "
            "Applied after --include."
        ),
    )
    p.add_argument("--abusech-key", help="Abuse.ch API key (INSECURE: visible via 'ps'. Prefer IOCSCAN_ABUSECH_KEY env var)")
    p.add_argument("--vt-key", help="VirusTotal API key (INSECURE: visible via 'ps'. Prefer IOCSCAN_VT_KEY env var)")
    p.add_argument("--abuseipdb-key", help="AbuseIPDB API key (INSECURE: visible via 'ps'. Prefer IOCSCAN_ABUSEIPDB_KEY env var)")
    p.add_argument("--otx-key", help="OTX API key (INSECURE: visible via 'ps'. Prefer IOCSCAN_OTX_KEY env var)")
    p.add_argument("--greynoise-key", help="GreyNoise API key (INSECURE: visible via 'ps'. Prefer IOCSCAN_GREYNOISE_KEY env var)")
    p.add_argument("--urlscan-key", help="urlscan.io API key (INSECURE: visible via 'ps'. Prefer IOCSCAN_URLSCAN_KEY env var)")
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

    explain_p = sub.add_parser(
        "explain",
        help="explain verdict for one IOC (per-provider rationale + math)",
    )
    explain_p.add_argument("ioc", help="single IOC to explain")

    wl_p = sub.add_parser("whitelist", help="manage Tranco top-1K whitelist cache")
    wl_sub = wl_p.add_subparsers(dest="wl_cmd")
    wl_sub.add_parser("update", help="fetch latest Tranco top-1K and cache it")
    wl_sub.add_parser("stats", help="show whitelist cache status")

    health_p = sub.add_parser(
        "health",
        help="per-provider operational health (last error, p95 latency, error rate)",
    )
    health_p.add_argument(
        "--days", type=int, default=7,
        help="lookback window in days (default: 7)",
    )
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
        args.format = "table"
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
        args.cell_links = False
        args.quiet = False
        args.links_only = False
        args.sort = "input"
        args.include = ""
        args.exclude = ""
        args.abusech_key = None
        args.vt_key = None
        args.abuseipdb_key = None
        args.otx_key = None
        args.greynoise_key = None
        args.urlscan_key = None
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
        "urlscan": args.urlscan_key,
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
    if args.cmd == "explain":
        from iocscan.explain import explain_main
        return explain_main(args, config)
    if args.cmd == "health":
        return _cmd_health(args, config)
    if args.list_themes:
        return _cmd_list_themes(args)

    try:
        raw = _read_inputs(args)
    except ValueError as e:
        print(f"input error: {e}", file=sys.stderr)
        return 3
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


def _progress_enabled(args) -> bool:
    """Stderr progress is on only when the user is watching a table.

    Disabled under --json (machine output), --quiet (TSV), legacy --json flag,
    and --debug (avoids interleaving with log lines).
    """
    if getattr(args, "json", False):
        return False
    if getattr(args, "quiet", False):
        return False
    if getattr(args, "debug", False):
        return False
    return getattr(args, "format", "table") == "table"


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
                applicable = [p for p in providers_to_query if ioc_type in p.supports]
                total_providers = len(applicable)

                if _progress_enabled(args) and total_providers:
                    # Transient progress: spinner clears once the IOC is done so
                    # the final table renders without leftover ANSI artifacts.
                    progress = Progress(
                        SpinnerColumn(),
                        TextColumn("Fetching data: {task.fields[ioc]} ({task.completed}/{task.total} providers)"),
                        transient=True,
                        # Stderr so stdout stays clean for piping table output.
                        console=Console(stderr=True),
                    )
                    task_id = progress.add_task("scan", total=total_providers, ioc=ioc)
                    progress.start()
                    try:
                        scan = await scan_ioc(
                            ioc, ioc_type, providers_to_query, client, config,
                            on_result=lambda _r, p=progress, t=task_id: p.advance(t),
                        )
                    finally:
                        progress.stop()
                else:
                    scan = await scan_ioc(ioc, ioc_type, providers_to_query, client, config)

                if cached:
                    merged_results = list(cached.values()) + scan.provider_results
                    enrichment_only = {p.name for p in ALL_PROVIDERS if p.enrichment_only}
                    v = aggregate(
                        merged_results, min_coverage=config.min_coverage,
                        enrichment_only=enrichment_only,
                    )
                    resp, tot = coverage(merged_results, enrichment_only=enrichment_only)
                    final_verdict, whitelisted = _apply_whitelist(ioc, ioc_type, v)
                    scan = ScanResult(ioc, ioc_type, final_verdict, merged_results, resp, tot, whitelisted=whitelisted)
                if cache:
                    cache.put(ioc, scan.provider_results)
                    # Mirror cache's --no-cache opt-out: observability is also
                    # skipped when the user explicitly disables persistence.
                    cache.record_observations(scan.provider_results)
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

        # Resolve effective output format. --quiet (TSV, no noise) wins over
        # everything; otherwise legacy --json maps to --format json.
        # --json with a non-default --format is a contradiction — reject it
        # so the user gets a clear error rather than one silently winning.
        fmt = args.format
        if args.json:
            if args.format != "table":
                print(
                    f"error: --json conflicts with --format {args.format}; use one or the other",
                    file=sys.stderr,
                )
                return 3
            fmt = "json"
            if not args.quiet:
                print("warning: --json is deprecated; use --format json", file=sys.stderr)

        if args.links_only:
            _emit_links(scans_out, ALL_PROVIDERS)
            return exit_code
        if args.quiet:
            _emit_quiet(scans_out, defang=args.defang)
        elif fmt == "json":
            payload_str = render_json(
                scans_out, min_coverage=config.min_coverage,
                defang=args.defang, providers=ALL_PROVIDERS,
            )
            inc = [s.strip() for s in args.include.split(",") if s.strip()]
            exc = [s.strip() for s in args.exclude.split(",") if s.strip()]
            if inc or exc:
                import json
                from iocscan.ui.field_filter import apply_filter
                payload = json.loads(payload_str)
                payload_str = json.dumps(apply_filter(payload, inc, exc), indent=2)
            print(payload_str)
        elif fmt in EXPORT_FORMATS:
            print(render_export(scans_out, fmt, defang=args.defang))
        else:  # table
            console = make_console(no_color=args.no_color, ascii_only=args.ascii, theme=args.theme)
            render_table(
                scans_out, console,
                narrow=args.narrow, wide=args.wide,
                ascii_only=args.ascii, defang=args.defang,
                providers=ALL_PROVIDERS,
                links=args.cell_links,
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


def _cmd_health(args, config) -> int:
    """Render per-provider health from the observability table."""
    from datetime import datetime

    from rich import box
    from rich.table import Table

    from iocscan.core.observability import health_report

    cache_path = Path(os.path.expanduser("~")) / ".iocscan" / "cache.db"
    cache = Cache(cache_path, ttl_seconds=config.cache_ttl_hours * 3600)
    try:
        report = health_report(cache._conn, lookback_seconds=args.days * 86400)
        if not report:
            print(
                f"no observations in the last {args.days} day(s); run iocscan first",
                file=sys.stderr,
            )
            return 0

        console = make_console()
        t = Table(box=box.HEAVY_HEAD, show_header=True, header_style="bold")
        t.add_column("provider")
        t.add_column("samples", justify="right")
        t.add_column("errors", justify="right")
        t.add_column("err %", justify="right")
        t.add_column("p95 ms", justify="right")
        t.add_column("last error")
        t.add_column("last 429")
        t.add_column("last 5xx")

        def _fmt_ts(ts):
            return (
                datetime.fromtimestamp(ts).isoformat(timespec="seconds")
                if ts
                else "—"
            )

        for p in report:
            t.add_row(
                p.provider,
                str(p.samples),
                str(p.error_count),
                f"{p.error_rate * 100:.1f}",
                str(p.p95_latency_ms) if p.p95_latency_ms is not None else "—",
                _fmt_ts(p.last_error_at),
                _fmt_ts(p.last_429_at),
                _fmt_ts(p.last_5xx_at),
            )
        console.print(t)
        return 0
    finally:
        cache.close()


def _cmd_providers(config) -> int:
    """Sync entry point — kicks off the async probe + render."""
    return asyncio.run(_cmd_providers_async(config))


async def _cmd_providers_async(config) -> int:
    from iocscan.core.observability import ProviderHealth, health_report
    from iocscan.core.quota import QuotaResult, probe_quotas
    from iocscan.ui.providers_table import render_providers_table

    # Health (last 429s) is best-effort from the same SQLite cache file.
    health: dict[str, ProviderHealth] = {}
    try:
        cache_path = Path(os.path.expanduser("~")) / ".iocscan" / "cache.db"
        if cache_path.exists():
            c = Cache(cache_path, ttl_seconds=config.cache_ttl_hours * 3600)
            try:
                for h in health_report(c._conn):  # noqa: SLF001 — Cache exposes the conn for this purpose
                    health[h.provider] = h
            finally:
                c.close()
    except (sqlite3.Error, ValueError, OSError):
        # Observability is non-critical; an empty `health` just means "—" in the Last 429 column.
        health = {}

    # Only providers with a probeable quota endpoint trigger live probes.
    probeable = [p for p in ALL_PROVIDERS if p.name in ("virustotal", "abuseipdb") and p.has_key(config)]

    stderr_console = Console(stderr=True)
    quotas: dict[str, QuotaResult] = {}
    async with _make_client(config.timeout_seconds) as client:
        if probeable:
            progress = Progress(
                SpinnerColumn(),
                TextColumn("Fetching provider quotas… ({task.completed}/{task.total})"),
                transient=True,
                console=stderr_console,
            )
            task_id = progress.add_task("probe", total=len(probeable))
            progress.start()
            try:
                quotas = await probe_quotas(probeable, config, client, timeout_seconds=20.0)
                # Bump bar to full after all probes finish.
                progress.update(task_id, completed=len(probeable))
            finally:
                progress.stop()

    # Fill quota cells for providers we didn't probe.
    for p in ALL_PROVIDERS:
        if p.name in quotas:
            continue
        if not p.has_key(config):
            quotas[p.name] = QuotaResult(p.name, None, None, "No Key")
        elif p.name in ("virustotal", "abuseipdb"):
            # Had a key but wasn't included (defensive — shouldn't happen).
            quotas[p.name] = QuotaResult(p.name, None, None, "error: not probed")
        else:
            quotas[p.name] = QuotaResult(p.name, None, None, "no quota API")

    stdout_console = Console()
    render_providers_table(ALL_PROVIDERS, config, quotas, health, stdout_console)
    return 0


def _emit_quiet(scans, *, defang: bool) -> None:
    """One TSV line per IOC: IOC\\tverdict\\tresponding/total. No color, no header."""
    for s in scans:
        ioc = to_defanged(s.ioc) if defang else s.ioc
        print(f"{ioc}\t{s.verdict.value}\t{s.responding}/{s.total}")


def _emit_links(scans, providers) -> None:
    """TSV: IOC\\tprovider\\tpermalink, one row per (IOC, provider) with a permalink."""
    by_name = {p.name: p for p in providers}
    for s in scans:
        for r in s.provider_results:
            p = by_name.get(r.provider)
            if p is None:
                continue
            link = p.permalink(s.ioc, s.ioc_type)
            if link:
                print(f"{s.ioc}\t{p.name}\t{link}")


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
