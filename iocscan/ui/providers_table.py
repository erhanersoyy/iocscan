"""ASCII table renderer for `iocscan providers`."""
from __future__ import annotations

from datetime import datetime

from rich import box
from rich.console import Console
from rich.table import Table

from iocscan.core.config import Config
from iocscan.core.observability import ProviderHealth
from iocscan.core.quota import QuotaResult
from iocscan.providers.base import Provider
from iocscan.ui.table import _border_style


def _fmt_rate(p: Provider) -> str:
    """Render the static rate-limit budget declared on the provider class.

    `max_rps` is expressed per-second internally; surface it as req/min so it
    reads alongside the daily cap. Returns "—" when nothing is declared.
    """
    parts: list[str] = []
    if p.max_rps:
        parts.append(f"{round(p.max_rps * 60)}/min")
    if p.max_per_day:
        parts.append(f"{p.max_per_day}/day")
    return " · ".join(parts) if parts else "—"


def _fmt_supports(p: Provider) -> str:
    """Render supported IOC kinds, collapsing the hash subtypes into a single
    "hash (md5, sha1, sha256)" group instead of three separate entries."""
    hashes: list[str] = []
    others: list[str] = []
    for k in p.supports:
        v = k.value
        if v.startswith("hash_"):
            hashes.append(v.removeprefix("hash_"))
        else:
            others.append(v)
    parts = sorted(others)
    if hashes:
        parts.append(f"hash ({', '.join(sorted(hashes))})")
    return ", ".join(parts)


def render_providers_table(
    providers: list[Provider],
    config: Config,
    quotas: dict[str, QuotaResult],
    health: dict[str, ProviderHealth],
    console: Console,
) -> None:
    t = Table(
        box=box.ASCII,
        show_header=True,
        header_style="bold",
        padding=(0, 1),
        show_lines=True,
        border_style=_border_style(console),
    )
    t.add_column("Provider")
    t.add_column("Supports")
    t.add_column("Key")
    t.add_column("Key Added")
    t.add_column("Status")
    t.add_column("Quota / Rate Limits")
    t.add_column("Last Rate Limit Hit")

    for p in providers:
        active = p.has_key(config)
        status = (
            "[bold bright_green]* active[/]" if active
            else "[bold bright_red]x missing key[/]"
        )
        kinds = _fmt_supports(p)
        key_req = p.key_requirement()
        if key_req == "no":
            key_added = "—"
        elif config.key_for(p.key_alias or p.name):
            key_added = "[bright_green]added[/]"
        else:
            key_added = "[bright_red]no key[/]"
        q = quotas.get(p.name) or QuotaResult(p.name, None, None, "No Key")
        if q.used is not None and q.allowed is not None:
            quota_cell = f"{q.used} / {q.allowed}"
        else:
            quota_cell = q.note or "—"
        quota_cell = f"{quota_cell} / {_fmt_rate(p)}"
        h = health.get(p.name)
        if h and h.last_429_at:
            last_429 = datetime.fromtimestamp(h.last_429_at).strftime("%Y-%m-%d %H:%M")
        else:
            last_429 = "—"
        t.add_row(p.name, kinds, key_req, key_added, status, quota_cell, last_429)

    console.print(t)
    console.print(
        "\n[bold]To add keys:[/] edit config.toml or run [cyan]'iocscan config set <provider> <key>'[/].\n"
        "[yellow]Warning:[/] 'iocscan config set' may expose API keys by recording them in your shell history; "
        "editing config.toml directly avoids this."
    )
