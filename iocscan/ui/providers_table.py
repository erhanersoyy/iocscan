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
    t.add_column("Status")
    t.add_column("Quota")
    t.add_column("Last 429")

    for p in providers:
        active = p.has_key(config)
        status = (
            "[bold bright_green]* active[/]" if active
            else "[bold bright_red]x missing key[/]"
        )
        kinds = ",".join(sorted(k.value for k in p.supports))
        q = quotas.get(p.name) or QuotaResult(p.name, None, None, "No Key")
        if q.used is not None and q.allowed is not None:
            quota_cell = f"{q.used} / {q.allowed}"
        else:
            quota_cell = q.note or "—"
        h = health.get(p.name)
        if h and h.last_429_at:
            last_429 = datetime.fromtimestamp(h.last_429_at).strftime("%Y-%m-%d %H:%M")
        else:
            last_429 = "—"
        t.add_row(p.name, kinds, status, quota_cell, last_429)

    console.print(t)
