from __future__ import annotations

from rich.console import Console

from iocscan.ui.console import make_console
from iocscan.ui.table import _border_style
from iocscan.ui.themes import THEMES


def test_every_theme_uses_grey70_for_table_border():
    for name, theme in THEMES.items():
        spec = theme.styles["table.border"]
        rendered = str(spec)
        assert "grey70" in rendered, f"{name} theme has {rendered!r}"


def test_border_style_returns_grey70_with_default_theme():
    console = make_console(no_color=False)
    assert "grey70" in _border_style(console)


def test_border_style_fallback_is_grey70_for_bare_console():
    assert _border_style(Console(color_system=None)) == "grey70"
