"""Single entry point for building a rich.Console.

Centralizes the NO_COLOR / FORCE_COLOR / --ascii / --theme contract so
the rest of the codebase never instantiates Console() directly.

Precedence (highest wins):
    NO_COLOR env  >  FORCE_COLOR env  >  rich auto-detect

Theme: if the caller passes a theme name, the corresponding rich.Theme is
attached. NO_COLOR still wins — semantic styles resolve but produce no
ANSI color.
"""
from __future__ import annotations

import os
import sys

from rich.console import Console

from iocscan.ui.themes import DEFAULT_THEME, get_theme


def make_console(
    *,
    ascii_only: bool = False,
    stderr: bool = False,
    theme: str | None = DEFAULT_THEME,
) -> Console:
    file = sys.stderr if stderr else sys.stdout
    rich_theme = get_theme(theme) if theme else None
    if os.environ.get("NO_COLOR"):
        return Console(file=file, no_color=True, theme=rich_theme)
    if os.environ.get("FORCE_COLOR"):
        return Console(file=file, force_terminal=True, theme=rich_theme)
    # rich auto-detect handles isatty / dumb terminals / piped output.
    return Console(file=file, legacy_windows=ascii_only, theme=rich_theme)
