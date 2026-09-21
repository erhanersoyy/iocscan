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
import re
import sys

from rich.console import Console
from rich.markup import escape as _markup_escape

from iocscan.ui.themes import DEFAULT_THEME, get_theme

# C0 controls except newline, DEL, C1 controls (U+009B is a one-character CSI)
# and the bidi overrides/isolates that visually reorder a line.
_TERMINAL_CONTROLS = re.compile(r"[\x00-\x09\x0b-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def escape(text: str) -> str:
    """Escape provider text for rich markup *and* for the terminal. Rich's own
    escape handles markup only and passes ESC through, so a hostile tag, PTR
    hostname or WHOIS field could move the cursor and overwrite the verdict.
    Newlines survive: explain's multi-line raw JSON relies on them."""
    return _markup_escape(_TERMINAL_CONTROLS.sub(" ", text))


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
