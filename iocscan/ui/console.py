"""Single entry point for building a rich.Console.

Centralizes the NO_COLOR / FORCE_COLOR / --no-color / --ascii contract so
the rest of the codebase never instantiates Console() directly.

Precedence (highest wins):
    --no-color flag  >  FORCE_COLOR env  >  NO_COLOR env  >  rich auto-detect
"""
from __future__ import annotations

import os
import sys

from rich.console import Console


def make_console(
    *,
    no_color: bool = False,
    ascii_only: bool = False,
    stderr: bool = False,
) -> Console:
    file = sys.stderr if stderr else sys.stdout
    if no_color or os.environ.get("NO_COLOR"):
        return Console(file=file, no_color=True, force_terminal=None)
    if os.environ.get("FORCE_COLOR"):
        return Console(file=file, force_terminal=True)
    # rich auto-detect handles isatty / dumb terminals / piped output.
    return Console(file=file, legacy_windows=ascii_only)
