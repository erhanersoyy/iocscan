"""Color themes for the terminal UI.

Four built-in presets, each a rich.Theme with the same semantic style
names so call sites just write `[verdict.malicious]…[/]` and let the
selected theme decide the actual color.

Palette sources (all WCAG AA against their intended background):
- forensic       : Ayu Dark-derived; high contrast, "operations room" feel
- mocha          : Catppuccin Mocha; modern pastel-on-dark
- solarized-dark : classic Solarized; cyan/orange swap to avoid green-on-dark
                   "verified safe" connotation
- latte          : Catppuccin Latte; for light terminals

Semantic style names (every preset must define all of these):
    verdict.malicious / suspicious / clean / unknown / error / whitelisted
    table.header / table.border
    provider.name
    muted
"""
from __future__ import annotations

from rich.theme import Theme

DEFAULT_THEME = "solarized-dark"

REQUIRED_STYLES = frozenset({
    "verdict.malicious", "verdict.suspicious", "verdict.clean",
    "verdict.unknown", "verdict.error", "verdict.whitelisted",
    "table.header", "table.border", "provider.name", "muted",
})


THEMES: dict[str, Theme] = {
    "forensic": Theme({
        "verdict.malicious":   "bold #FF5C57",
        "verdict.suspicious":  "#FFB454",
        "verdict.clean":       "#5CCFE6",
        "verdict.unknown":     "#7F8C9F",
        "verdict.error":       "italic #D2A6FF",
        "verdict.whitelisted": "bold bright_white",
        "table.header":        "bold #E6E1CF",
        "table.border":        "grey70",
        "provider.name":       "#95E6CB",
        "muted":               "#5C6773",
    }),
    "mocha": Theme({
        "verdict.malicious":   "bold #F38BA8",
        "verdict.suspicious":  "#FAB387",
        "verdict.clean":       "#94E2D5",
        "verdict.unknown":     "#6C7086",
        "verdict.error":       "italic #CBA6F7",
        "verdict.whitelisted": "bold bright_white",
        "table.header":        "bold #CDD6F4",
        "table.border":        "grey70",
        "provider.name":       "#A6E3A1",
        "muted":               "#6C7086",
    }),
    "solarized-dark": Theme({
        "verdict.malicious":   "bold #DC322F",
        "verdict.suspicious":  "#CB4B16",
        "verdict.clean":       "#2AA198",
        "verdict.unknown":     "#586E75",
        "verdict.error":       "italic #6C71C4",
        "verdict.whitelisted": "bold bright_white",
        "table.header":        "bold #93A1A1",
        "table.border":        "grey70",
        "provider.name":       "#2AA198",
        "muted":               "#586E75",
    }),
    "latte": Theme({
        "verdict.malicious":   "bold #D20F39",
        "verdict.suspicious":  "#FE640B",
        "verdict.clean":       "#179299",
        "verdict.unknown":     "#8C8FA1",
        "verdict.error":       "italic #8839EF",
        "verdict.whitelisted": "bold bright_white",
        "table.header":        "bold #4C4F69",
        "table.border":        "grey70",
        "provider.name":       "#179299",
        "muted":               "#8C8FA1",
    }),
}


def get_theme(name: str) -> Theme:
    """Return the rich.Theme for `name`; raise ValueError on unknown names."""
    if name not in THEMES:
        choices = ", ".join(sorted(THEMES))
        raise ValueError(f"unknown theme {name!r}; choose from: {choices}")
    return THEMES[name]


def list_theme_names() -> list[str]:
    return sorted(THEMES)
