import pytest

from iocscan.ui.themes import (
    DEFAULT_THEME,
    REQUIRED_STYLES,
    THEMES,
    get_theme,
    list_theme_names,
)


def test_four_presets_exist():
    assert set(THEMES.keys()) == {"forensic", "mocha", "solarized-dark", "latte"}


def test_default_theme_is_solarized_dark():
    assert DEFAULT_THEME == "solarized-dark"
    assert DEFAULT_THEME in THEMES


@pytest.mark.parametrize("name", sorted(THEMES.keys()))
def test_every_preset_defines_required_styles(name):
    """Every theme must define the full semantic style vocabulary."""
    theme = THEMES[name]
    defined = set(theme.styles.keys())
    missing = REQUIRED_STYLES - defined
    assert not missing, f"theme {name!r} missing styles: {sorted(missing)}"


def test_get_theme_returns_theme_for_known_name():
    t = get_theme("mocha")
    assert "verdict.malicious" in t.styles


def test_get_theme_raises_on_unknown_name():
    with pytest.raises(ValueError, match="unknown theme"):
        get_theme("nonexistent")


def test_get_theme_error_message_lists_choices():
    """The error message must hint at valid theme names."""
    with pytest.raises(ValueError) as exc:
        get_theme("nope")
    msg = str(exc.value)
    for valid in THEMES:
        assert valid in msg


def test_list_theme_names_is_sorted():
    names = list_theme_names()
    assert names == sorted(names)
    assert set(names) == set(THEMES.keys())


@pytest.mark.parametrize("name", sorted(THEMES.keys()))
def test_every_preset_defines_verdict_styles_with_colors(name):
    """Every verdict style must declare a foreground color (not empty)."""
    theme = THEMES[name]
    for style_name in ("verdict.malicious", "verdict.suspicious",
                       "verdict.clean", "verdict.unknown", "verdict.error"):
        style = theme.styles[style_name]
        # Rich Style objects expose either .color or get_style().color
        # str(style) gives the human-readable representation
        s = str(style)
        assert s, f"{name}.{style_name} produced an empty style"
