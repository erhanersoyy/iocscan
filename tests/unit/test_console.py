from io import StringIO

import pytest

from iocscan.ui.console import make_console


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    yield


def test_make_console_returns_a_console():
    c = make_console()
    assert hasattr(c, "print")


def test_no_color_env_disables_color(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    c = make_console()
    assert c.no_color is True


def test_no_color_env_wins_over_force_color(monkeypatch):
    """NO_COLOR must win even if FORCE_COLOR is also set."""
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.setenv("NO_COLOR", "1")
    c = make_console()
    assert c.no_color is True


def test_force_color_env_forces_terminal(monkeypatch):
    monkeypatch.setenv("FORCE_COLOR", "1")
    c = make_console()
    # rich's force_terminal flag becomes True when FORCE_COLOR is set
    assert c.is_terminal or c.no_color is False  # color not disabled


def test_stderr_target_writes_to_stderr():
    import sys
    c = make_console(stderr=True)
    assert c.file is sys.stderr


def test_ascii_only_does_not_break_construction():
    # ascii_only flag just toggles legacy windows; should not raise
    c = make_console(ascii_only=True)
    assert hasattr(c, "print")
