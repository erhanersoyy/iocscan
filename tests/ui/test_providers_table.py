from __future__ import annotations

from io import StringIO

from rich.console import Console

from iocscan.core.config import Config
from iocscan.core.observability import ProviderHealth
from iocscan.core.quota import QuotaResult
from iocscan.providers.shodan_internetdb import ShodanInternetDB
from iocscan.providers.virustotal import VirusTotal
from iocscan.ui.providers_table import render_providers_table


def _render(providers, config, quotas, health):
    buf = StringIO()
    # color_system="truecolor" + force_terminal so style markup actually emits
    # ANSI; that lets us assert green/red highlight markers in the output.
    console = Console(file=buf, width=120, force_terminal=True, color_system="truecolor")
    render_providers_table(providers, config, quotas, health, console)
    return buf.getvalue()


def test_active_provider_renders_green(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    cfg = Config(keys={"virustotal": "x"})
    quotas = {"virustotal": QuotaResult("virustotal", 10, 500, "")}
    out = _render([VirusTotal()], cfg, quotas, {})
    assert "active" in out
    assert "\x1b[" in out and "92" in out


def test_missing_key_renders_red(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    cfg = Config()
    quotas = {"virustotal": QuotaResult("virustotal", None, None, "No Key")}
    out = _render([VirusTotal()], cfg, quotas, {})
    assert "missing key" in out
    assert "No Key" in out
    assert "91" in out


def test_quota_shows_used_over_allowed(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    cfg = Config(keys={"virustotal": "x"})
    quotas = {"virustotal": QuotaResult("virustotal", 142, 500, "")}
    out = _render([VirusTotal()], cfg, quotas, {})
    assert "142 / 500" in out


def test_anonymous_provider_shows_no_key_quota(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    cfg = Config()
    quotas = {"shodan_internetdb": QuotaResult("shodan_internetdb", None, None, "No Key")}
    out = _render([ShodanInternetDB()], cfg, quotas, {})
    assert "active" in out  # requires_key=False → always active
    assert "No Key" in out


def test_last_429_column_shows_timestamp_or_dash(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    cfg = Config(keys={"virustotal": "x"})
    quotas = {"virustotal": QuotaResult("virustotal", 0, 500, "")}
    health = {"virustotal": ProviderHealth(
        provider="virustotal", samples=10, error_count=1,
        error_rate=0.1, last_error_at=None, last_429_at=1700000000,
        last_5xx_at=None, p95_latency_ms=120,
    )}
    out = _render([VirusTotal()], cfg, quotas, health)
    assert "2023-11" in out

    out2 = _render([VirusTotal()], cfg, quotas, {})
    assert "—" in out2 or "-" in out2


def test_box_is_ascii_only(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    cfg = Config()
    quotas = {"virustotal": QuotaResult("virustotal", None, None, "No Key")}
    out = _render([VirusTotal()], cfg, quotas, {})
    for ch in ("┌", "─", "│", "└", "┐", "┘", "┬", "┴", "├", "┤", "┼"):
        assert ch not in out
