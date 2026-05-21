from __future__ import annotations

import subprocess
import sys


def test_providers_subcommand_emits_ascii_table(tmp_path):
    """End-to-end: `iocscan providers` produces an ASCII-bordered table.

    Run with HOME=tmp_path so no API keys are configured — every provider
    should render as 'missing key' (red) or 'active' (anonymous providers).
    """
    env = {"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"}
    r = subprocess.run(
        [sys.executable, "-m", "iocscan", "providers"],
        capture_output=True, text=True, env=env, timeout=60,
    )
    assert r.returncode == 0, r.stderr

    # ASCII box only: no unicode box-drawing chars.
    for ch in ("┌", "─", "│", "└", "┐", "┘"):
        assert ch not in r.stdout, f"found {ch!r}"

    # Status column populated for at least one anonymous and one keyed provider.
    assert "active" in r.stdout      # e.g. shodan_internetdb (anonymous)
    assert "missing key" in r.stdout # e.g. virustotal (no key configured)

    # New columns present.
    assert "Quota" in r.stdout
    assert "Last 429" in r.stdout


def test_providers_subcommand_shows_fetching_spinner_when_keys_present(tmp_path):
    """When at least one probeable key is configured, the spinner text
    'Fetching provider quotas' must appear on stderr."""
    env = {
        "HOME": str(tmp_path),
        "PATH": "/usr/bin:/bin",
        "IOCSCAN_VT_KEY": "deadbeef-not-real",
    }
    r = subprocess.run(
        [sys.executable, "-m", "iocscan", "providers"],
        capture_output=True, text=True, env=env, timeout=60,
    )
    # The probe will fail (fake key), but the spinner text must still flash.
    assert "Fetching provider quotas" in r.stderr or "Fetching" in r.stderr
