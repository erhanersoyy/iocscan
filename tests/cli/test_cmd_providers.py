from __future__ import annotations

import os
import pty
import select
import subprocess
import sys
import time

import pytest


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
    assert "Rate" in r.stdout and "Limit Hit" in r.stdout


@pytest.mark.network
def test_providers_subcommand_shows_fetching_spinner_when_keys_present_under_pty(tmp_path):
    """When a probeable key is configured, the 'Fetching' spinner text appears
    on stderr. Run under a real PTY so Rich's TTY detection fires."""
    env = {
        "HOME": str(tmp_path),
        "PATH": "/usr/bin:/bin",
        "IOCSCAN_VT_KEY": "deadbeef-not-real",
        "TERM": "xterm-256color",
        "PYTHONUNBUFFERED": "1",
    }
    err_master, err_slave = pty.openpty()
    proc = subprocess.Popen(
        [sys.executable, "-m", "iocscan", "providers"],
        stdout=subprocess.PIPE, stderr=err_slave, env=env,
    )
    os.close(err_slave)
    captured = bytearray()
    try:
        deadline = time.time() + 60
        while True:
            if proc.poll() is not None and not select.select([err_master], [], [], 0)[0]:
                break
            if time.time() > deadline:
                proc.kill()
                break
            rlist, _, _ = select.select([err_master], [], [], 0.5)
            if rlist:
                try:
                    chunk = os.read(err_master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                captured.extend(chunk)
    finally:
        os.close(err_master)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)

    assert b"Fetching" in captured, f"stderr did not contain 'Fetching'; got: {captured!r}"
