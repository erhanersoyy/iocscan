from __future__ import annotations

import os
import pty
import select
import subprocess
import sys
import time
from unittest.mock import MagicMock


def test_json_mode_has_no_progress_on_stderr(tmp_path):
    """JSON mode must not print 'Fetching' anywhere (stdout or stderr)."""
    env = {
        "HOME": str(tmp_path),
        "PATH": "/usr/bin:/bin",
        "PYTHONUNBUFFERED": "1",
    }
    r = subprocess.run(
        [sys.executable, "-m", "iocscan", "--no-cache", "--format", "json", "203.0.113.1"],
        capture_output=True, text=True, env=env, timeout=30,
    )
    assert "Fetching" not in r.stderr
    assert "Fetching" not in r.stdout


def test_table_mode_emits_progress_to_stderr_under_pty(tmp_path):
    """With a real PTY on stderr, table-mode must emit the 'Fetching' marker."""
    env = {
        "HOME": str(tmp_path),
        "PATH": "/usr/bin:/bin",
        "PYTHONUNBUFFERED": "1",
        "TERM": "xterm-256color",
    }

    # Give the subprocess a pty as its stderr. Stdout stays a normal pipe so we
    # can ignore the (potentially incomplete) table output.
    err_master, err_slave = pty.openpty()
    proc = subprocess.Popen(
        [sys.executable, "-m", "iocscan", "--no-cache", "203.0.113.1"],
        stdout=subprocess.PIPE, stderr=err_slave, env=env,
    )
    os.close(err_slave)
    captured = bytearray()
    try:
        # Drain the pty until the process exits or we time out.
        deadline = time.time() + 30
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


def test_progress_disabled_when_json_or_quiet():
    """The progress wrapper must respect args.format=='json' and args.quiet."""
    from iocscan.cli import _progress_enabled

    args = MagicMock(format="json", quiet=False, debug=False, json=False)
    assert _progress_enabled(args) is False

    args = MagicMock(format="table", quiet=True, debug=False, json=False)
    assert _progress_enabled(args) is False

    args = MagicMock(format="table", quiet=False, debug=True, json=False)
    assert _progress_enabled(args) is False

    args = MagicMock(format="table", quiet=False, debug=False, json=True)
    assert _progress_enabled(args) is False

    args = MagicMock(format="table", quiet=False, debug=False, json=False)
    assert _progress_enabled(args) is True
