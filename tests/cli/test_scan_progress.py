from __future__ import annotations

import subprocess
import sys


def test_scan_progress_appears_on_stderr(tmp_path):
    """Smoke test: --format json must NOT print progress (stdout clean), while
    default mode must print at least the "Fetching" string to stderr.
    """
    env = {
        "HOME": str(tmp_path),
        "PATH": "/usr/bin:/bin",
        "PYTHONUNBUFFERED": "1",
    }

    # JSON mode: clean stdout, no progress noise.
    # Use --no-cache so both runs hit providers independently.
    r = subprocess.run(
        [sys.executable, "-m", "iocscan", "--format", "json", "--no-cache", "203.0.113.1"],
        capture_output=True, text=True, env=env, timeout=30,
    )
    assert "Fetching" not in r.stderr
    assert "Fetching" not in r.stdout

    # Default (table) mode against the same unreachable IP: progress appears
    # on stderr. We don't care about the exit code here.
    # --no-cache prevents the first run's cache from suppressing the spinner.
    r = subprocess.run(
        [sys.executable, "-m", "iocscan", "--no-cache", "203.0.113.1"],
        capture_output=True, text=True, env=env, timeout=30,
    )
    assert "Fetching" in r.stderr


from unittest.mock import MagicMock


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
