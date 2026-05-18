import io
import json
import sys
from unittest.mock import patch

import httpx
import pytest

from iocscan.cli import main


@pytest.fixture
def mock_provider_responses(monkeypatch):
    """Replace the shared client factory with a MockTransport handler."""
    def handler(req):
        host = str(req.url.host)
        if "urlhaus" in host:
            return httpx.Response(200, content='{"query_status": "no_results"}')
        if "threatfox" in host:
            return httpx.Response(200, content='{"query_status": "no_result"}')
        if "feodotracker" in host:
            return httpx.Response(200, content="[]")
        if "torproject" in host:
            return httpx.Response(200, content="")
        if "spamhaus" in host:
            return httpx.Response(200, content="; empty\n")
        return httpx.Response(200, content="{}")

    from iocscan import cli
    monkeypatch.setattr(cli, "_make_client",
        lambda timeout: httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=timeout))


def test_cli_exit_zero_when_all_clean(tmp_home, mock_provider_responses, capsys):
    rc = main(["8.8.8.8"])
    out = capsys.readouterr().out
    assert "8.8.8.8" in out
    assert rc == 0


def test_cli_json_flag(tmp_home, mock_provider_responses, capsys):
    rc = main(["--json", "8.8.8.8"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["results"][0]["ioc"] == "8.8.8.8"


def test_cli_file_input(tmp_home, mock_provider_responses, tmp_path, capsys):
    f = tmp_path / "iocs.txt"
    f.write_text("8.8.8.8\n# comment line\nevil.com\n")
    rc = main(["-f", str(f)])
    out = capsys.readouterr().out
    assert "8.8.8.8" in out
    assert "evil.com" in out


def test_cli_stdin_input(tmp_home, mock_provider_responses, capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("8.8.8.8\n"))
    rc = main([])
    out = capsys.readouterr().out
    assert "8.8.8.8" in out


def test_cli_invalid_args_exit_3(tmp_home, capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    rc = main([])
    err = capsys.readouterr().err
    assert rc == 3
    assert "no iocs" in err.lower()


def test_cli_debug_emits_per_provider_logs(tmp_home, mock_provider_responses, capsys):
    rc = main(["--debug", "8.8.8.8"])
    err = capsys.readouterr().err
    # debug log should mention provider names and "lookup" / latency
    assert "urlhaus" in err.lower()
    assert "lookup" in err.lower() or "latency" in err.lower() or "ms" in err.lower()


def test_cli_without_debug_quiet_stderr(tmp_home, mock_provider_responses, capsys):
    rc = main(["8.8.8.8"])
    err = capsys.readouterr().err
    # without --debug, no per-provider log noise on stderr (warnings only)
    assert "urlhaus lookup" not in err.lower()


def test_cli_cache_merge_applies_whitelist(tmp_home, mock_provider_responses, monkeypatch, capsys):
    """A whitelisted domain whose results are partially cached should still be clamped to CLEAN."""
    # Pre-populate the cache with a MALICIOUS result for google.com
    import os
    from pathlib import Path
    from iocscan.core.cache import Cache
    from iocscan.providers.base import ProviderResult, Verdict
    cache_path = Path(os.path.expanduser("~")) / ".iocscan" / "cache.db"
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache = Cache(cache_path, ttl_seconds=3600)
    cache.put("google.com", [
        ProviderResult("virustotal", Verdict.MALICIOUS, "10/70", None, None, 10),
        ProviderResult("otx", Verdict.MALICIOUS, "20 pulses", None, None, 10),
    ])
    cache.close()

    rc = main(["--json", "google.com"])
    import json
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["results"][0]["whitelisted"] is True
    assert data["results"][0]["verdict"] == "clean"  # not malicious despite VT+OTX cached


def test_cli_help_includes_security_warning_for_api_keys(tmp_home):
    """Test that --help output warns about insecure CLI API key flags."""
    from iocscan.cli import _build_scan_parser

    parser = _build_scan_parser()
    help_output = parser.format_help()

    # Check that the help output mentions INSECURE or config set for at least one key flag
    assert "INSECURE" in help_output or "config set" in help_output, \
        "Help output should warn about insecure CLI key flags"

    # Check that epilog includes the security note
    assert "Security note" in help_output or "INSECURE" in help_output


# --- PR #3 workflow flags: --quiet, --defang, --sort ---

def test_cli_quiet_emits_tsv_one_line_per_ioc(tmp_home, mock_provider_responses, capsys):
    rc = main(["--quiet", "8.8.8.8"])
    out = capsys.readouterr().out
    lines = [ln for ln in out.splitlines() if ln.strip()]
    assert len(lines) == 1
    parts = lines[0].split("\t")
    assert parts[0] == "8.8.8.8"
    # Second field is the verdict word; third is "responding/total"
    assert "/" in parts[2]


def test_cli_quiet_with_defang_defangs_ioc(tmp_home, mock_provider_responses, capsys):
    rc = main(["--quiet", "--defang", "8.8.8.8"])
    out = capsys.readouterr().out
    assert "8[.]8[.]8[.]8" in out


def test_cli_defang_table_renders_defanged_ioc(tmp_home, mock_provider_responses, capsys):
    rc = main(["--defang", "8.8.8.8"])
    out = capsys.readouterr().out
    # Table view: defanged form must appear
    assert "8[.]8[.]8[.]8" in out


def test_cli_sort_verdict_with_quiet(tmp_home, mock_provider_responses, capsys):
    """--sort verdict should reorder TSV output worst-first.

    With mock providers everything is CLEAN so order is by appearance, but
    verify the flag is accepted and produces output.
    """
    rc = main(["--quiet", "--sort", "verdict", "1.1.1.1", "8.8.8.8"])
    out = capsys.readouterr().out
    assert "1.1.1.1" in out and "8.8.8.8" in out
    assert rc == 0


def test_cli_unknown_sort_key_is_rejected(tmp_home, capsys):
    # argparse choices reject unknown values before reaching scan logic
    with pytest.raises(SystemExit):
        main(["--sort", "weird", "8.8.8.8"])
