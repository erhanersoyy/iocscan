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


def test_cli_file_not_found_exits_3_with_clean_message(tmp_home, capsys, tmp_path):
    """-f with a non-existent path must exit 3 with a friendly stderr message,
    not a Python traceback."""
    missing = tmp_path / "does_not_exist.txt"
    rc = main(["-f", str(missing)])
    captured = capsys.readouterr()
    assert rc == 3
    assert "Traceback" not in captured.err
    assert "file not found" in captured.err.lower()
    assert str(missing) in captured.err


def test_cli_file_is_directory_exits_3(tmp_home, capsys, tmp_path):
    """-f with a directory path must exit 3 with a clear message."""
    rc = main(["-f", str(tmp_path)])
    captured = capsys.readouterr()
    assert rc == 3
    assert "Traceback" not in captured.err
    assert "not a file" in captured.err.lower() or "directory" in captured.err.lower()


def test_cli_file_unreadable_exits_3(tmp_home, capsys, tmp_path):
    """-f with an unreadable file must exit 3."""
    import os
    if os.geteuid() == 0:
        pytest.skip("root bypasses file permissions")
    f = tmp_path / "secret.txt"
    f.write_text("8.8.8.8\n")
    f.chmod(0o000)
    try:
        rc = main(["-f", str(f)])
        captured = capsys.readouterr()
        assert rc == 3
        assert "Traceback" not in captured.err
        assert "permission" in captured.err.lower()
    finally:
        f.chmod(0o600)  # restore so tmp_path cleanup works


def test_cli_file_too_large_exits_3(tmp_home, capsys, tmp_path, monkeypatch):
    """-f with a file larger than the 50 MiB cap must exit 3, not OOM the process."""
    from iocscan import cli as cli_mod
    monkeypatch.setattr(cli_mod, "_MAX_INPUT_BYTES", 64)  # lower cap for the test
    big = tmp_path / "big.txt"
    big.write_text("8.8.8.8\n" * 50)  # > 64 bytes
    rc = main(["-f", str(big)])
    captured = capsys.readouterr()
    assert rc == 3
    assert "too large" in captured.err.lower()


def test_cli_file_symlink_refused_exits_3(tmp_home, capsys, tmp_path):
    """-f with a symlinked input file must exit 3 — mirrors the cache.db symlink guard."""
    target = tmp_path / "real.txt"
    target.write_text("8.8.8.8\n")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    rc = main(["-f", str(link)])
    captured = capsys.readouterr()
    assert rc == 3
    assert "Traceback" not in captured.err
    assert "symlink" in captured.err.lower()


def test_cli_file_binary_exits_3(tmp_home, capsys, tmp_path):
    """-f with a non-UTF-8 file must exit 3, not crash with UnicodeDecodeError."""
    f = tmp_path / "binary.bin"
    f.write_bytes(b"\xff\xfe\x00\x01garbage\x80\x81")
    rc = main(["-f", str(f)])
    captured = capsys.readouterr()
    assert rc == 3
    assert "Traceback" not in captured.err
    assert "utf-8" in captured.err.lower() or "encoding" in captured.err.lower()


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


# --- PR #4 format matrix ---

def test_cli_format_csv_emits_header(tmp_home, mock_provider_responses, capsys):
    rc = main(["--format", "csv", "8.8.8.8"])
    out = capsys.readouterr().out
    assert out.splitlines()[0] == "ioc,type,verdict,responding,total,whitelisted"
    assert rc == 0


def test_cli_format_jsonl_one_line_per_ioc(tmp_home, mock_provider_responses, capsys):
    rc = main(["--format", "jsonl", "8.8.8.8"])
    out = capsys.readouterr().out
    lines = [ln for ln in out.splitlines() if ln.strip()]
    assert len(lines) == 1
    import json as _json
    obj = _json.loads(lines[0])
    assert obj["ioc"] == "8.8.8.8"


def test_cli_format_markdown_emits_table(tmp_home, mock_provider_responses, capsys):
    rc = main(["--format", "markdown", "8.8.8.8"])
    out = capsys.readouterr().out
    assert "| IOC |" in out
    assert "|---|" in out


def test_cli_legacy_json_flag_still_works(tmp_home, mock_provider_responses, capsys):
    rc = main(["--json", "8.8.8.8"])
    captured = capsys.readouterr()
    # --json continues to produce pretty JSON on stdout (quoted key proves it)
    assert "\"ioc\":" in captured.out
    # …and emits a deprecation warning to stderr
    assert "deprecated" in captured.err


def test_cli_format_json_canonical_emits_pretty_json(tmp_home, mock_provider_responses, capsys):
    """The non-deprecated `--format json` form must emit pretty JSON with no warning."""
    rc = main(["--format", "json", "8.8.8.8"])
    captured = capsys.readouterr()
    assert "\"ioc\":" in captured.out
    assert "deprecated" not in captured.err


def test_cli_quiet_suppresses_json_deprecation_warning(tmp_home, mock_provider_responses, capsys):
    """--quiet wins over everything: no deprecation noise even when --json is set."""
    rc = main(["--quiet", "--json", "8.8.8.8"])
    captured = capsys.readouterr()
    # TSV output, no JSON
    assert "\t" in captured.out
    assert "\"ioc\":" not in captured.out
    # And no deprecation warning leaked to stderr
    assert "deprecated" not in captured.err


def test_cli_json_with_format_csv_rejected(tmp_home, mock_provider_responses, capsys):
    """Combining --json with a non-default --format is contradictory and must exit 3."""
    rc = main(["--json", "--format", "csv", "8.8.8.8"])
    captured = capsys.readouterr()
    assert rc == 3
    assert "conflict" in captured.err.lower()


def test_cli_quiet_overrides_format(tmp_home, mock_provider_responses, capsys):
    """--quiet wins over --format (low-noise contract)."""
    rc = main(["--quiet", "--format", "csv", "8.8.8.8"])
    out = capsys.readouterr().out
    # TSV: tab-separated, not CSV header
    assert "\t" in out
    assert "ioc,type" not in out


def test_cli_links_only_emits_tsv(tmp_home, mock_provider_responses, capsys):
    """--links-only emits IOC\\tprovider\\tpermalink and suppresses the table."""
    rc = main(["--links-only", "--no-cache", "1.2.3.4"])
    out = capsys.readouterr().out
    lines = [ln for ln in out.split("\n") if ln.strip()]
    assert lines, "expected at least one IOC\\tprovider\\tpermalink line"
    for ln in lines:
        parts = ln.split("\t")
        assert len(parts) == 3, f"expected 3 columns, got: {ln!r}"
        assert parts[0] == "1.2.3.4"
        assert parts[2].startswith("http")
    # Table glyphs / box characters must not leak in.
    assert "┳" not in out
    assert "│" not in out


def test_cli_links_only_skips_providers_without_permalink(tmp_home, mock_provider_responses, capsys):
    """Providers with no permalink (Feodo/Spamhaus/Tor) must not appear."""
    rc = main(["--links-only", "--no-cache", "1.2.3.4"])
    out = capsys.readouterr().out
    for offender in ("feodo", "spamhaus", "\ttor\t"):
        assert offender not in out


def test_cli_include_filter_keeps_only_specified_paths(tmp_home, mock_provider_responses, capsys):
    """--include drops every key not on the include list."""
    rc = main([
        "--format", "json",
        "--include", "results.*.ioc,results.*.verdict",
        "--no-cache",
        "1.2.3.4",
    ])
    out = capsys.readouterr().out
    payload = json.loads(out)
    # `scan` block stripped, only `results` survives.
    assert "scan" not in payload
    r = payload["results"][0]
    assert set(r.keys()) <= {"ioc", "verdict"}
    assert r["ioc"] == "1.2.3.4"


def test_cli_exclude_filter_drops_paths(tmp_home, mock_provider_responses, capsys):
    """--exclude removes the listed sub-trees but keeps everything else."""
    rc = main([
        "--format", "json",
        "--exclude", "results.*.providers",
        "--no-cache",
        "1.2.3.4",
    ])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert "providers" not in payload["results"][0]
    # Other top-level fields stay.
    assert payload["results"][0]["ioc"] == "1.2.3.4"
    assert "verdict" in payload["results"][0]


def test_cli_include_exclude_compose(tmp_home, mock_provider_responses, capsys):
    """--include picks the subtree, then --exclude prunes from within it."""
    rc = main([
        "--format", "json",
        "--include", "results.*.ioc,results.*.verdict,results.*.coverage",
        "--exclude", "results.*.coverage.total",
        "--no-cache",
        "1.2.3.4",
    ])
    out = capsys.readouterr().out
    payload = json.loads(out)
    r = payload["results"][0]
    assert "responding" in r["coverage"]
    assert "total" not in r["coverage"]
