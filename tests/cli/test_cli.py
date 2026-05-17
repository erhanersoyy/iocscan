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
