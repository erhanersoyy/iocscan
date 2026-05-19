"""Tests for `iocscan explain <ioc>`."""
from __future__ import annotations

import httpx
import pytest

from iocscan.cli import main


@pytest.fixture
def mock_provider_responses(monkeypatch):
    """All providers return empty/clean — same shape as the cli tests use."""
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
    monkeypatch.setattr(
        cli,
        "_make_client",
        lambda timeout: httpx.AsyncClient(
            transport=httpx.MockTransport(handler), timeout=timeout
        ),
    )


def test_explain_rejects_invalid_ioc(tmp_home, capsys):
    rc = main(["explain", "not-an-ioc"])
    err = capsys.readouterr().err
    assert rc == 3
    assert "invalid IOC" in err


def test_explain_renders_per_provider_and_math_panels(tmp_home, mock_provider_responses, capsys):
    rc = main(["explain", "8.8.8.8"])
    out = capsys.readouterr().out
    # Per-provider panel(s) rendered.
    assert "virustotal" in out or "feodo" in out or "spamhaus" in out
    # Aggregation math panel always renders.
    assert "aggregation math" in out
    assert "final verdict" in out
    # Verdict-driven exit code — any of clean/malicious/suspicious/unknown is fine.
    assert rc in (0, 1, 2, 5)


def test_explain_math_panel_shows_weights(tmp_home, mock_provider_responses, capsys):
    main(["explain", "8.8.8.8"])
    out = capsys.readouterr().out
    assert "weights:" in out
    assert "voting:" in out
