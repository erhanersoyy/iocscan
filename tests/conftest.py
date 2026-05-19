import os
import tempfile
from pathlib import Path

import httpx
import pytest


@pytest.fixture
def tmp_home(monkeypatch):
    """Redirect ~/.iocscan to a temp dir."""
    with tempfile.TemporaryDirectory() as d:
        monkeypatch.setenv("HOME", d)
        monkeypatch.delenv("IOCSCAN_VT_KEY", raising=False)
        monkeypatch.delenv("IOCSCAN_ABUSEIPDB_KEY", raising=False)
        monkeypatch.delenv("IOCSCAN_OTX_KEY", raising=False)
        monkeypatch.delenv("IOCSCAN_GREYNOISE_KEY", raising=False)
        monkeypatch.delenv("IOCSCAN_URLSCAN_KEY", raising=False)
        yield Path(d)


def make_client(handler) -> httpx.AsyncClient:
    """Build an AsyncClient backed by MockTransport for unit tests."""
    transport = httpx.MockTransport(handler)
    return httpx.AsyncClient(transport=transport, timeout=5.0)
