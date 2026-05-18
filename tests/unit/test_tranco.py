import time
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

from iocscan.core import tranco


# ---------------------------------------------------------------------------
# Helpers for mocking httpx.stream
# ---------------------------------------------------------------------------

def _make_stream_resp(status_code: int, content: bytes):
    """Return a Response that mimics what httpx.stream yields."""
    resp = httpx.Response(status_code, stream=httpx.ByteStream(content))
    return resp


@contextmanager
def _fake_stream_cm(resp):
    """Yield a mocked response as a context manager, supporting iter_bytes()."""
    yield resp


# ---------------------------------------------------------------------------
# Cache / age helpers (no HTTP)
# ---------------------------------------------------------------------------

def test_load_cache_missing_returns_empty(tmp_path):
    assert tranco.load_cache(tmp_path / "missing.txt") == set()


def test_load_cache_reads_file(tmp_path):
    p = tmp_path / "tranco.txt"
    p.write_text("google.com\ncloudflare.com\nMICROSOFT.com\n\n")
    assert tranco.load_cache(p) == {"google.com", "cloudflare.com", "microsoft.com"}


def test_cache_age_days_missing(tmp_path):
    assert tranco.cache_age_days(tmp_path / "missing.txt") is None


def test_cache_age_days_recent(tmp_path):
    p = tmp_path / "tranco.txt"
    p.write_text("x.com\n")
    age = tranco.cache_age_days(p)
    assert age == 0


# ---------------------------------------------------------------------------
# fetch_and_save / _latest_list_url — using streaming mocks
# ---------------------------------------------------------------------------

def test_fetch_and_save_writes_domains(tmp_path, monkeypatch):
    csv_body = b"1,google.com\n2,cloudflare.com\n3,microsoft.com\n"
    meta_body = b'{"list_id": "ABC", "available": true, "failed": false}'

    def fake_stream(method, url, **kwargs):
        if "/api/lists/date/" in url:
            return _fake_stream_cm(_make_stream_resp(200, meta_body))
        if "/download/ABC/1000" in url:
            return _fake_stream_cm(_make_stream_resp(200, csv_body))
        return _fake_stream_cm(_make_stream_resp(404, b""))

    monkeypatch.setattr(tranco.httpx, "stream", fake_stream)
    target = tmp_path / "tranco.txt"
    n = tranco.fetch_and_save(path=target)
    assert n == 3
    assert target.exists()
    assert tranco.load_cache(target) == {"google.com", "cloudflare.com", "microsoft.com"}


def test_fetch_and_save_falls_back_to_yesterday(tmp_path, monkeypatch):
    """If today's list is not available, the fetcher tries previous dates."""
    call_count = {"meta": 0}
    csv_body = b"1,example.com\n"

    def fake_stream(method, url, **kwargs):
        if "/api/lists/date/" in url:
            call_count["meta"] += 1
            if call_count["meta"] == 1:
                # today's list unavailable
                return _fake_stream_cm(_make_stream_resp(200, b'{"available": false}'))
            return _fake_stream_cm(
                _make_stream_resp(200, b'{"list_id": "Y2", "available": true, "failed": false}')
            )
        if "/download/Y2/1000" in url:
            return _fake_stream_cm(_make_stream_resp(200, csv_body))
        return _fake_stream_cm(_make_stream_resp(404, b""))

    monkeypatch.setattr(tranco.httpx, "stream", fake_stream)
    target = tmp_path / "tranco.txt"
    n = tranco.fetch_and_save(path=target)
    assert n == 1
    assert call_count["meta"] >= 2


def test_fetch_and_save_no_recent_list_raises(tmp_path, monkeypatch):
    def fake_stream(method, url, **kwargs):
        return _fake_stream_cm(_make_stream_resp(200, b'{"available": false}'))

    monkeypatch.setattr(tranco.httpx, "stream", fake_stream)
    with pytest.raises(ValueError, match="no recent list"):
        tranco.fetch_and_save(path=tmp_path / "x.txt")


def test_tranco_response_too_large_rejected(tmp_path, monkeypatch):
    """A response body exceeding MAX_BODY must raise ValueError.

    Updated to use an actually oversized body via httpx.ByteStream so that
    the streaming byte-counter (not the old header check) is exercised.
    """
    from iocscan.core.tranco import MAX_BODY

    meta_body = b'{"list_id": "BIG", "available": true, "failed": false}'
    oversized_body = b"x" * (MAX_BODY + 1)

    def fake_stream(method, url, **kwargs):
        if "/api/lists/date/" in url:
            return _fake_stream_cm(_make_stream_resp(200, meta_body))
        # CSV download returns a body larger than MAX_BODY
        return _fake_stream_cm(_make_stream_resp(200, oversized_body))

    monkeypatch.setattr(tranco.httpx, "stream", fake_stream)
    with pytest.raises(ValueError, match="too large"):
        tranco.fetch_and_save(path=tmp_path / "tranco.txt")


def test_tranco_meta_response_too_large_raises(tmp_path, monkeypatch):
    """A metadata endpoint that returns a body > MAX_BODY must raise ValueError."""
    from iocscan.core.tranco import MAX_BODY

    oversized_body = b"x" * (MAX_BODY + 1)

    def fake_stream(method, url, **kwargs):
        if "/api/lists/date/" in url:
            return _fake_stream_cm(_make_stream_resp(200, oversized_body))
        return _fake_stream_cm(_make_stream_resp(404, b""))

    monkeypatch.setattr(tranco.httpx, "stream", fake_stream)
    with pytest.raises(ValueError, match="too large"):
        tranco.fetch_and_save(path=tmp_path / "tranco.txt")


def test_tranco_response_no_content_length_still_capped_csv(tmp_path, monkeypatch):
    """CSV body > MAX_BODY with no content-length header must raise ValueError.

    The old header-based check would default to 0 and skip the guard entirely
    (the bypass bug).  The streaming byte-counter must catch it regardless.
    """
    from iocscan.core.tranco import MAX_BODY

    meta_body = b'{"list_id": "BIG", "available": true, "failed": false}'
    # ByteStream-backed response has no content-length header
    oversized_body = b"x" * (MAX_BODY + 1)

    def fake_stream(method, url, **kwargs):
        if "/api/lists/date/" in url:
            return _fake_stream_cm(_make_stream_resp(200, meta_body))
        return _fake_stream_cm(_make_stream_resp(200, oversized_body))

    monkeypatch.setattr(tranco.httpx, "stream", fake_stream)
    with pytest.raises(ValueError, match="too large"):
        tranco.fetch_and_save(path=tmp_path / "tranco.txt")


def test_tranco_response_no_content_length_still_capped_meta(tmp_path, monkeypatch):
    """Metadata body > MAX_BODY with no content-length header must raise ValueError."""
    from iocscan.core.tranco import MAX_BODY

    oversized_body = b"x" * (MAX_BODY + 1)

    def fake_stream(method, url, **kwargs):
        if "/api/lists/date/" in url:
            return _fake_stream_cm(_make_stream_resp(200, oversized_body))
        return _fake_stream_cm(_make_stream_resp(404, b""))

    monkeypatch.setattr(tranco.httpx, "stream", fake_stream)
    with pytest.raises(ValueError, match="too large"):
        tranco.fetch_and_save(path=tmp_path / "tranco.txt")
