import time
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

from iocscan.core import tranco


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


def test_fetch_and_save_writes_domains(tmp_path, monkeypatch):
    csv_body = "1,google.com\n2,cloudflare.com\n3,microsoft.com\n"
    meta_body = '{"list_id": "ABC", "available": true, "failed": false}'

    def fake_get(url, **kwargs):
        if "/api/lists/date/" in url:
            return httpx.Response(200, content=meta_body)
        if "/download/ABC/1000" in url:
            return httpx.Response(200, content=csv_body)
        return httpx.Response(404)

    monkeypatch.setattr(tranco.httpx, "get", fake_get)
    target = tmp_path / "tranco.txt"
    n = tranco.fetch_and_save(path=target)
    assert n == 3
    assert target.exists()
    assert tranco.load_cache(target) == {"google.com", "cloudflare.com", "microsoft.com"}


def test_fetch_and_save_falls_back_to_yesterday(tmp_path, monkeypatch):
    """If today's list is not available, the fetcher tries previous dates."""
    call_count = {"meta": 0}
    csv_body = "1,example.com\n"

    def fake_get(url, **kwargs):
        if "/api/lists/date/" in url:
            call_count["meta"] += 1
            if call_count["meta"] == 1:
                # today's list unavailable
                return httpx.Response(200, content='{"available": false}')
            return httpx.Response(200, content='{"list_id": "Y2", "available": true, "failed": false}')
        if "/download/Y2/1000" in url:
            return httpx.Response(200, content=csv_body)
        return httpx.Response(404)

    monkeypatch.setattr(tranco.httpx, "get", fake_get)
    target = tmp_path / "tranco.txt"
    n = tranco.fetch_and_save(path=target)
    assert n == 1
    assert call_count["meta"] >= 2


def test_fetch_and_save_no_recent_list_raises(tmp_path, monkeypatch):
    def fake_get(url, **kwargs):
        return httpx.Response(200, content='{"available": false}')

    monkeypatch.setattr(tranco.httpx, "get", fake_get)
    with pytest.raises(ValueError, match="no recent list"):
        tranco.fetch_and_save(path=tmp_path / "x.txt")
