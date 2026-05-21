from __future__ import annotations

import pytest

from iocscan.providers.base import ProviderResult, Verdict


def test_details_defaults_to_empty_tuple():
    r = ProviderResult("vt", Verdict.CLEAN, "0/90", None, None, 12)
    assert r.details == ()


def test_details_accepts_tuple_of_strings():
    r = ProviderResult(
        "shodan_internetdb", Verdict.CLEAN, "3 ports",
        {"ports": [22, 80, 443]}, None, 42,
        details=("ports: 22, 80, 443", "tags: cdn"),
    )
    assert r.details == ("ports: 22, 80, 443", "tags: cdn")


def test_provider_result_is_frozen():
    r = ProviderResult("vt", Verdict.CLEAN, "", None, None, 1)
    with pytest.raises(Exception):
        r.details = ("x",)  # type: ignore[misc]
