from __future__ import annotations

from iocscan.ui.field_filter import apply_filter


_BASE = {
    "scan": {"timestamp": "2026-05-19T12:00:00Z", "tool_version": "0.1.2"},
    "results": [
        {
            "ioc": "1.2.3.4",
            "type": "ip",
            "verdict": "malicious",
            "providers": {
                "virustotal": {"verdict": "malicious", "score": "12/70"},
                "otx":        {"verdict": "clean",     "score": "0 pulses"},
            },
        },
        {
            "ioc": "evil.com",
            "type": "domain",
            "verdict": "clean",
            "providers": {
                "virustotal": {"verdict": "clean", "score": "0/70"},
            },
        },
    ],
}


def test_no_filters_returns_payload_unchanged():
    assert apply_filter(_BASE, [], []) == _BASE


def test_include_picks_top_level_keys():
    out = apply_filter(_BASE, ["scan", "results.*.ioc"], [])
    assert out["scan"]["tool_version"] == "0.1.2"
    assert out["results"][0]["ioc"] == "1.2.3.4"
    assert "verdict" not in out["results"][0]
    assert "providers" not in out["results"][0]


def test_include_deep_path_picks_nested_field():
    out = apply_filter(_BASE, ["results.*.providers.virustotal.score"], [])
    assert out["results"][0]["providers"]["virustotal"]["score"] == "12/70"
    assert "verdict" not in out["results"][0]["providers"]["virustotal"]
    assert "otx" not in out["results"][0]["providers"]


def test_exclude_drops_path():
    out = apply_filter(_BASE, [], ["results.*.providers.otx"])
    assert "otx" not in out["results"][0]["providers"]
    assert "virustotal" in out["results"][0]["providers"]


def test_include_then_exclude_compose():
    out = apply_filter(
        _BASE,
        ["results.*.ioc", "results.*.verdict", "results.*.providers.virustotal"],
        ["results.*.providers.virustotal.verdict"],
    )
    assert out["results"][0]["providers"]["virustotal"] == {"score": "12/70"}


def test_missing_path_is_silently_ignored():
    out = apply_filter(_BASE, ["results.*.nope"], [])
    assert out["results"] == [{}, {}]  # outer shape preserved, no error


def test_star_only_at_list_positions():
    """A bare key path must not match list indices."""
    # `results.0.ioc` (with literal "0" rather than "*") should NOT work for lists.
    # We use `*` for any list index.
    out = apply_filter(_BASE, ["results.0.ioc"], [])
    # `0` isn't a key inside dicts; the list isn't traversed. Result is empty list.
    assert out.get("results", []) == []


def test_exclude_does_not_mutate_input():
    """apply_filter must not mutate the caller's payload."""
    snapshot = {
        "results": [{"ioc": "1.2.3.4", "providers": {"otx": {"score": "0"}}}],
    }
    apply_filter(snapshot, [], ["results.*.providers.otx"])
    assert snapshot["results"][0]["providers"]["otx"] == {"score": "0"}


def test_empty_path_segments_are_skipped():
    """Stray empty segments from a trailing/leading comma must not blow up."""
    out = apply_filter(_BASE, ["", "results.*.ioc"], [""])
    assert out["results"][0]["ioc"] == "1.2.3.4"
