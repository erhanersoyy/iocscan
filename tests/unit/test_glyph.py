from iocscan.providers.base import Verdict
from iocscan.ui.glyph import (
    CELL_AUTH_FAIL,
    CELL_HARD_ERROR,
    CELL_NO_RECORD,
    CELL_RATE_LIMITED,
    VERDICT_GLYPH,
    VERDICT_GLYPH_ASCII,
    classify_error,
    classify_error_ascii,
    verdict_glyph,
    whitelist_glyph,
)


def test_every_verdict_has_unicode_glyph():
    """Every Verdict member must map to a non-empty unicode glyph."""
    for v in Verdict:
        assert v in VERDICT_GLYPH
        assert VERDICT_GLYPH[v].strip()


def test_every_verdict_has_ascii_fallback():
    """ASCII fallback must exist for every verdict."""
    for v in Verdict:
        assert v in VERDICT_GLYPH_ASCII
        assert VERDICT_GLYPH_ASCII[v].isascii()


def test_verdict_glyph_helper_respects_ascii_flag():
    assert verdict_glyph(Verdict.MALICIOUS) == "●"
    assert verdict_glyph(Verdict.MALICIOUS, ascii_only=True) == "[!]"


def test_whitelist_glyph_has_ascii_fallback():
    assert whitelist_glyph() == "⚑"
    assert whitelist_glyph(ascii_only=True) == "[WL]"
    assert whitelist_glyph(ascii_only=True).isascii()


def test_classify_error_routes_429_to_rate_limited():
    assert classify_error("429 rate limit") == CELL_RATE_LIMITED
    assert classify_error("HTTP 429") == CELL_RATE_LIMITED


def test_classify_error_routes_auth_to_auth_fail():
    assert classify_error("auth failed") == CELL_AUTH_FAIL
    assert classify_error("401 Unauthorized") == CELL_AUTH_FAIL
    assert classify_error("403 Forbidden") == CELL_AUTH_FAIL


def test_classify_error_falls_back_to_hard_error():
    assert classify_error("network: ConnectError") == CELL_HARD_ERROR
    assert classify_error("parse error") == CELL_HARD_ERROR
    assert classify_error(None) == CELL_HARD_ERROR
    assert classify_error("") == CELL_HARD_ERROR


def test_classify_error_ascii_returns_ascii_chars():
    for msg in ("429 rate limit", "auth failed", "network", None):
        glyph = classify_error_ascii(msg)
        assert glyph.isascii()


def test_cell_semantics_are_distinct():
    """All 5 cell-semantic glyphs must be visually distinct."""
    glyphs = {CELL_NO_RECORD, "·", CELL_HARD_ERROR, CELL_RATE_LIMITED, CELL_AUTH_FAIL}
    assert len(glyphs) == 5
