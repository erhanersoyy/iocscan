"""Glyph + cell-semantics mapping for the table and footer.

Every verdict signal is encoded along three channels (color + glyph + word)
so output remains readable when any one channel is unavailable (NO_COLOR,
narrow terminals, screen readers).

Cell semantics (5-way) distinguishes how a provider responded, beyond the
verdict itself: blocklist miss vs inconclusive vs hard error vs rate
limit vs auth fail. This lets a SOC analyst tell "didn't run" from
"ran and saw nothing" at a glance. Not-applicable (provider doesn't
support this IOC type) is rendered as the plain word "n/a", not a glyph,
so the middle-dot is never overloaded against the UNKNOWN verdict.
"""
from __future__ import annotations

from iocscan.providers.base import Verdict

# ----- Verdict glyphs ----------------------------------------------------

# UNKNOWN has no glyph on purpose: it is the weakest verdict (insufficient
# coverage) and is shown as the plain colored word "unknown". Giving it the
# middle-dot collided with the not-applicable cell marker, so it relies on
# the color + word channels instead.
VERDICT_GLYPH: dict[Verdict, str] = {
    Verdict.MALICIOUS:  "●",
    Verdict.SUSPICIOUS: "◐",
    Verdict.CLEAN:      "○",
    Verdict.UNKNOWN:    "",
    Verdict.ERROR:      "✗",
}

VERDICT_GLYPH_ASCII: dict[Verdict, str] = {
    Verdict.MALICIOUS:  "[!]",
    Verdict.SUSPICIOUS: "[~]",
    Verdict.CLEAN:      "[ ]",
    Verdict.UNKNOWN:    "",
    Verdict.ERROR:      "[x]",
}

# Rich theme-style key per verdict — shared by the table and the summary footer.
VERDICT_STYLES: dict[Verdict, str] = {
    Verdict.MALICIOUS:  "verdict.malicious",
    Verdict.SUSPICIOUS: "verdict.suspicious",
    Verdict.CLEAN:      "verdict.clean",
    Verdict.UNKNOWN:    "verdict.unknown",
    Verdict.ERROR:      "verdict.error",
}

WHITELIST_GLYPH = "⚑"
WHITELIST_GLYPH_ASCII = "[WL]"


def verdict_glyph(v: Verdict, *, ascii_only: bool = False) -> str:
    return (VERDICT_GLYPH_ASCII if ascii_only else VERDICT_GLYPH)[v]


def verdict_label(v: Verdict, *, ascii_only: bool = False) -> str:
    """Glyph + word, or just the word when the verdict has no glyph (UNKNOWN)."""
    glyph = verdict_glyph(v, ascii_only=ascii_only)
    return f"{glyph} {v.value}" if glyph else v.value


def whitelist_glyph(*, ascii_only: bool = False) -> str:
    return WHITELIST_GLYPH_ASCII if ascii_only else WHITELIST_GLYPH


# ----- 5-way cell semantics ----------------------------------------------
# Used in the transposed (--wide) grid when a provider responded but produced
# no numeric score, or failed in a specific way. The compact table uses the
# same labels through its "Details" column.

CELL_NO_RECORD       = "—"     # provider ran, no hit / score 0 — votes CLEAN
CELL_UNKNOWN         = "?"     # provider responded but verdict is inconclusive
CELL_HARD_ERROR      = "✗"     # generic failure (network, parse, 5xx)
CELL_RATE_LIMITED    = "▲"     # 429 — retryable
CELL_AUTH_FAIL       = "⚡"     # 401/403 — fixable by user

CELL_NO_RECORD_ASCII    = "-"
CELL_UNKNOWN_ASCII      = "?"
CELL_HARD_ERROR_ASCII   = "x"
CELL_RATE_LIMITED_ASCII = "!"
CELL_AUTH_FAIL_ASCII    = "@"


def classify_error(error_msg: str | None) -> str:
    """Map a ProviderResult.error string to one of the 5-way cell glyphs.

    Falls back to CELL_HARD_ERROR for unrecognised messages.
    """
    if not error_msg:
        return CELL_HARD_ERROR
    msg = error_msg.lower()
    if "429" in msg or "rate limit" in msg:
        return CELL_RATE_LIMITED
    if "auth" in msg or "401" in msg or "403" in msg:
        return CELL_AUTH_FAIL
    return CELL_HARD_ERROR


def classify_error_ascii(error_msg: str | None) -> str:
    g = classify_error(error_msg)
    return {
        CELL_HARD_ERROR:   CELL_HARD_ERROR_ASCII,
        CELL_RATE_LIMITED: CELL_RATE_LIMITED_ASCII,
        CELL_AUTH_FAIL:    CELL_AUTH_FAIL_ASCII,
    }[g]
