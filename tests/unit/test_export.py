import csv
import io
import json

import pytest

from iocscan.core.scan import ScanResult
from iocscan.providers.base import IOCType, Verdict
from iocscan.ui.export import EXPORT_FORMATS, render_export


def _scan(ioc, verdict, ioc_type=IOCType.IP, responding=5, total=9, whitelisted=False):
    return ScanResult(ioc, ioc_type, verdict, [], responding, total, whitelisted=whitelisted)


# --- jsonl ---------------------------------------------------------------

def test_jsonl_one_object_per_line():
    out = render_export(
        [_scan("1.1.1.1", Verdict.CLEAN), _scan("evil.com", Verdict.MALICIOUS, IOCType.DOMAIN)],
        "jsonl",
    )
    lines = out.splitlines()
    assert len(lines) == 2
    obj0 = json.loads(lines[0])
    obj1 = json.loads(lines[1])
    assert obj0["ioc"] == "1.1.1.1"
    assert obj1["ioc"] == "evil.com"
    assert obj0["coverage"]["responding"] == 5


def test_jsonl_respects_defang():
    out = render_export([_scan("evil.com", Verdict.CLEAN, IOCType.DOMAIN)], "jsonl", defang=True)
    obj = json.loads(out)
    assert obj["ioc"] == "evil[.]com"


def test_jsonl_empty_scans_returns_empty_string():
    assert render_export([], "jsonl") == ""


# --- csv -----------------------------------------------------------------

def test_csv_has_header_and_rows():
    out = render_export(
        [_scan("1.1.1.1", Verdict.CLEAN), _scan("evil.com", Verdict.MALICIOUS, IOCType.DOMAIN)],
        "csv",
    )
    reader = csv.reader(io.StringIO(out))
    rows = list(reader)
    assert rows[0] == ["ioc", "type", "verdict", "responding", "total", "whitelisted"]
    assert rows[1][0] == "1.1.1.1"
    assert rows[2][0] == "evil.com"


def test_csv_quotes_commas_in_iocs():
    """The stdlib csv module must quote any embedded comma."""
    out = render_export([_scan("ev,il.com", Verdict.CLEAN, IOCType.DOMAIN)], "csv")
    # The IOC contains a comma → must appear wrapped in quotes
    assert '"ev,il.com"' in out


def test_csv_prefixes_formula_injection_payloads():
    """Cells starting with =/+/-/@/tab/cr must be defanged with a leading apostrophe.

    Defense-in-depth against spreadsheet formula injection — parse_iocs would
    reject these characters today, but the export layer should not rely on
    upstream filtering.
    """
    for payload in ("=cmd|'/c calc'!A1", "+1+1", "-2+3", "@SUM(A1)", "\t=evil"):
        out = render_export([_scan(payload, Verdict.CLEAN, IOCType.DOMAIN)], "csv")
        reader = csv.reader(io.StringIO(out))
        rows = list(reader)
        assert rows[1][0].startswith("'"), f"payload not prefixed: {payload!r} -> {rows[1][0]!r}"


def test_csv_respects_defang():
    out = render_export([_scan("1.2.3.4", Verdict.CLEAN)], "csv", defang=True)
    reader = csv.reader(io.StringIO(out))
    rows = list(reader)
    assert rows[1][0] == "1[.]2[.]3[.]4"


# --- markdown ------------------------------------------------------------

def test_markdown_has_header_separator_and_rows():
    out = render_export(
        [_scan("1.1.1.1", Verdict.CLEAN, responding=9, total=9),
         _scan("evil.com", Verdict.MALICIOUS, IOCType.DOMAIN, whitelisted=False)],
        "markdown",
    )
    lines = out.splitlines()
    assert lines[0].startswith("| IOC | type | verdict | coverage | whitelisted |")
    assert lines[1] == "|---|---|---|---|---|"
    assert "| 1.1.1.1 |" in lines[2]
    assert "| evil.com |" in lines[3]


def test_markdown_whitelisted_renders_yes_no():
    out = render_export(
        [_scan("a", Verdict.CLEAN, whitelisted=True),
         _scan("b", Verdict.CLEAN, whitelisted=False)],
        "markdown",
    )
    lines = out.splitlines()
    assert "| yes |" in lines[2]
    assert "| no |" in lines[3]


def test_markdown_respects_defang():
    out = render_export([_scan("apple.com", Verdict.CLEAN, IOCType.DOMAIN)], "markdown", defang=True)
    assert "| apple[.]com |" in out


# --- dispatcher ----------------------------------------------------------

def test_unknown_format_raises():
    with pytest.raises(ValueError, match="unknown export format"):
        render_export([_scan("a", Verdict.CLEAN)], "weird")


def test_export_formats_constant_matches_supported():
    """EXPORT_FORMATS must list every format render_export accepts."""
    for fmt in EXPORT_FORMATS:
        # should not raise
        render_export([_scan("a", Verdict.CLEAN)], fmt)
