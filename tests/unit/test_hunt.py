from __future__ import annotations

import pytest

from iocscan.providers.base import IOCType, Verdict
from iocscan.core.scan import ScanResult
from iocscan.ui.hunt import HUNT_FORMATS, render_hunt


def _scan(ioc, ioc_type, verdict, *, whitelisted=False):
    return ScanResult(
        ioc=ioc, ioc_type=ioc_type, verdict=verdict,
        provider_results=[], responding=1, total=1,
        whitelisted=whitelisted,
    )


# ---- partitioning / scoping ----

def test_all_verdicts_pass_through():
    """Hunt queries include every supplied IOC regardless of verdict —
    triage is the table view's job, hunt is a verbatim translator."""
    scans = [
        _scan("1.1.1.1", IOCType.IP, Verdict.MALICIOUS),
        _scan("2.2.2.2", IOCType.IP, Verdict.CLEAN),
        _scan("3.3.3.3", IOCType.IP, Verdict.UNKNOWN),
        _scan("4.4.4.4", IOCType.IP, Verdict.SUSPICIOUS),
    ]
    out = render_hunt(scans, "splunk-spl")
    for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"):
        assert ip in out


def test_whitelisted_iocs_pass_through():
    """Whitelist clamps the verdict shown to the analyst but does NOT
    suppress the IOC from hunt output — the analyst may still want to
    sweep their SIEM for the term."""
    scans = [_scan("evil.com", IOCType.DOMAIN, Verdict.MALICIOUS, whitelisted=True)]
    out = render_hunt(scans, "splunk-spl")
    assert "evil.com" in out


_EMPTY_MARKERS = {
    "splunk-spl": "```",
    "kql-sentinel": "//",
    "kql-defender": "//",
    "crowdstrike-fql": "//",
    "elastic-eql": "//",
    "elastic-lucene": "//",
    "suricata-ip-rules": "#",
}


def test_empty_input_produces_no_op_comment_for_every_format():
    assert set(_EMPTY_MARKERS) == set(HUNT_FORMATS)
    for fmt, marker in _EMPTY_MARKERS.items():
        out = render_hunt([], fmt)
        assert out.startswith(marker), f"{fmt}: expected {marker!r}, got {out!r}"


# ---- per-emitter shape ----

def test_splunk_spl_groups_ip_domain_url_hash():
    scans = [
        _scan("1.1.1.1", IOCType.IP, Verdict.MALICIOUS),
        _scan("evil.com", IOCType.DOMAIN, Verdict.MALICIOUS),
        _scan("https://evil.com/x", IOCType.URL, Verdict.MALICIOUS),
        _scan("d41d8cd98f00b204e9800998ecf8427e", IOCType.HASH_MD5, Verdict.MALICIOUS),
    ]
    out = render_hunt(scans, "splunk-spl")
    assert "All_Traffic.src IN" in out and "1.1.1.1" in out
    assert "DNS.query IN" in out and "evil.com" in out
    assert 'Web.url="*https://evil.com/x*"' in out
    assert "Processes.process_hash IN" in out
    assert "Filesystem.file_hash IN" in out
    assert "| tstats" in out
    assert "datamodel=Network_Traffic.All_Traffic" in out
    assert out.startswith("```")


def test_kql_sentinel_emits_union_when_multiple_types():
    scans = [
        _scan("1.1.1.1", IOCType.IP, Verdict.MALICIOUS),
        _scan("evil.com", IOCType.DOMAIN, Verdict.MALICIOUS),
    ]
    out = render_hunt(scans, "kql-sentinel")
    assert out.startswith("union")
    assert "DeviceNetworkEvents" in out
    assert "DnsEvents" in out


def test_kql_sentinel_single_type_no_union():
    scans = [_scan("1.1.1.1", IOCType.IP, Verdict.MALICIOUS)]
    out = render_hunt(scans, "kql-sentinel")
    assert not out.startswith("union")
    assert "DeviceNetworkEvents" in out


def test_kql_defender_handles_only_ip_and_url():
    scans = [
        _scan("1.1.1.1", IOCType.IP, Verdict.MALICIOUS),
        _scan("evil.com", IOCType.DOMAIN, Verdict.MALICIOUS),   # ignored by Defender
    ]
    out = render_hunt(scans, "kql-defender")
    assert "RemoteIP" in out
    assert "evil.com" not in out  # Defender query doesn't include the domain


def test_crowdstrike_fql_blocks_per_ioc_type():
    scans = [
        _scan("1.1.1.1", IOCType.IP, Verdict.MALICIOUS),
        _scan("evil.com", IOCType.DOMAIN, Verdict.MALICIOUS),
    ]
    out = render_hunt(scans, "crowdstrike-fql")
    # Two blocks separated by blank line
    blocks = out.split("\n\n")
    assert len(blocks) == 2
    assert any("DnsRequest" in b for b in blocks)
    assert any("NetworkConnectIP4" in b for b in blocks)


def test_elastic_eql_uses_network_keyword():
    scans = [_scan("1.1.1.1", IOCType.IP, Verdict.MALICIOUS)]
    out = render_hunt(scans, "elastic-eql")
    assert out.startswith("network where")
    assert "destination.ip in" in out


def test_elastic_lucene_or_form():
    scans = [
        _scan("1.1.1.1", IOCType.IP, Verdict.MALICIOUS),
        _scan("2.2.2.2", IOCType.IP, Verdict.MALICIOUS),
    ]
    out = render_hunt(scans, "elastic-lucene")
    assert 'destination.ip:("1.1.1.1" OR "2.2.2.2")' in out


def test_suricata_emits_one_rule_per_ip():
    scans = [
        _scan("1.1.1.1", IOCType.IP, Verdict.MALICIOUS),
        _scan("2.2.2.2", IOCType.IP, Verdict.MALICIOUS),
    ]
    out = render_hunt(scans, "suricata-ip-rules")
    rules = [ln for ln in out.split("\n") if ln.startswith("alert ip")]
    assert len(rules) == 2
    # SIDs auto-increment from 9000000
    assert "sid:9000000" in rules[0]
    assert "sid:9000001" in rules[1]


def test_unknown_format_raises():
    scans = [_scan("1.1.1.1", IOCType.IP, Verdict.MALICIOUS)]
    with pytest.raises(ValueError):
        render_hunt(scans, "no-such-format")


# ---- defense-in-depth: SIEM-query injection escape ----

def test_q_dq_escapes_embedded_double_quotes():
    """Even if a quote-bearing string reaches the emitter, it must be
    backslash-escaped so the SIEM parser sees a single literal value."""
    from iocscan.ui.hunt import _q_dq
    crafted = 'evil.com/x" OR url IN ("y'
    out = _q_dq([crafted])
    # The output string is wrapped in double quotes; the inner `"` must be
    # `\"` so the SIEM tokenizer keeps everything inside the same literal.
    assert out == '"evil.com/x\\" OR url IN (\\"y"'


def test_q_sq_escapes_embedded_single_quotes():
    from iocscan.ui.hunt import _q_sq
    crafted = "evil.com/x' OR url='y"
    out = _q_sq([crafted])
    assert out == "'evil.com/x\\' OR url=\\'y'"


def test_q_dq_escapes_backslash_first():
    """A bare `\\"` would otherwise become `\\"\\"` (i.e. valid escape + new
    quote); we must escape backslashes before quotes."""
    from iocscan.ui.hunt import _q_dq
    out = _q_dq(["a\\b"])
    assert out == '"a\\\\b"'
