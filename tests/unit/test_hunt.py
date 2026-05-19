from __future__ import annotations

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

def test_only_malicious_and_suspicious_are_kept():
    scans = [
        _scan("1.1.1.1", IOCType.IP, Verdict.MALICIOUS),
        _scan("2.2.2.2", IOCType.IP, Verdict.CLEAN),
        _scan("3.3.3.3", IOCType.IP, Verdict.UNKNOWN),
        _scan("4.4.4.4", IOCType.IP, Verdict.SUSPICIOUS),
    ]
    out = render_hunt(scans, "splunk-spl")
    assert "1.1.1.1" in out
    assert "4.4.4.4" in out
    assert "2.2.2.2" not in out
    assert "3.3.3.3" not in out


def test_whitelisted_iocs_are_excluded():
    scans = [_scan("evil.com", IOCType.DOMAIN, Verdict.MALICIOUS, whitelisted=True)]
    out = render_hunt(scans, "splunk-spl")
    assert "evil.com" not in out
    assert "no IOCs" in out


def test_empty_input_produces_no_op_comment_for_every_format():
    for fmt in HUNT_FORMATS:
        out = render_hunt([], fmt)
        # Format-appropriate comment marker:
        assert out.startswith(("//", "#"))


# ---- per-emitter shape ----

def test_splunk_spl_groups_ip_domain_url_hash():
    scans = [
        _scan("1.1.1.1", IOCType.IP, Verdict.MALICIOUS),
        _scan("evil.com", IOCType.DOMAIN, Verdict.MALICIOUS),
        _scan("https://evil.com/x", IOCType.URL, Verdict.MALICIOUS),
        _scan("d41d8cd98f00b204e9800998ecf8427e", IOCType.HASH_MD5, Verdict.MALICIOUS),
    ]
    out = render_hunt(scans, "splunk-spl")
    assert "src_ip IN" in out and "1.1.1.1" in out
    assert "dns_query IN" in out and "evil.com" in out
    assert "url IN" in out
    assert "file_hash IN" in out
    assert out.startswith("index=* earliest=-90d")


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
    import pytest
    scans = [_scan("1.1.1.1", IOCType.IP, Verdict.MALICIOUS)]
    with pytest.raises(ValueError):
        render_hunt(scans, "no-such-format")
