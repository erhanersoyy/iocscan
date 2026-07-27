"""Hunt-query emitters: turn iocscan results into SIEM/EDR queries.

Every supplied IOC goes into the query regardless of verdict or whitelist
status — triage belongs to the table/JSON view; hunt is a verbatim
IOC → query translator. Empty input yields a single no-op comment.

Exception: suricata-ip-rules is deployed detection content, not a hunt
query, so it emits rules only for malicious/suspicious IOCs.
"""
from __future__ import annotations

from iocscan.core.scan import ScanResult
from iocscan.providers.base import HASH_TYPES, IOCType, Verdict


def render_hunt(scans: list[ScanResult], fmt: str) -> str:
    # Suricata output is deployed detection content, not a hunt query, so it
    # needs the verdicts — every other emitter only needs the IOC strings.
    if fmt == "suricata-ip-rules":
        return _suricata_rules(scans)
    emitter = _EMITTERS.get(fmt)
    if emitter is None:
        raise ValueError(f"unknown hunt format: {fmt!r}")
    return emitter(_partition(scans))


def _partition(scans: list[ScanResult]) -> dict[IOCType, list[str]]:
    out: dict[IOCType, list[str]] = {}
    for s in scans:
        out.setdefault(s.ioc_type, []).append(s.ioc)
    return out


def _has_any(by_type: dict[IOCType, list[str]]) -> bool:
    return any(by_type.values())


def _all_hashes(by: dict[IOCType, list[str]]) -> list[str]:
    return [h for t in HASH_TYPES for h in by.get(t, [])]


# Escape backslashes *before* quotes so a crafted `\"` doesn't survive as
# `\"` (a valid escape + new quote). _detect_url in core/ioc.py already
# rejects unencoded quotes in URL IOCs; we escape here as defense in depth.
_BS = "\\"
_DQ = '"'
_SQ = "'"


def _esc_dq(s: str) -> str:
    return s.replace(_BS, _BS + _BS).replace(_DQ, _BS + _DQ)


def _esc_sq(s: str) -> str:
    return s.replace(_BS, _BS + _BS).replace(_SQ, _BS + _SQ)


def _q_dq(values: list[str]) -> str:
    return ", ".join(f'"{_esc_dq(v)}"' for v in values)


def _q_sq(values: list[str]) -> str:
    return ", ".join(f"'{_esc_sq(v)}'" for v in values)


def _splunk_spl(by: dict[IOCType, list[str]]) -> str:
    """Emit CIM-compliant Splunk hunt SPL via tstats over accelerated datamodels.

    `summariesonly=false` so non-accelerated environments still return results;
    triple-backtick comments because // is SPL2-only and would tokenise as
    literal search terms in classic SPL1.
    """
    if not _has_any(by):
        return "``` no IOCs to hunt ```"

    ips = by.get(IOCType.IP, [])
    domains = by.get(IOCType.DOMAIN, [])
    urls = by.get(IOCType.URL, [])
    hashes = _all_hashes(by)

    blocks: list[str] = [
        "``` iocscan hunt — earliest=-90d, summariesonly=false ```",
    ]

    if ips:
        lst = _q_dq(ips)
        blocks.append(_tstats_block(
            "Network_Traffic", "All_Traffic",
            f"(All_Traffic.src IN ({lst}) OR All_Traffic.dest IN ({lst}))",
            ["All_Traffic.src", "All_Traffic.dest", "All_Traffic.dest_port", "sourcetype"],
        ))

    if domains:
        blocks.append(_tstats_block(
            "Network_Resolution", "DNS",
            f"DNS.query IN ({_q_dq(domains)})",
            ["DNS.src", "DNS.query", "DNS.answer", "DNS.record_type"],
        ))

    if urls:
        # `*X*` already matches X exactly; substring form also catches logged
        # URLs with appended query strings the IOC list doesn't carry verbatim.
        wild = " OR ".join(f'Web.url="*{_esc_dq(u)}*"' for u in urls)
        blocks.append(_tstats_block(
            "Web", "Web",
            f"({wild})",
            ["Web.src", "Web.dest", "Web.url", "Web.http_user_agent"],
        ))

    if hashes:
        lst = _q_dq(hashes)
        # Process executions and filesystem artefacts live in separate
        # Endpoint datasets — hit both.
        blocks.append(_tstats_block(
            "Endpoint", "Processes",
            f"Processes.process_hash IN ({lst})",
            ["Processes.dest", "Processes.user", "Processes.process_name", "Processes.process_hash"],
        ))
        blocks.append(_tstats_block(
            "Endpoint", "Filesystem",
            f"Filesystem.file_hash IN ({lst})",
            ["Filesystem.dest", "Filesystem.user", "Filesystem.file_name", "Filesystem.file_path", "Filesystem.file_hash"],
        ))

    return "\n\n".join(blocks)


def _tstats_block(datamodel: str, dataset: str, where: str, by_fields: list[str]) -> str:
    return (
        f"| tstats summariesonly=false count "
        f"min(_time) as firstTime max(_time) as lastTime "
        f"from datamodel={datamodel}.{dataset} "
        f"where earliest=-90d {where} "
        f"by {' '.join(by_fields)} "
        f'| `drop_dm_object_name("{dataset}")` '
        f"| convert ctime(firstTime) ctime(lastTime)"
    )


def _kql_sentinel(by: dict[IOCType, list[str]]) -> str:
    if not _has_any(by):
        return "// no IOCs to hunt"
    parts: list[str] = []
    ips = by.get(IOCType.IP, [])
    if ips:
        parts.append(f"DeviceNetworkEvents | where RemoteIP in~ ({_q_dq(ips)})")
    domains = by.get(IOCType.DOMAIN, [])
    if domains:
        parts.append(f"DnsEvents | where Name in~ ({_q_dq(domains)})")
    urls = by.get(IOCType.URL, [])
    if urls:
        parts.append(f"DeviceNetworkEvents | where RemoteUrl in~ ({_q_dq(urls)})")
    hashes = _all_hashes(by)
    if hashes:
        h = _q_dq(hashes)
        parts.append(
            f"DeviceFileEvents | where SHA256 in~ ({h}) "
            f"or SHA1 in~ ({h}) "
            f"or MD5 in~ ({h})"
        )
    if len(parts) == 1:
        return parts[0]
    inner = ",\n  ".join(f"({p})" for p in parts)
    return f"union\n  {inner}"


def _kql_defender(by: dict[IOCType, list[str]]) -> str:
    if not _has_any(by):
        return "// no IOCs to hunt"
    clauses: list[str] = []
    if by.get(IOCType.IP):
        clauses.append(f"RemoteIP in~ ({_q_dq(by[IOCType.IP])})")
    if by.get(IOCType.URL):
        clauses.append(f"RemoteUrl in~ ({_q_dq(by[IOCType.URL])})")
    if not clauses:
        return "// kql-defender supports IP and URL only; no matching IOCs"
    body = " or ".join(clauses)
    return f"DeviceNetworkEvents | where {body}"


def _crowdstrike_fql(by: dict[IOCType, list[str]]) -> str:
    """CrowdStrike Falcon Query Language — per-IOC-type query, blank line between."""
    if not _has_any(by):
        return "// no IOCs to hunt"
    blocks: list[str] = []
    if by.get(IOCType.DOMAIN):
        blocks.append(
            f"event_simpleName=DnsRequest DomainName=[{_q_sq(by[IOCType.DOMAIN])}]"
        )
    if by.get(IOCType.IP):
        blocks.append(
            f"event_simpleName=NetworkConnectIP4 RemoteAddressIP4=[{_q_sq(by[IOCType.IP])}]"
        )
    hashes_sha256 = by.get(IOCType.HASH_SHA256, [])
    if hashes_sha256:
        blocks.append(
            f"event_simpleName=ProcessRollup2 SHA256HashData=[{_q_sq(hashes_sha256)}]"
        )
    return "\n\n".join(blocks) or "// crowdstrike-fql: no DOMAIN/IP/SHA256 IOCs"


def _elastic_eql(by: dict[IOCType, list[str]]) -> str:
    """Elastic EQL — single sequence with disjunctions across IOC types."""
    if not _has_any(by):
        return "// no IOCs to hunt"
    clauses: list[str] = []
    if by.get(IOCType.IP):
        clauses.append(f'destination.ip in ({_q_dq(by[IOCType.IP])})')
    if by.get(IOCType.DOMAIN):
        clauses.append(f'dns.question.name in ({_q_dq(by[IOCType.DOMAIN])})')
    if by.get(IOCType.URL):
        clauses.append(f'url.full in ({_q_dq(by[IOCType.URL])})')
    body = " or ".join(clauses)
    return f"network where {body}"


def _elastic_lucene(by: dict[IOCType, list[str]]) -> str:
    if not _has_any(by):
        return "// no IOCs to hunt"

    def _or_quoted(values: list[str]) -> str:
        return " OR ".join(f'"{_esc_dq(v)}"' for v in values)

    clauses: list[str] = []
    if by.get(IOCType.IP):
        clauses.append(f"destination.ip:({_or_quoted(by[IOCType.IP])})")
    if by.get(IOCType.DOMAIN):
        clauses.append(f"dns.question.name:({_or_quoted(by[IOCType.DOMAIN])})")
    if by.get(IOCType.URL):
        clauses.append(f"url.full:({_or_quoted(by[IOCType.URL])})")
    return " OR ".join(clauses) or "// no IOCs to hunt"


# Local/site rule range. Suricata reserves 1000000-1999999 for local rules and
# most distributions leave 9000000+ free; bump this if it collides with your
# own numbering.
SID_BASE = 9000000

# Suricata's standard classtypes: a confirmed hit is C2-grade, a suspicious one
# is not strong enough to claim that.
_CLASSTYPE = {
    Verdict.MALICIOUS: "trojan-activity",
    Verdict.SUSPICIOUS: "misc-activity",
}


def _rule_evidence(scan: ScanResult) -> str:
    """Names of the providers that voted malicious, for the rule msg.

    An analyst reviewing a fired alert needs to know which feed put the IP in
    the ruleset — 'iocscan said so' is not actionable.
    """
    names = [r.provider for r in scan.provider_results if r.verdict == Verdict.MALICIOUS]
    return ", ".join(names[:3]) if names else "no single-provider hit"


def _suricata_rules(scans: list[ScanResult]) -> str:
    """One `alert ip` rule per malicious/suspicious IP.

    Clean, unknown, and whitelisted IOCs are deliberately excluded: this output
    is loaded into a sensor, and alerting on an IP the tool itself scored clean
    produces false positives under a msg that contradicts the verdict.
    """
    ip_scans = [s for s in scans if s.ioc_type == IOCType.IP]
    actionable = [s for s in ip_scans if s.verdict in _CLASSTYPE]
    if not actionable:
        skipped = len(ip_scans)
        if not skipped:
            return "# suricata-ip-rules: no IPs to hunt"
        return (
            f"# suricata-ip-rules: no malicious/suspicious IPs "
            f"({skipped} IP{'s' if skipped != 1 else ''} skipped)"
        )
    return "\n".join(
        f'alert ip $HOME_NET any -> {s.ioc} any '
        f'(msg:"iocscan {s.verdict.value} IP {s.ioc} ({_rule_evidence(s)})"; '
        f'classtype:{_CLASSTYPE[s.verdict]}; metadata:source iocscan; '
        f'sid:{sid}; rev:1;)'
        for sid, s in enumerate(actionable, start=SID_BASE)
    )


_EMITTERS = {
    "splunk-spl": _splunk_spl,
    "kql-sentinel": _kql_sentinel,
    "kql-defender": _kql_defender,
    "crowdstrike-fql": _crowdstrike_fql,
    "elastic-eql": _elastic_eql,
    "elastic-lucene": _elastic_lucene,
}

# suricata-ip-rules is handled ahead of _EMITTERS in render_hunt (it needs the
# verdicts, not just the IOC strings) but is still an offered format.
HUNT_FORMATS = tuple(_EMITTERS) + ("suricata-ip-rules",)
