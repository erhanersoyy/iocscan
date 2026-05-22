"""Hunt-query emitters: turn iocscan results into SIEM/EDR queries.

Every supplied IOC goes into the query regardless of verdict or whitelist
status — triage belongs to the table/JSON view; hunt is a verbatim
IOC → query translator. Empty input yields a single no-op comment.
"""
from __future__ import annotations

from iocscan.core.scan import ScanResult
from iocscan.providers.base import IOCType


HUNT_FORMATS = (
    "splunk-spl",
    "kql-sentinel",
    "kql-defender",
    "crowdstrike-fql",
    "elastic-eql",
    "elastic-lucene",
    "suricata-ip-rules",
)


def render_hunt(scans: list[ScanResult], fmt: str) -> str:
    by_type = _partition(scans)
    if fmt == "splunk-spl":
        return _splunk_spl(by_type)
    if fmt == "kql-sentinel":
        return _kql_sentinel(by_type)
    if fmt == "kql-defender":
        return _kql_defender(by_type)
    if fmt == "crowdstrike-fql":
        return _crowdstrike_fql(by_type)
    if fmt == "elastic-eql":
        return _elastic_eql(by_type)
    if fmt == "elastic-lucene":
        return _elastic_lucene(by_type)
    if fmt == "suricata-ip-rules":
        return _suricata(by_type)
    raise ValueError(f"unknown hunt format: {fmt!r}")


def _partition(scans: list[ScanResult]) -> dict[IOCType, list[str]]:
    out: dict[IOCType, list[str]] = {}
    for s in scans:
        out.setdefault(s.ioc_type, []).append(s.ioc)
    return out


def _has_any(by_type: dict[IOCType, list[str]]) -> bool:
    return any(by_type.values())


# Quote helpers — defense-in-depth against SIEM-query injection.
# The IP / DOMAIN / HASH parsers reject characters that would break
# downstream syntax, but URL IOCs go through `urlparse` which is more
# permissive. _detect_url in core/ioc.py now refuses URLs carrying
# unencoded quotes / whitespace / control chars, but we still escape
# at emission so a regression upstream cannot smuggle clauses into
# the analyst's SIEM.
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
    hashes: list[str] = []
    for t in (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256):
        hashes.extend(by.get(t, []))

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


def _tstats_block(datamodel: str, dataset: str, where: str, by: list[str]) -> str:
    return (
        f"| tstats summariesonly=false count "
        f"min(_time) as firstTime max(_time) as lastTime "
        f"from datamodel={datamodel}.{dataset} "
        f"where earliest=-90d {where} "
        f"by {' '.join(by)} "
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
    hashes: list[str] = []
    for t in (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256):
        hashes.extend(by.get(t, []))
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
    clauses: list[str] = []
    if by.get(IOCType.IP):
        ips_or = " OR ".join(f'"{v}"' for v in by[IOCType.IP])
        clauses.append(f"destination.ip:({ips_or})")
    if by.get(IOCType.DOMAIN):
        doms_or = " OR ".join(f'"{v}"' for v in by[IOCType.DOMAIN])
        clauses.append(f"dns.question.name:({doms_or})")
    if by.get(IOCType.URL):
        urls_or = " OR ".join(f'"{v}"' for v in by[IOCType.URL])
        clauses.append(f"url.full:({urls_or})")
    return " OR ".join(clauses) or "// no IOCs to hunt"


def _suricata(by: dict[IOCType, list[str]]) -> str:
    """One `alert ip` rule per malicious IP. SID auto-incrementing from 9000000."""
    ips = by.get(IOCType.IP, [])
    if not ips:
        return "# suricata-ip-rules: no IPs to hunt"
    rules: list[str] = []
    for i, ip in enumerate(ips, start=9000000):
        rules.append(
            f'alert ip $HOME_NET any -> {ip} any '
            f'(msg:"iocscan: malicious IP {ip}"; sid:{i}; rev:1;)'
        )
    return "\n".join(rules)
