# iocscan — Blue Team IOC Verdict CLI

**Status:** Design approved 2026-05-17
**Author:** n.erhan.ersoy@gmail.com
**Audience:** Blue team / SOC analysts

## 1. Purpose

`iocscan` is a Python CLI tool that takes IP addresses and domain names and returns a consolidated `malicious / suspicious / clean / unknown` verdict by querying nine open-source threat intelligence providers in parallel. It runs without configuration on first install (five no-key providers always work) and gains coverage as the user adds free-tier API keys.

## 2. Goals & Non-Goals

**Goals**
- Single command produces a colored terminal table with per-source results and a final verdict.
- Works with zero configuration: five no-key providers are queried by default.
- Free-tier API keys (VirusTotal, AbuseIPDB, OTX, GreyNoise) are optional and unlock four more providers.
- Honest verdicts: never claim "clean" when too few providers responded.
- Machine-readable output (`--json`) for SOAR / SIEM integration.
- Fast: 9 providers complete in 3–5 seconds via asyncio.

**Non-Goals (YAGNI)**
- No file hashes, URLs (full path), email addresses, or CVEs in v1 — IP and domain only.
- No log-file IOC extraction (existing tools cover this).
- No firewall rule generation, SIEM forwarders, or Snort signatures.
- No web UI, no daemon mode.
- No commercial TI provider integrations (Recorded Future, Mandiant, etc.).
- No internal MISP / OpenCTI plugin in v1 (clean Provider ABC makes this easy to add later).

## 3. Providers (9 total)

### Key-less (always active)
| Provider | IOC Types | Endpoint | Notes |
|---|---|---|---|
| URLhaus | IP, domain | `https://urlhaus-api.abuse.ch/v1/host/` | Anonymous POST; malware distribution URLs. Endpoint's `host` parameter accepts both IPs and domains. |
| ThreatFox | IP, domain | `https://threatfox-api.abuse.ch/api/v1/` | Anonymous POST; C2 indicators |
| Feodo Tracker | IP | `https://feodotracker.abuse.ch/downloads/ipblocklist.json` | Cached daily; banking trojan C2 |
| Tor Exit List | IP | `https://check.torproject.org/torbulkexitlist` | Cached daily; informational, not malicious by itself |
| Spamhaus DROP | IP | `https://www.spamhaus.org/drop/drop.txt` | Cached daily; hijacked netblocks |

### Free-tier (require API key, optional)
| Provider | IOC Types | Free Limit | Env Var |
|---|---|---|---|
| VirusTotal | IP, domain | 500/day, 4/min | `IOCSCAN_VT_KEY` |
| AbuseIPDB | IP | 1,000/day | `IOCSCAN_ABUSEIPDB_KEY` |
| AlienVault OTX | IP, domain | ~10,000/hour | `IOCSCAN_OTX_KEY` |
| GreyNoise Community | IP | 50/week | `IOCSCAN_GREYNOISE_KEY` |

Domain-only IOCs skip IP-only providers, and vice versa — `Provider.supports` declares each provider's capability set.

## 4. Architecture (Plugin-based)

```
iocscan/
├── pyproject.toml
├── iocscan/
│   ├── __init__.py
│   ├── cli.py                # argparse + asyncio entry point
│   ├── providers/
│   │   ├── base.py           # Provider ABC, ProviderResult, enums
│   │   ├── urlhaus.py
│   │   ├── threatfox.py
│   │   ├── feodo.py
│   │   ├── tor.py
│   │   ├── spamhaus.py
│   │   ├── virustotal.py
│   │   ├── abuseipdb.py
│   │   ├── otx.py
│   │   └── greynoise.py
│   ├── core/
│   │   ├── ioc.py            # IOC type detection, defang normalization
│   │   ├── verdict.py        # aggregate() — majority vote with min coverage
│   │   ├── cache.py          # SQLite TTL cache
│   │   └── config.py         # env var + ~/.iocscan/config.toml merge
│   └── ui/
│       ├── table.py          # Rich colored table renderer
│       └── json_out.py       # JSON serializer
└── tests/
    ├── unit/
    ├── providers/            # httpx.MockTransport per-provider tests
    └── fixtures/responses/   # Saved JSON responses per provider
```

## 5. Provider Contract

```python
# iocscan/providers/base.py
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum

class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"

class Verdict(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"       # no data, OR insufficient coverage at aggregate level
    ERROR = "error"           # network / auth / rate-limit / parse failure

@dataclass(frozen=True)
class ProviderResult:
    provider: str             # "virustotal"
    verdict: Verdict
    score: str                # short display string: "12/70", "95%", "hit", "—"
    raw: dict | None          # raw JSON for --json output
    error: str | None         # human-readable error if verdict == ERROR
    latency_ms: int

class Provider(ABC):
    name: str
    supports: set[IOCType]
    requires_key: bool
    max_rps: float            # per-provider concurrency cap (None = unlimited)
    max_per_day: int | None   # informational; used by `iocscan providers` output

    @abstractmethod
    async def lookup(
        self, ioc: str, ioc_type: IOCType, client: httpx.AsyncClient
    ) -> ProviderResult: ...

    def has_key(self, config) -> bool:
        """True if no key required, or key is configured."""
```

**Rules:**
- Every provider must return a `ProviderResult` — never raise.
- Network / auth errors → `Verdict.ERROR` with descriptive `error` field.
- Missing-but-required key → `Verdict.ERROR` with `error="key required"`, no HTTP call made.
- Latency is measured around the network call.

## 6. Verdict Aggregation

```python
MIN_COVERAGE = 3  # minimum responding providers for a confident verdict

def aggregate(results: list[ProviderResult]) -> Verdict:
    responding = [r for r in results if r.verdict not in (Verdict.ERROR, Verdict.UNKNOWN)]
    if len(responding) < MIN_COVERAGE:
        return Verdict.UNKNOWN
    malicious  = sum(1 for r in responding if r.verdict == Verdict.MALICIOUS)
    suspicious = sum(1 for r in responding if r.verdict == Verdict.SUSPICIOUS)
    if malicious > len(responding) / 2:
        return Verdict.MALICIOUS
    if (malicious + suspicious) > len(responding) / 2:
        return Verdict.SUSPICIOUS
    return Verdict.CLEAN
```

`UNKNOWN` now carries two meanings:
1. Providers were queried but had no data on this IOC.
2. Fewer than 3 providers responded successfully (low coverage).

The table always shows `verdict (responding/total)` so the analyst sees coverage explicitly.

## 7. Data Flow

```
CLI input (args / -f file / stdin)
        │
        ▼
   IOC parser (defang, IP/domain detect, dedupe, invalid skip with stderr warning)
        │  List[IOC]
        ▼
   Cache lookup  ── hit ──► merge into results
        │  miss
        ▼
   asyncio.gather over Providers (shared httpx.AsyncClient, timeout=10s)
        │  List[ProviderResult]
        ▼
   Verdict aggregation
        │
        ▼
   Cache write
        │
        ▼
   Rich table  /  --json output
```

## 8. CLI Surface

```bash
# Scanning
iocscan 1.2.3.4 evil.com                  # positional args
iocscan -f iocs.txt                       # one IOC per line, # comments allowed
cat iocs.txt | iocscan                    # stdin
iocscan --json 1.2.3.4                    # machine-readable JSON
iocscan --no-cache evil.com               # bypass cache for this run
iocscan --debug 1.2.3.4                   # verbose stderr (HTTP, stack traces)
iocscan --narrow 1.2.3.4                  # force compact table layout

# Ad-hoc key override (highest priority)
iocscan --vt-key XXX --abuseipdb-key YYY 1.2.3.4

# Management
iocscan config set virustotal KEY         # writes ~/.iocscan/config.toml (chmod 0600)
iocscan config show                       # list configured keys (masked)
iocscan config path                       # print config file location
iocscan cache clear                       # delete cache.db
iocscan cache stats                       # rows, size, oldest entry
iocscan providers                         # list providers + status (active / missing key)
```

### Exit Codes
| Code | Meaning |
|---|---|
| 0 | All IOCs clean |
| 1 | At least one IOC malicious |
| 2 | At least one IOC suspicious (no malicious) |
| 3 | Argument / parse error |
| 4 | All providers failed (network down, total auth failure) |
| 5 | All IOCs unknown (insufficient coverage) |

CI / SOAR can branch on exit code without parsing stdout.

## 9. Configuration

Resolution order (first match wins):
1. CLI flag (`--vt-key VAL`) — highest priority, useful for ad-hoc / CI
2. Environment variable (`IOCSCAN_VT_KEY`)
3. `~/.iocscan/config.toml`

```toml
[providers]
virustotal = "xxxxxxxx"
abuseipdb  = "yyyyyyyy"
otx        = "zzzzzzzz"
greynoise  = "wwwwwwww"

[settings]
cache_ttl_hours = 24
timeout_seconds = 10
min_coverage    = 3
```

`config.toml` is written with mode `0600`. `iocscan config set` performs atomic writes (write to temp, rename).

## 10. Caching

- **Backend:** SQLite at `~/.iocscan/cache.db` (created on first run).
- **Schema:** `(ioc, provider) → (fetched_at, verdict, score, raw_json)`.
- **TTL:** 24h default, configurable via `cache_ttl_hours` or `IOCSCAN_CACHE_TTL` env var.
- **Partial hits:** if 7 of 9 providers are cached, only 2 are queried.
- **Bypass:** `--no-cache` skips reads AND writes for that run.
- **Invalidate:** `iocscan cache clear` drops the table; `cache stats` reports size and age.

## 11. Error Handling

| Failure Type | Behavior | Table Cell |
|---|---|---|
| Network timeout (10s) | Skip, continue | `error: timeout` (red italic) |
| 429 rate limit | Skip, continue, stderr warning | `error: 429 rate limit` |
| 401 / 403 auth | Skip, continue, stderr warning | `error: auth failed` |
| 5xx server | Skip, continue | `error: 5xx` |
| Response parse error | Skip, continue, `--debug` shows trace | `error: parse` |
| Required key missing | Skip BEFORE network call | `error: key required` |
| Invalid IOC format | Drop row, stderr warning | row not in output |
| All providers fail | Print error to stderr, exit 4 | every cell = error |

`--debug` writes per-provider HTTP requests/responses, full stack traces, and latency to stderr. Default mode writes only a one-line summary per error.

## 12. Output Format

### Default: Rich Colored Table
- Columns: `IOC | Type | Verdict | VT | AbuseIPDB | OTX | URLhaus | ThreatFox | Feodo | Tor | Spamhaus | GreyNoise`
- Verdict colors: `malicious` = red bold, `suspicious` = yellow, `clean` = green, `unknown` = gray, `error` = red italic
- Verdict cell shows coverage: `clean (5/9)`
- Per-provider cells show short score: `12/70`, `95%`, `hit`, `—`, `error: 429`
- Terminal width < 140 chars → automatic fallback to compact mode (provider results joined with pipes)
- `--narrow` flag forces compact mode regardless of width

### `--json`
```json
{
  "scan": {
    "timestamp": "2026-05-17T10:30:00Z",
    "tool_version": "0.1.0",
    "min_coverage": 3
  },
  "results": [
    {
      "ioc": "1.2.3.4",
      "type": "ip",
      "verdict": "malicious",
      "coverage": {"responding": 6, "total": 9},
      "providers": {
        "virustotal":  {"verdict": "malicious",  "score": "12/70", "latency_ms": 412, "raw": {...}},
        "abuseipdb":   {"verdict": "malicious",  "score": "95%",   "latency_ms": 234, "raw": {...}},
        "otx":         {"verdict": "malicious",  "score": "hit",   "latency_ms": 187, "raw": {...}},
        "greynoise":   {"verdict": "error",      "score": "",      "error": "key required"},
        ...
      }
    }
  ]
}
```

## 13. Concurrency & Performance

- Single shared `httpx.AsyncClient` (HTTP/2 enabled, connection pool of 20).
- All providers queried in parallel via `asyncio.gather(return_exceptions=False)` — provider implementations swallow their own exceptions and return `ERROR` results.
- Per-provider `httpx.Timeout(10.0)`.
- Per-provider rate-limit awareness: each provider class declares `max_rps`; the shared client uses an `asyncio.Semaphore` per provider to enforce it. Hitting the limit returns `Verdict.ERROR` with `error="rate limit"`.
- Batch scans (many IOCs): IOCs are processed sequentially, but all providers for a single IOC run in parallel. (A future optimization could pipeline IOCs, deferred to v2.)

## 14. Test Strategy

**Unit (pytest):**
- `core/ioc.py` — defang variants, IPv4 / IPv6, URL → domain extraction, invalid inputs
- `core/verdict.py` — all combinations: all clean, split votes, all error, mixed, below MIN_COVERAGE
- `core/cache.py` — TTL expiry, partial hit (7 of 9 cached), atomic write, schema migration
- `core/config.py` — precedence (CLI > env > file), missing key, malformed TOML

**Provider tests (httpx.MockTransport):**
- Each provider gets fixtures in `tests/fixtures/responses/{provider}/{scenario}.json`
- Scenarios per provider: malicious hit, clean miss, 429 rate limit, malformed response
- Real network is never hit in unit tests.

**Integration smoke tests (`@pytest.mark.network`):**
- Only key-less providers (URLhaus, ThreatFox, Feodo, Tor, Spamhaus).
- Run weekly in CI, skipped by default locally.

**CLI snapshot tests:**
- Fixed terminal width (80 and 200) — two snapshots of table output.
- `--json` output diffed against canonical fixture.

**Coverage targets:** `core/` ≥ 90%, `providers/` ≥ 80%.

## 15. Dependencies (Python ≥ 3.11)

- `httpx[http2]` — async HTTP client
- `rich` — colored terminal table
- `tomli-w` — write TOML config (Python 3.11+ already has `tomllib` for reading)
- `pytest`, `pytest-asyncio`, `pytest-cov` — testing
- No other runtime dependencies.

## 16. Packaging & Distribution

- Standard `pyproject.toml` with `[project.scripts]` exposing `iocscan` entry point.
- `pipx install iocscan` is the recommended install path.
- License: MIT.
- Repository layout follows the directory tree in §4.

## 17. Open Items (for v2, not v1)

- Hash and URL IOC types.
- Pipelined batch mode (concurrent IOCs).
- Pluggable internal providers (e.g., MISP, OpenCTI) via entry-point discovery.
- Output formatters beyond table / JSON (CSV, STIX 2.1).
- A `--watch` mode that re-queries periodically.
