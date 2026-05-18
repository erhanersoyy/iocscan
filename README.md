# iocscan

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Blue-team CLI that produces a consolidated `malicious / suspicious / clean / unknown` verdict for IP addresses and domains by querying **nine** open-source threat-intelligence providers in parallel.

Four providers work out of the box (no API key). Five more activate when you add free-tier API keys. A typical scan completes in 3–5 seconds.

---

## Why iocscan

- **Honest verdicts.** If too few providers respond, the verdict is `unknown` — never falsely "clean".
- **Authoritative blocklist short-circuit.** A single hit on Spamhaus DROP or Feodo Tracker yields `malicious` regardless of votes.
- **Critical-infra whitelist.** Bundled list of ~40 high-traffic domains (Google, Cloudflare, GitHub, …) plus optional Tranco top-1K override false positives.
- **Fast.** All providers fire in parallel with per-provider rate limiting.
- **SOAR-friendly.** `--json` output + documented exit codes for pipelines.
- **Local cache.** 24h SQLite cache; bulk feeds (Spamhaus, Feodo, Tor) are downloaded once per process.

---

## Install

Requires Python 3.11 or newer.

```bash
git clone https://github.com/erhanersoyy/iocscan.git
cd iocscan
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

That's it. Every command below assumes the venv is active. Re-activate any new terminal with `source .venv/bin/activate`.

---

## Quick start

```bash
python -m iocscan 1.2.3.4 evil.com           # scan one or more IOCs
python -m iocscan -f iocs.txt                # one IOC per line, # comments allowed
cat iocs.txt | python -m iocscan             # pipe from stdin
python -m iocscan --json 8.8.8.8 > out.json  # machine-readable
python -m iocscan providers                  # see which providers are active
```

iocscan understands common defanged formats (`evil[.]com`, `1[.]2[.]3[.]4`, `hxxp://...`) and bare URLs (the hostname is extracted).

> Tip: if `python -m iocscan ...` feels verbose, add an alias to your shell rc:
> `alias iocscan='python -m iocscan'` — then everything below works as `iocscan ...`.

---

## Reading the output

iocscan renders a **wide** table when the terminal is at least 140 columns and a **compact** table (or with `--narrow`) when it isn't. Both layouts use the same symbols and colors.

### Symbols

| Symbol | Meaning |
|---|---|
| `—` | Provider ran, no hit / score 0 → **clean** (e.g. blocklist miss, `0 pulses`) |
| `n/a` | Provider does not apply to this IOC type (e.g. an IP-only feed against a domain). Distinguishes "didn't run" from "ran and saw nothing". *Compact mode only.* |
| `0/92`, `50 pulses`, `tor exit`, `15%` | Numeric or label score from the provider — interpretation depends on the source (see the [Providers](#providers) table) |
| `err (reason)` | Provider failed (auth, network, parse, rate limit). Does **not** count toward coverage. |

### Colors

| Color | Verdict |
|---|---|
| **green** | clean |
| **yellow** | suspicious |
| **bold red** | malicious |
| **italic red** | provider-level error |
| **dim gray** | unknown / not applicable |

### Final verdict cell

The `Verdict` column reads e.g. `clean (9/9)` — the value (`clean` / `suspicious` / `malicious` / `unknown`) plus how many providers actually responded out of how many were applicable. A trailing `(whitelisted)` tag means the IOC matched the bundled or Tranco whitelist and any `malicious` / `suspicious` verdict was clamped down to `clean`.

### Compact mode (`--narrow`)

When the table won't fit, every provider is listed on its own line inside the `Details` column, in the same order as the wide columns. Example:

```
urlhaus: —
threatfox: —
feodo: n/a
tor: n/a
spamhaus: n/a
vt: 0/92
abuseip: n/a
otx: 50 pulses
greynoise: n/a
```

Force compact mode anywhere with `--narrow` if you prefer this layout in a wide terminal.

---

## Providers

| Provider | Key required | IOC types |
|---|---|---|
| URLhaus | yes (free, single key for all abuse.ch) | IP, domain |
| ThreatFox | yes (free, single key for all abuse.ch) | IP, domain |
| Feodo Tracker | no | IP |
| Tor Exit List | no | IP |
| Spamhaus DROP | no | IP |
| VirusTotal | yes (free 500/day) | IP, domain |
| AbuseIPDB | yes (free 1000/day) | IP |
| AlienVault OTX | yes (free ~10k/h) | IP, domain |
| GreyNoise Community | no (optional key for higher rate limit) | IP |

> abuse.ch (URLhaus + ThreatFox) requires an Auth-Key on their query APIs. Registration is free at <https://auth.abuse.ch> — the same single key covers both.

---

## Configure API keys

Three ways to provide keys (lowest → highest priority): config file → environment variable → CLI flag. Higher priority overrides lower.

**Recommended — config file** (stored at `~/.iocscan/config.toml`, mode 0600):

```bash
python -m iocscan config set abusech    YOUR_KEY  # single key for URLhaus + ThreatFox
python -m iocscan config set virustotal YOUR_KEY
python -m iocscan config set abuseipdb  YOUR_KEY
python -m iocscan config set otx        YOUR_KEY
python -m iocscan config set greynoise  YOUR_KEY  # optional; raises anonymous rate limit
```

**Environment variables** (useful in CI):

```bash
export IOCSCAN_ABUSECH_KEY=...
export IOCSCAN_VT_KEY=...
export IOCSCAN_ABUSEIPDB_KEY=...
export IOCSCAN_OTX_KEY=...
export IOCSCAN_GREYNOISE_KEY=...   # optional
```

**CLI flags** (insecure — visible to other local users via `ps`; prefer env or config):

```bash
python -m iocscan --vt-key YOUR_KEY 8.8.8.8
```

Inspect what's loaded (keys are masked):

```bash
python -m iocscan config show
python -m iocscan config path
```

---

## Usage scenarios

### 1. SOC analyst — quick triage

```bash
python -m iocscan 203.0.113.10 malicious-domain.test
```

Output is a colored table with one row per provider plus a final verdict, plus per-IOC coverage (e.g. `7/9 responding`).

### 2. Bulk scan from a file

```bash
# iocs.txt
# Indicators from incident #4231
203.0.113.10
evil[.]com
hxxps://phish.example/login

python -m iocscan -f iocs.txt
```

Blank lines and `#` comments are ignored. Defanged formats are normalised automatically.

### 3. SOAR / SIEM integration with `--json`

```bash
python -m iocscan --json -f iocs.txt > results.json
```

```jsonc
{
  "results": [
    {
      "ioc": "8.8.8.8",
      "type": "ip",
      "verdict": "clean",
      "responding": 6,
      "total": 7,
      "whitelisted": false,
      "providers": [
        { "provider": "virustotal", "verdict": "clean", "score": "0/94", "latency_ms": 312 },
        { "provider": "abuseipdb",  "verdict": "clean", "score": "0%",   "latency_ms": 188 }
        // ...
      ]
    }
  ]
}
```

### 4. CI / CD pipeline — fail the build on malicious IOCs

```bash
python -m iocscan -f deploy-artifacts/ioc-extract.txt
case $? in
  0) echo "all clean — proceed";;
  1) echo "MALICIOUS IOC found — block release"; exit 1;;
  2) echo "suspicious IOC — manual review";;
  4) echo "all providers failed — retry later";;
  5) echo "too little coverage — add API keys";;
esac
```

### 5. Threat hunting — stream from logs

```bash
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' /var/log/access.log \
  | sort -u \
  | python -m iocscan --json \
  | jq '.results[] | select(.verdict == "malicious") | .ioc'
```

### 6. Phishing email triage

Paste defanged indicators from a report straight in:

```bash
echo "login-secure[.]bank-update[.]top" | python -m iocscan
```

---

## Exit codes

| Code | Meaning |
|---|---|
| 0 | All IOCs clean |
| 1 | At least one IOC malicious |
| 2 | At least one IOC suspicious (no malicious) |
| 3 | Argument / parse error |
| 4 | All providers failed |
| 5 | All IOCs unknown (insufficient coverage) |

These are part of the public contract — safe to script against.

---

## Verdict logic (in short)

1. If fewer than `min_coverage` providers (default 3) respond non-error/non-unknown → `unknown`.
2. If any **authoritative** provider (Spamhaus DROP, Feodo Tracker) returns `malicious` → final `malicious`.
3. Otherwise weighted vote at ≥30%: VirusTotal and OTX count as 2; others count as 1.
4. Whitelist override: if the IOC is a bundled-whitelist or Tranco top-1K domain, `malicious`/`suspicious` is clamped to `clean` (and the table marks it as whitelisted).

---

## Cache

Results are cached at `~/.iocscan/cache.db` for 24 hours.

```bash
python -m iocscan --no-cache 8.8.8.8        # bypass cache for one run
python -m iocscan cache stats               # rows, IOCs, age, disk size
python -m iocscan cache clear               # flush everything
```

The cache merges with new fetches per-provider — missing providers (e.g. newly-added API key) are filled in incrementally.

---

## Whitelist (optional Tranco top-1K)

`iocscan` ships with a bundled list of well-known infrastructure domains that always override `malicious`/`suspicious` to `clean`. To augment with the [Tranco](https://tranco-list.eu) top-1K daily list (research-grade popularity ranking):

```bash
python -m iocscan whitelist update   # fetch latest Tranco top-1K (~50 KB)
python -m iocscan whitelist stats    # cache age, domain count
```

The cache lives at `~/.iocscan/tranco-1k.txt`. Re-run `update` weekly to keep it fresh.

---

## Troubleshooting

- **`config error: ...`** — `~/.iocscan/config.toml` is malformed. `python -m iocscan config path` shows the location; edit or delete.
- **All results say `auth failed`** — your API key is wrong or expired. Verify with `python -m iocscan config show`.
- **All results say `429 rate limit`** — you're hitting free-tier limits. Wait, or add a key for higher-tier providers (GreyNoise especially).
- **Exit code 5 (all unknown)** — fewer than 3 providers responded. Add more API keys; see `python -m iocscan providers`.
- **Verbose troubleshooting** — `python -m iocscan --debug ...` logs each provider call to stderr (no API keys are logged).

---

## Development

Same install as above, plus dev extras for tests:

```bash
pip install -r requirements.txt
pip install pytest pytest-asyncio pytest-cov

# Run the test suite (network tests are excluded by default)
pytest tests/ -q

# Include live-network tests (slow, flaky)
pytest tests/ -q -m network

# Coverage
pytest --cov=iocscan --cov-report=term-missing
```

See `CLAUDE.md` for architecture notes (verdict aggregation, provider plugin model, rate limiter, cache semantics).

---

## Security

- API keys are stored at `~/.iocscan/config.toml` with mode `0600` and the parent directory at `0700`. Writes are atomic (tmp + rename).
- The SQLite cache refuses to open if it's a symlink.
- Bulk-feed providers cap the response body at 50 MB.
- Passing keys via `--*-key` flags is **insecure** — they are visible to other local users via `ps`. Use env vars or the config file.

Found a vulnerability? Open a private security advisory on GitHub.

---

## Uninstall

iocscan does not install anything system-wide. Removing the project comes down to deleting the three things it creates. A guided script is included:

```bash
./uninstall.sh
```

The script walks through four steps, asking for confirmation before each:

| Step | What it removes |
|---|---|
| 1 | `~/.iocscan/` — API keys (`config.toml`), TI cache (`cache.db`), Tranco whitelist (`tranco-1k.txt`). Offers to back up `config.toml` first. |
| 2 | `<project>/.venv/` — the project-only virtualenv (httpx, rich, pytest, …). Other projects' venvs are unaffected. |
| 3 | The project directory itself — source, tests, local git history. Uncommitted changes are lost. |
| 4 | **Manual only**: GitHub remote repo deletion (irreversible, never automated). |

**Not touched** (anything that belongs to other projects or the system): `python3`, `git`, `gh`, `pip`, Homebrew, `~/.ssh/`, `~/.gitconfig`, or other `.venv` directories on the machine.

If you'd rather do it by hand:

```bash
rm -rf ~/.iocscan/         # user data (consider backing up config.toml first)
rm -rf .venv/              # project venv
cd .. && rm -rf iocscan/   # project source + local git history
```

---

## License

MIT — see [LICENSE](LICENSE).
