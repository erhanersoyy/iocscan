# iocscan

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Blue-team CLI that produces a consolidated `malicious / suspicious / clean / unknown` verdict for IP addresses and domains by querying **nine** open-source threat-intelligence providers in parallel.

Four providers work out of the box (no API key). Five more activate when you add free-tier API keys.

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
python -m iocscan --quiet -f iocs.txt        # one TSV line per IOC
python -m iocscan --defang evil.com          # render output as evil[.]com
python -m iocscan --sort verdict -f iocs.txt # worst-first
python -m iocscan providers                  # see which providers are active
```

iocscan understands common defanged formats (`evil[.]com`, `1[.]2[.]3[.]4`, `hxxp://...`) and bare URLs (the hostname is extracted).

> Tip: if `python -m iocscan ...` feels verbose, add an alias to your shell rc:
> `alias iocscan='python -m iocscan'` — then everything below works as `iocscan ...`.

---

## Reading the output

Example scan of a mixed batch of IPs and domains (default `solarized-dark` theme, wide table):

![iocscan example output](test_output.png)

iocscan renders a **wide** table when the terminal is at least 100 columns and a **compact** table when it isn't. Use `--narrow` to force compact or `--wide` to force wide. Add `--no-color` to disable ANSI colors, `--ascii` to swap Unicode glyphs for `[!]`/`[~]`/`[ ]`/etc. fallbacks (also honors the standard `NO_COLOR` / `FORCE_COLOR` env vars).

### Themes

Four built-in color themes, each WCAG-AA contrast-verified:

| Theme | Best for |
|---|---|
| `solarized-dark` (default) | Solarized terminals, dark backgrounds |
| `forensic` | High-contrast "operations room" feel, projection-ready |
| `mocha` | Catppuccin Mocha, modern dark terminals |
| `latte` | Catppuccin Latte, light terminals |

Pick one with `--theme <name>` or set the `IOCSCAN_THEME` env var. Preview every theme with:

```bash
python -m iocscan --list-themes
```

### Verdict glyphs

Every verdict is shown along three channels — **color + glyph + word** — so meaning survives if any one channel drops (NO_COLOR, screen reader, narrow terminal).

| Glyph | Verdict | Color |
|---|---|---|
| `●` | malicious | bold red |
| `◐` | suspicious | yellow |
| `○` | clean | green |
| `·` | unknown | dim gray |
| `✗` | error | italic red |
| `⚑` | whitelisted (suffix on the verdict cell) | dim |

ASCII fallback: `[!]` `[~]` `[ ]` `[.]` `[x]` `[WL]`.

### Cell semantics (per-provider)

| Cell | Meaning |
|---|---|
| `—` | Provider ran, no hit / score 0 → clean (e.g. blocklist miss, `0 pulses`) |
| `·` | Provider does not apply to this IOC type (e.g. IP-only feed against a domain) |
| `0/92`, `50 pulses`, `tor exit`, `15%` | Numeric or label score from the provider |
| `✗ <msg>` | Hard failure: network error, 5xx, parse error |
| `▲ 429 rate limit` | Rate limited — retryable |
| `⚡ auth failed` | Authentication failed — fixable by setting the right API key |

Errors do **not** count toward coverage.

### Final verdict cell

The `Verdict` column reads e.g. `● clean (9/9)` — glyph + value + how many providers actually responded out of how many were applicable. A trailing `⚑ whitelisted` tag means the IOC matched the bundled or Tranco whitelist and any `malicious` / `suspicious` verdict was clamped down to `clean`.

### Summary footer

After the table, a multi-line summary block shows totals, verdict counts, provider errors, cache hits/fresh fetches, and the exit code. Suppressed under `--json` and when output is piped.

### Output modes

| Flag | Format | Use case |
|---|---|---|
| *(default)* | Colored table + summary footer | Interactive triage |
| `--format json` | Pretty JSON to stdout | SOAR / SIEM ingestion (full provider detail) |
| `--format jsonl` | One JSON object per line | Streaming pipelines |
| `--format csv` | RFC 4180 CSV with 6 columns | Spreadsheets / ticket attachments |
| `--format markdown` | GitHub-flavored markdown table | Paste into PR / Confluence / ticket |
| `--quiet` / `-q` | TSV: `IOC\tverdict\tcoverage` per line | `grep` / `awk` / CI scripts |
| `--defang` | Renders IOCs as `evil[.]com`, `1[.]2[.]3[.]4` in any of the above | Pasting into Slack / email / Confluence without auto-links |

`--json` still works as a deprecated alias for `--format json`. `--quiet` wins over `--format` (low-noise contract).

JSON is the only format that carries the full per-provider breakdown — `jsonl`, `csv`, and `markdown` are flat summary exports (IOC, type, verdict, coverage, whitelisted).

### Sorting

`--sort {input,verdict,coverage}` (default `input`):

- **`input`** — preserve the order IOCs were passed in (default; safe for scripts).
- **`verdict`** — worst first (malicious → suspicious → unknown → clean).
- **`coverage`** — most evidence first (highest `responding/total`).

JSON output stays in input order **unless** `--sort` is explicit — machines should not be silently reordered.

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

## Verdict logic (in short)

1. If fewer than `min_coverage` providers (default 3) respond non-error/non-unknown → `unknown`.
2. If any **authoritative** provider (Spamhaus DROP, Feodo Tracker) returns `malicious` → final `malicious`.
3. Otherwise weighted vote at ≥30%: VirusTotal and OTX count as 2; others count as 1.
4. Whitelist override: if the IOC is a bundled-whitelist or Tranco top-1K domain, `malicious`/`suspicious` is clamped to `clean` (and the table marks it as whitelisted).

---

## Project layout

High-level map of the codebase. Each row links a directory to its single responsibility.

| Path | Responsibility |
|---|---|
| `iocscan/cli.py` | Argparse entry point + subcommand routing (`scan`, `config`, `cache`, `providers`, `whitelist`); `-f` input safety; output dispatch. |
| `iocscan/core/scan.py` | Per-IOC orchestration: filters providers by IOC type, rate-limits, `asyncio.gather`s their lookups, returns `ScanResult`. |
| `iocscan/core/verdict.py` | Aggregates per-provider results into the final verdict (authoritative override → weighted vote → coverage floor). |
| `iocscan/core/ioc.py` | Parses & validates IOCs; understands defanged forms (`evil[.]com`, `hxxps://...`). |
| `iocscan/core/config.py` | API key resolution: config file (0600) → env var → CLI flag. |
| `iocscan/core/cache.py` | SQLite cache at `~/.iocscan/cache.db` (24h TTL, symlink-refusal guard). |
| `iocscan/core/whitelist.py` + `core/tranco.py` | Bundled critical-infra list + optional Tranco top-1K override. |
| `iocscan/providers/base.py` | `Provider` ABC, `ProviderResult` dataclass, shared `Verdict`/`IOCType` enums. |
| `iocscan/providers/<name>.py` | One file per TI source (9 total). Each subclasses `Provider`. |
| `iocscan/providers/__init__.py` | `ALL_PROVIDERS` registry — the single list `scan.py` iterates. |
| `iocscan/ui/table.py`, `ui/footer.py`, `ui/json_out.py`, `ui/export.py` | Output renderers: rich table, summary footer, JSON, jsonl/csv/markdown. |
| `iocscan/ui/themes.py`, `ui/glyph.py`, `ui/console.py` | Theming, verdict glyphs, terminal detection. |
| `tests/` | pytest suite mirroring the source tree (`unit/`, `providers/`, `cli/`, `integration/`). |

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
