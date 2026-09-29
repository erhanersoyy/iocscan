# iocscan

![iocscan](https://github.com/erhanersoyy/iocscan/releases/download/assets/github_cover_1280x640.png)

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Blue-team CLI that produces a consolidated `malicious / suspicious / clean / unknown` verdict for IP addresses, domains, URLs and file hashes by querying multiple open-source threat-intelligence providers in parallel.

Many providers work out of the box (no API key). The rest activate when you add free-tier API keys.

---

## Install

Requires Python 3.11 or newer.

**Linux / macOS:**

```bash
git clone https://github.com/erhanersoyy/iocscan.git
cd iocscan
python3 -m venv .venv
source .venv/bin/activate
pip install .                # dependencies + the `iocscan` command
```

**Windows (PowerShell):**

```powershell
git clone https://github.com/erhanersoyy/iocscan.git
cd iocscan
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install .                # dependencies + the `iocscan` command
```

> On Windows, POSIX file permissions (`0600`) cannot be enforced on `config.toml`. The file is still protected by NTFS ACLs on your user account, but on multi-user machines treat this as weaker than the Unix guarantee. iocscan prints a one-line warning when this applies.

That's it. `pip install .` installs the dependencies and an `iocscan` command inside the venv. Re-activate the venv in every new terminal with `source .venv/bin/activate` (or `.venv\Scripts\Activate.ps1` on Windows).

**Updating:** after `git pull`, run `pip install .` again — the `iocscan` command runs the installed copy, not the files in the directory.

### Install with an AI coding agent

Using Claude Code, Cursor, Codex or a similar agent that can run terminal commands? Paste this prompt:

```text
Clone https://github.com/erhanersoyy/iocscan and install it by following the Install section of its README exactly: project-local .venv only, no sudo, no global pip installs. Do not ask me for API keys and do not change any files in the repo. When done, run `iocscan providers` and show me the output. If a step fails, stop and tell me the error instead of trying workarounds.
```

The prompt keeps the install inside the project's `.venv` and keeps API keys out of the chat history. Add your keys yourself afterwards — see [Configure API keys](#configure-api-keys).

---

## Quick start

Every command in this README assumes the venv is active (your prompt starts with `(.venv)`). The `iocscan` command then works from any directory.

```bash
source ~/iocscan/.venv/bin/activate  # adjust the path; Windows: .venv\Scripts\Activate.ps1
```

**First run — see what works out of the box:**

```bash
iocscan providers  # which providers are active, which need a key
```

**Scan something:**

```bash
iocscan 1.2.3.4                           # an IP
iocscan evil.com                          # a domain
iocscan "https://evil.com/login"          # a URL
iocscan 44d88612fea8a8f36de82e1278abb02f  # a file hash (MD5, SHA-1 or SHA-256)
iocscan 1.2.3.4 evil.com 5.6.7.8          # several at once
```

**Many IOCs:**

```bash
iocscan -f iocs.txt                 # one IOC per line, # comments allowed
cat iocs.txt | iocscan              # or pipe them in
iocscan --sort verdict -f iocs.txt  # malicious first
```

**Different output:**

```bash
iocscan --format json 8.8.8.8 > out.json  # full detail, machine-readable
iocscan --quiet -f iocs.txt               # one line per IOC: ioc <tab> verdict <tab> coverage
iocscan --defang evil.com                 # print evil[.]com so it is safe to paste
iocscan explain evil.com                  # why this verdict?
```

You can paste IOCs straight from a report: defanged forms (`evil[.]com`, `1[.]2[.]3[.]4`, `hxxps://...`) are converted back automatically. The IOC type is detected for you. URLs must start with `http://` or `https://` (or `hxxp://` / `hxxps://`).

About half the providers work without a key. VirusTotal, OTX, AbuseIPDB and the abuse.ch family need a free one — see [Configure API keys](#configure-api-keys). More examples are in [Usage scenarios](#usage-scenarios).

---

## Flags

| Flag | Description |
|---|---|
| `-f`, `--file <path>` | Read IOCs from a file (one per line, blank lines and `#` comments are ignored). |
| `-F`, `--format <fmt>` | Output format: `table` (default), `json`, `jsonl`, `csv`, `markdown`, or a hunt-query format (`splunk-spl`, `kql-sentinel`, `kql-defender`, `crowdstrike-fql`, `elastic-eql`, `elastic-lucene`, `suricata-ip-rules`). |
| `--json` | Deprecated alias for `--format json`. |
| `--no-cache` | Bypass the SQLite cache for this run and re-query every provider live. |
| `--debug` | Verbose stderr logging (HTTP traffic, provider errors) without leaking API keys. |
| `--wide` | Render the transposed grid (providers as rows, IOCs as columns) instead of the compact default. |
| `--ascii` | Use ASCII glyphs (`[!]`, `[~]`, `[ ]`) instead of Unicode for compatibility with old terminals. |
| `--theme <name>` | Pick a color theme: `solarized-dark` (default), `forensic`, `mocha`, `latte`. Env: `IOCSCAN_THEME`. |
| `--list-themes` | Render a one-line preview of every available theme, then exit. |
| `--defang` | Render IOCs in defanged form (`1.2.3[.]4`, `evil[.]com`) so output is safe to paste anywhere. |
| `--cell-links` | Emit OSC 8 hyperlinks on provider cells so modern terminals make them clickable. |
| `-q`, `--quiet` | Suppress table and footer; emit one TSV line per IOC (`IOC\tverdict\tcoverage`) for scripting. |
| `--links-only` | Emit `IOC\tprovider\tpermalink` TSV (only rows where a permalink exists); suppresses normal output. |
| `--sort <key>` | Output order: `input` (default), `verdict` (worst-first), `coverage` (most-evidence-first). |
| `--only <names>` | Query only these providers (comma-separated; see `iocscan providers`). Useful for bulk runs where a rate-limited provider dominates the wall clock. |
| `--skip <names>` | Exclude these providers (applied after `--only`). |
| `--include <paths>` | JSON only: comma-separated dot-paths to keep (e.g. `results.*.ioc,results.*.verdict`). |
| `--exclude <paths>` | JSON only: comma-separated dot-paths to drop (applied after `--include`). |
| `--<provider>-key <key>` | Pass a provider key on the CLI (`--vt-key`, `--abuseipdb-key`, `--otx-key`, `--greynoise-key`, `--abusech-key`, `--urlscan-key`). Insecure — visible via `ps`; prefer env vars or `config set`. |

---

## Reading the output

Example scan of a mixed batch of IPs and domains (default `solarized-dark` theme, `--wide` grid):

![iocscan example output](https://github.com/erhanersoyy/iocscan/releases/download/assets/test_output.png)

iocscan renders the **compact** table by default — it lists every provider on its own line and fits any terminal width. Pass `--wide` to switch to the transposed grid (providers as rows, IOCs as columns), handy when scanning a handful of IOCs side by side. Pass `--ascii` to swap Unicode glyphs for `[!]`/`[~]`/`[ ]`/etc. fallbacks, or run `iocscan glyphs` for the full symbol reference. The standard `NO_COLOR` and `FORCE_COLOR` env vars are honored to disable or force ANSI colors.

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
iocscan --list-themes
```

### Cell semantics

Each provider column reports one cell per IOC. The cell tells you what the provider saw, not what the final verdict is — coverage and weighting are applied later by the aggregator.

| Cell | Meaning |
|---|---|
| `— (no hit - clean)` | Provider ran successfully and found nothing on this IOC. Counts as a clean vote toward the verdict. |
| `?` | Provider responded but the result is inconclusive (ambiguous score, insufficient data). Does not count toward coverage. |
| `n/a` | Provider does not apply to this IOC type (e.g. an IP-only feed against a domain). Excluded from coverage. Only shown in the `--wide` grid; the compact default omits the row entirely. |
| `0/92`, `50 pulses`, `15%` | Numeric or labelled score returned by the provider. Interpretation is provider-specific. |
| `tor exit`, `tor exit (bad)`, `tor guard`, `tor relay` | Tor provider only: which role this IP plays in the Tor network. Enrichment — informative, never a vote. See [Tor node classification](#tor-node-classification). |
| `0/7 attributing (26 raw)` | OTX only: pulses that actually attribute this IOC, out of the clone-collapsed total (`raw` counts pulses before collapsing). A pulse naming hundreds of thousands of indicators is a bulk feed — the IOC co-occurs with malicious things rather than being reported as one — so it does not vote. The `details` lines report how many bulk feeds were skipped and how large they were, then name the most specific attributing pulse (fewest indicators) and list the dominant tags (the malware family, usually) of whichever set decided the score. Tags that only describe the sample — an OTX indicator type, CPU architecture or file format (`FileHash-SHA256`, `mips`, `elf`, …) — are dropped so the family name is not crowded out. |
| `✗ <msg>` | Hard failure: network error, 5xx response, or a parse error. Does not count toward coverage. |
| `▲ 429 rate limit` | Provider rate-limited the request. Retryable; does not count toward coverage. |
| `⚡ auth failed` | The API key is missing, wrong, or expired. Fix with `config set` or the matching env var. |

A `— (no hit - clean)` cell is the only "clean" signal a provider can emit — there is no green check. Errors and rate limits are deliberately separated from "unknown" so coverage reflects only what providers actually answered.

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

---

## Providers

iocscan ships with 17 providers. **Verdict** providers contribute a vote to the final verdict; **enrichment** providers add context (ASN, certificates, ports, whois age, Tor node role) without influencing the score.

| Provider | Role | Key | IOC types | Official site |
|---|---|---|---|---|
| URLhaus | Verdict (authoritative) | Auth-Key (free) | IP, domain, URL | <https://urlhaus.abuse.ch> |
| ThreatFox | Verdict | Auth-Key (free) | IP, domain, URL, hash | <https://threatfox.abuse.ch> |
| MalwareBazaar | Verdict (authoritative) | Auth-Key (free) | hash | <https://bazaar.abuse.ch> |
| YARAify | Verdict | Auth-Key (free) | hash | <https://yaraify.abuse.ch> |
| CIRCL Hashlookup | Verdict | none | hash | <https://hashlookup.circl.lu> |
| Feodo Tracker | Verdict (authoritative) | none | IP | <https://feodotracker.abuse.ch> |
| Spamhaus DROP | Verdict (authoritative) | none | IP | <https://www.spamhaus.org/drop/> |
| Tor Relay List | Enrichment | none | IP | <https://onionoo.torproject.org> |
| VirusTotal | Verdict (weight ×2) | free 500/day | IP, domain, URL, hash | <https://www.virustotal.com> |
| AbuseIPDB | Verdict | free 1000/day | IP | <https://www.abuseipdb.com> |
| AlienVault OTX | Verdict (weight ×2) | free | IP, domain, URL, hash | <https://otx.alienvault.com> |
| GreyNoise Community | Verdict | optional (raises rate limit) | IP | <https://www.greynoise.io> |
| urlscan.io | Verdict | optional | URL | <https://urlscan.io> |
| Shodan InternetDB | Enrichment | none | IP | <https://internetdb.shodan.io> |
| Team Cymru ASN | Enrichment | none | IP | <https://team-cymru.com/community-services/ip-asn-mapping/> |
| WHOIS Age | Enrichment | none | IP, domain | <https://www.iana.org/whois> |
| crt.sh | Enrichment | none | domain | <https://crt.sh> |

> abuse.ch endpoints (URLhaus, ThreatFox, MalwareBazaar, YARAify) require an Auth-Key on their query APIs. Registration is free at <https://auth.abuse.ch> — the same single key covers all four.

> "Authoritative" means a single `malicious` hit from that provider is enough to mark the IOC `malicious` regardless of what the others say. See [Verdict logic](#verdict-logic-in-short).

### Tor node classification

The Tor provider reads the Tor Project's own [Onionoo](https://onionoo.torproject.org) relay directory (`type=relay&running=true`) instead of the plain-text exit list, so it reports **which role an IP plays in the Tor network** rather than only whether it is an exit. Coverage is IPv4 *and* IPv6; the old `torbulkexitlist` was exit-only and contained no IPv6 addresses at all.

The roles sit at opposite ends of a Tor circuit, which is why they mean opposite things:

```
[ user ] --> GUARD --> MIDDLE --> EXIT --> [ your server ]
             (entry)             (exit)
                ^                   ^
        outbound: someone     inbound: someone
        inside your network   reached you from
        is using Tor          behind Tor
```

| Cell | Verdict | Implies | Meaning |
|---|---|---|---|
| `tor exit (bad)` | `suspicious` | inbound | Directory authorities flagged this exit `BadExit` — traffic tampering, SSL stripping, content injection. Unlike the other three this is an actual malice signal, not just "Tor was used". |
| `tor exit` | `suspicious` | inbound | Last hop out of Tor, and therefore the source address your logs will show. The client's real IP is not recoverable and blocking does not stick — the next request comes from a different exit. False-positive risk is very low. |
| `tor guard` | `suspicious` | outbound | Entry point into Tor: clients connect *to* guards. One of your hosts talking to a guard means someone **inside** your network is using Tor — policy violation, or C2 / exfil tunnelled over it. The exit list could never surface this. |
| `tor relay` | `clean` | — | A running relay that is neither guard nor exit. Not an alert — context that explains why another provider flagged the address. |
| `—` | `clean` | — | Not a Tor relay. |

Labels rank `bad > exit > guard > relay`, and the order is load-bearing: in a recent snapshot 1,587 of the 2,226 exit IPs (71%) also carried the `Guard` flag. Ranked the other way round, most real exits would be reported as guards and inbound anonymised traffic would be missed.

Snapshot sizes, for scale — the network churns constantly, so treat these as orders of magnitude: roughly 9,700 relay IPs (~6,700 IPv4, ~3,000 IPv6), of which ~2,200 are exits and ~6,400 guards, plus a few dozen `BadExit`. The feed this replaces covered ~1,300 IPv4 addresses and nothing else.

All four signals are enrichment-only: they are rendered in the table but never vote and never count toward coverage. Running Tor is not a crime — journalists, activists and ordinary privacy-conscious users share the network with the attackers. "Tor" is context for the analyst, not evidence that an IP is malicious.

If the Onionoo snapshot is more than 48 hours old the provider returns an error instead of an answer. A `clean` derived from stale relay data is a worse outcome than an honest "unknown".

**Inbound example.** A burst of failed logins from a single address scores `tor exit`. The source is anonymised, so blocking it buys nothing; pivot to behavioural controls — rate limiting, MFA, account lockout.

**Outbound example.** A workstation in your firewall logs is reaching an address that scores `tor guard`. Nothing in a normal corporate environment does that: treat it as Tor client activity on that host and work backwards to the process that opened the connection.

---

## Configure API keys

Three ways to provide keys (lowest → highest priority): config file → environment variable → CLI flag. Higher priority overrides lower.

**Recommended — config file** (stored at `~/.iocscan/config.toml`, mode 0600):

```bash
iocscan config set abusech    YOUR_KEY  # single key for all abuse.ch endpoints
iocscan config set virustotal YOUR_KEY
iocscan config set abuseipdb  YOUR_KEY
iocscan config set otx        YOUR_KEY
iocscan config set greynoise  YOUR_KEY  # optional; raises anonymous rate limit
iocscan config set urlscan    YOUR_KEY  # optional
```

**Environment variables** (useful in CI):

```bash
export IOCSCAN_ABUSECH_KEY=...
export IOCSCAN_VT_KEY=...
export IOCSCAN_ABUSEIPDB_KEY=...
export IOCSCAN_OTX_KEY=...
export IOCSCAN_GREYNOISE_KEY=...   # optional
export IOCSCAN_URLSCAN_KEY=...     # optional
```

**CLI flags** (insecure — visible to other local users via `ps`; prefer env or config):

```bash
iocscan --vt-key YOUR_KEY 8.8.8.8
```

Inspect what's loaded (keys are masked):

```bash
iocscan config show
iocscan config path
```

---

## Usage scenarios

### 1. SOC analyst — quick triage

```bash
iocscan 203.0.113.10 malicious-domain.test
```

Output is a colored table with one block per IOC: every provider's result on its own line, plus the final verdict and coverage — e.g. `● malicious (7/9)` means 7 of 9 applicable providers gave a usable answer.

### 2. Bulk scan from a file

```bash
# iocs.txt
# Indicators from incident #4231
203.0.113.10
evil[.]com
hxxps://phish.example/login

iocscan -f iocs.txt
iocscan -f iocs.txt --sort verdict  # malicious first, clean last
```

Blank lines and `#` comments are ignored. Defanged formats are normalised automatically.

### 3. File hash lookup

```bash
iocscan 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
iocscan 44d88612fea8a8f36de82e1278abb02f  # MD5 and SHA-1 work too
```

The hash type is detected from its length. Hashes go to VirusTotal, OTX, ThreatFox, MalwareBazaar, YARAify and CIRCL Hashlookup. Only CIRCL Hashlookup works without a key, so add at least the abuse.ch key (`config set abusech ...`) before relying on hash verdicts.

### 4. Suspicious URL from a phishing email

```bash
echo "hxxps://login-secure[.]bank-update[.]top/verify" | iocscan
iocscan --defang "hxxps://login-secure[.]bank-update[.]top/verify"  # keep it defanged in the output too
```

A URL nobody has reported before often comes back `unknown` (exit `5`) — see [Verdict logic](#verdict-logic-in-short). That means "not enough data", not "safe".

### 5. "Why did it say malicious?" — explain one IOC

```bash
iocscan explain 203.0.113.10
```

Prints why each provider voted the way it did, then the voting math: weights, the 30% threshold, whether an authoritative blocklist decided it, the Tranco tier, and whether the whitelist clamped the result. Use it before escalating or before closing a ticket as a false positive.

### 6. SOAR / SIEM integration with JSON

```bash
iocscan --format json -f iocs.txt > results.json
```

```jsonc
{
  "scan": { "timestamp": "2026-09-29T08:12:44Z", "tool_version": "0.4.0", "min_coverage": 3 },
  "results": [
    {
      "ioc": "8.8.8.8",
      "type": "ip",
      "verdict": "clean",
      "whitelisted": false,
      "tranco_tier": null,
      "coverage": { "responding": 6, "total": 7 },
      "providers": {
        "virustotal": {
          "verdict": "clean", "score": "0/94", "error": null, "latency_ms": 312,
          "details": [], "cached": false, "fetched_at": "2026-09-29T08:12:44Z",
          "raw": { /* provider's original response */ },
          "permalink": "https://www.virustotal.com/gui/ip-address/8.8.8.8"
        }
        // ... one entry per provider, keyed by provider name
      }
    }
  ]
}
```

Only need a few fields? Trim the output with `--include` / `--exclude` (`*` matches any list index):

```bash
iocscan --format json --include 'results.*.ioc,results.*.verdict,results.*.coverage' -f iocs.txt
iocscan --format json --exclude 'results.*.providers' -f iocs.txt  # summary only
```

For streaming pipelines, `--format jsonl` writes one flat JSON object per IOC per line.

### 7. CI / CD pipeline — fail the build on malicious IOCs

```bash
iocscan -f deploy-artifacts/ioc-extract.txt
case $? in
  0) echo "all clean — proceed";;
  1) echo "MALICIOUS IOC found — block release"; exit 1;;
  2) echo "suspicious IOC — manual review";;
  3) echo "bad input — check the IOC file"; exit 1;;
  4) echo "all providers failed — retry later";;
  5) echo "too little coverage — add API keys";;
esac
```

Or just the verdicts, one TSV line per IOC:

```bash
iocscan -q -f iocs.txt | awk -F'\t' '$2 == "malicious" { print $1 }'
```

### 8. Threat hunting — stream from logs

```bash
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' /var/log/access.log \
  | sort -u \
  | iocscan --format json \
  | jq '.results[] | select(.verdict == "malicious") | .ioc'
```

### 9. Turn IOCs into a SIEM / EDR hunt query

```bash
iocscan -F splunk-spl -f iocs.txt       # Splunk SPL
iocscan -F kql-sentinel -f iocs.txt     # Microsoft Sentinel KQL
iocscan -F kql-defender -f iocs.txt     # Microsoft Defender KQL
iocscan -F crowdstrike-fql -f iocs.txt  # CrowdStrike FQL
iocscan -F elastic-eql -f iocs.txt      # Elastic EQL (also: elastic-lucene)
```

Paste the output into your SIEM to find every host that talked to these IOCs. Hunt queries include **every** IOC you gave, whatever its verdict — the point is to search, not to judge.

The one exception is `suricata-ip-rules`: it produces detection rules that get loaded into a sensor, so it only emits `alert` rules for IPs scored `malicious` or `suspicious`:

```bash
iocscan -F suricata-ip-rules -f iocs.txt > iocscan.rules
```

### 10. Write-ups, tickets and spreadsheets

```bash
iocscan -F markdown --defang -f iocs.txt  # table for a ticket / Confluence / PR
iocscan -F csv -f iocs.txt > triage.csv   # ioc, type, verdict, responding, total, whitelisted
iocscan --links-only 203.0.113.10         # IOC <tab> provider <tab> link to the provider's own page
```

`--links-only` is handy when you want to open the evidence in each provider's web UI and attach screenshots.

### 11. Big batches — pick the providers

```bash
iocscan --skip virustotal -f big-list.txt                       # VT free tier is 4 req/min; skip it for a first pass
iocscan --only spamhaus,feodo,urlhaus,threatfox -f big-list.txt  # blocklists only — fast
iocscan --no-cache 203.0.113.10                                 # ignore cached results, ask everyone again
```

Provider names are the ones listed by `iocscan providers`.

### 12. Something looks off — check the providers

```bash
iocscan providers        # which providers are active, missing a key, remaining quota
iocscan health           # error rate, p95 latency, last error per provider (last 7 days)
iocscan health --days 1  # only today
iocscan --debug 8.8.8.8  # full request log on stderr (API keys are never printed)
```

If many IOCs come back `unknown`, `providers` usually shows the reason: a missing key, an expired key (`auth failed`), or a used-up quota (`429 rate limit`).

---

## Verdict logic (in short)

1. If any **authoritative** provider (URLhaus, Spamhaus DROP, Feodo Tracker, MalwareBazaar) returns `malicious` → final `malicious`, regardless of coverage.
2. Otherwise, if fewer than `min_coverage` providers (default 3) respond non-error/non-unknown → `unknown`.
3. Otherwise weighted vote at ≥30%: VirusTotal and OTX count as 2; others count as 1. `malicious` additionally requires total malicious weight ≥ 2 (one multi-engine provider, or two independent sources) — a lone weight-1 hit is demoted to `suspicious`. A malicious vote below the 30% bar likewise floors the verdict at `suspicious` — it is never silently outvoted to `clean`.
4. Whitelist override: if the IOC is a bundled-whitelist or Tranco top-1K domain, `malicious`/`suspicious` is clamped to `clean` (and the table marks it as whitelisted). Whitelist entries that are public suffixes (e.g. `github.io`, `blogspot.com`, `googleapis.com`) match exact only — their subdomains are tenant-controlled and never inherit the whitelist.

Record-based providers (VirusTotal, urlscan, OTX for URLs, hash lookups) vote `unknown` when they hold no record of an IOC — absence of evidence is not evidence of absence. Curated blocklists are different: "not listed" is a real observation there, so Feodo, Spamhaus, URLhaus and ThreatFox still cast a clean vote when they have no hit (the `— (no hit - clean)` cell above). The Tor relay list is enrichment-only: an IP's role in the Tor network — exit, guard, plain relay, or none of them — is context, not a vote.

OTX abstains the same way when every pulse naming an IOC is a bulk feed: it holds evidence but cannot attribute it, so it votes `unknown` rather than casting an affirmative weight-2 `clean` that would dilute another provider's hit. In a sample of 30 mid-tier legitimate domains this happened to 4 of them. It costs nothing when a VirusTotal key is configured (coverage stays at 3 of 4), but with an OTX key and no VirusTotal key those IOCs drop to 2 responding providers and come back `unknown` (exit `5`) instead of `clean` (exit `0`).

For URLs this matters in practice: a URL nobody has ever seen (no URLhaus listing, no VirusTotal record, no OTX pulses, few urlscan scans) falls below `min_coverage` and comes back `unknown` (exit code `5`) rather than `clean` (exit `0`). Scripts that branch on the exit code for URL batches should treat `5` as "insufficient data", not "safe".

---

## Cache

Results are cached at `~/.iocscan/cache.db` for 24 hours. Cached rows keep the fetch time of the original lookup (`fetched_at` in JSON output, alongside `cached: true`), so a merged result set never claims to be fresher than it is.

> **Upgrading:** run `iocscan cache clear` once after upgrading. Rows written by an older version were scored under older provider rules, and a cached verdict is replayed as-is until it expires.

```bash
iocscan --no-cache 8.8.8.8  # bypass cache for one run
iocscan cache stats         # rows, IOCs, age, disk size
iocscan cache clear         # flush everything
```

The cache merges with new fetches per-provider — missing providers (e.g. newly-added API key) are filled in incrementally.

---

## Whitelist and Tranco popularity tier

Popular, legitimate domains show up in threat feeds all the time (a CDN hosted one bad file, a cloud IP was reused). iocscan handles this in two ways, and they work differently:

| Source | Which domains | What you see | Changes the verdict? |
|---|---|---|---|
| Bundled whitelist | ~40 critical-infrastructure domains, always on | `⚑` | **Yes** — `malicious`/`suspicious` becomes `clean` |
| Tranco rank 1 – 1,000 | top 1K of the [Tranco](https://tranco-list.eu) list (optional) | `⚑ top-1k` | **Yes** — same as above |
| Tranco rank 1,001 – 10,000 | | `top-10k` | No — label only |
| Tranco rank 10,001 – 20,000 | | `top-20k` | No — label only |

The Tranco list is optional. Download it once, then refresh it about once a week:

```bash
iocscan whitelist update  # download the Tranco top-20K (~260 KB) to ~/.iocscan/tranco-20k.txt
iocscan whitelist stats   # how many domains, how old the file is
```

Without it, only the bundled whitelist is active and no `top-Nk` labels are shown.

**Why only the top 1K changes the verdict.** Lower in the ranking you find free-hosting and URL-shortener services that attackers use a lot. Clearing those automatically would hide real attacks. So ranks past 1K only get a label. For example, `githubcopilot.com` (rank ~4,200) shows as `● malicious (4/4) top-10k`: the label tells you "this is a popular domain, look again before you block it", but the verdict stays as it is.

How it reads in the output:

| Output | Meaning |
|---|---|
| `○ clean (5/5) ⚑ top-1k` | Whitelisted top-1K domain. If any provider had flagged it, the verdict would still be `clean` |
| `● malicious (4/4) top-10k` | Popular domain, verdict **not** changed — check it by hand |
| `● malicious (4/4)` | Not in the Tranco list at all |

The same information is in `--format json` (`whitelisted`, `tranco_tier`) and in `explain` (a `tranco:` line and, if the verdict was changed, a `whitelisted:` line showing the before and after).

Rules worth knowing:

- **Domains only.** IPs, URLs and hashes are never whitelisted and never get a tier.
- **Subdomains use their parent's rank.** `api.github.com` is ranked as `github.com`.
- **Shared-hosting domains are the exception.** Anyone can create a subdomain under `github.io`, `blogspot.com`, `googleapis.com` and similar, so `attacker.github.io` does **not** inherit `github.io`'s whitelist entry or rank.
- **`⚑` means "this domain is on the whitelist"**, whatever the providers said — you also see it on a domain that was clean anyway. To see whether the whitelist actually changed a verdict, run `explain`.

Upgrading from an older version: an existing `~/.iocscan/tranco-1k.txt` is still used until you run `whitelist update`, which replaces it with the 20K file.

---

## Uninstall

iocscan does not install anything system-wide. Removing the project comes down to deleting the three things it creates. A guided script is included for each platform:

```bash
./uninstall/uninstall.sh           # Linux / macOS
```

```powershell
.\uninstall\uninstall.ps1          # Windows (PowerShell)
```

The script walks through four steps, asking for confirmation before each:

| Step | What it removes |
|---|---|
| 1 | `~/.iocscan/` — API keys (`config.toml`), TI cache (`cache.db`), Tranco cache (`tranco-20k.txt`). Offers to back up `config.toml` first. |
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
