# iocscan

Blue-team CLI that produces a consolidated `malicious / suspicious / clean / unknown` verdict for IP addresses and domains by querying nine open-source threat-intelligence providers in parallel.

Five providers work out of the box (no API key). Four more activate when you add free-tier API keys.

## Install

```bash
pipx install iocscan
```

## Quick start

```bash
iocscan 1.2.3.4 evil.com
iocscan -f iocs.txt
cat iocs.txt | iocscan
iocscan --json 8.8.8.8 > result.json
```

## Providers

| Provider | Key required | IOC types |
|---|---|---|
| URLhaus | no | IP, domain |
| ThreatFox | no | IP, domain |
| Feodo Tracker | no | IP |
| Tor Exit List | no | IP |
| Spamhaus DROP | no | IP |
| VirusTotal | yes (free 500/day) | IP, domain |
| AbuseIPDB | yes (free 1000/day) | IP |
| AlienVault OTX | yes (free ~10k/h) | IP, domain |
| GreyNoise Community | yes (free 50/week) | IP |

## Configure keys

```bash
iocscan config set virustotal YOUR_KEY
iocscan config set abuseipdb  YOUR_KEY
iocscan config set otx        YOUR_KEY
iocscan config set greynoise  YOUR_KEY
```

Or via environment variables:
```bash
export IOCSCAN_VT_KEY=...
export IOCSCAN_ABUSEIPDB_KEY=...
export IOCSCAN_OTX_KEY=...
export IOCSCAN_GREYNOISE_KEY=...
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | All IOCs clean |
| 1 | At least one IOC malicious |
| 2 | At least one IOC suspicious (no malicious) |
| 3 | Argument / parse error |
| 4 | All providers failed |
| 5 | All IOCs unknown (insufficient coverage) |

## Cache

Results are cached in `~/.iocscan/cache.db` for 24 hours. Use `--no-cache` to bypass, `iocscan cache clear` to flush.

## License

MIT.
