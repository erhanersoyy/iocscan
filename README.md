# iocscan

Blue-team CLI that produces a consolidated `malicious / suspicious / clean / unknown` verdict for IP addresses and domains by querying nine open-source threat-intelligence providers in parallel.

Four providers work out of the box (no API key). Five more activate when you add free-tier API keys.

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
| URLhaus | yes (free, single key for all abuse.ch) | IP, domain |
| ThreatFox | yes (free, single key for all abuse.ch) | IP, domain |
| Feodo Tracker | no | IP |
| Tor Exit List | no | IP |
| Spamhaus DROP | no | IP |
| VirusTotal | yes (free 500/day) | IP, domain |
| AbuseIPDB | yes (free 1000/day) | IP |
| AlienVault OTX | yes (free ~10k/h) | IP, domain |
| GreyNoise Community | no (optional key for higher rate limit; anonymous use is rate-limited) | IP |

## Configure keys

```bash
iocscan config set abusech    YOUR_KEY  # single key for URLhaus + ThreatFox
iocscan config set virustotal YOUR_KEY
iocscan config set abuseipdb  YOUR_KEY
iocscan config set otx        YOUR_KEY
iocscan config set greynoise  YOUR_KEY  # optional; raises anonymous rate limit
```

Or via environment variables:
```bash
export IOCSCAN_ABUSECH_KEY=...  # URLhaus + ThreatFox
export IOCSCAN_VT_KEY=...
export IOCSCAN_ABUSEIPDB_KEY=...
export IOCSCAN_OTX_KEY=...
export IOCSCAN_GREYNOISE_KEY=...  # optional
```

## Notes

abuse.ch (URLhaus and ThreatFox) added an Auth-Key requirement to their query APIs.
Registration is free at https://auth.abuse.ch — the same single key covers both providers.

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
