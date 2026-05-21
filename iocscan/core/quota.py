"""Live API-quota probes for `iocscan providers`.

Only providers that expose a quota endpoint or rate-limit headers are
probed live; everything else returns `note="No Key"` (no key configured)
or `note="no quota API"` (key present but no remote way to query it).

This module is intentionally tiny and provider-aware: keeping the probes
here (rather than as methods on each Provider) avoids polluting the
provider plugin contract with optional `quota_probe` hooks that most
providers would leave as no-ops.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

import httpx

from iocscan.core.config import Config
from iocscan.providers.base import Provider


@dataclass(frozen=True)
class QuotaResult:
    provider: str
    used: int | None
    allowed: int | None
    # "" on success, otherwise "No Key" / "no quota API" / "timeout" / "error: ..."
    note: str


# Only these providers expose a machine-readable quota endpoint or headers.
_PROBEABLE = {"virustotal", "abuseipdb"}


async def probe_quotas(
    providers: list[Provider],
    config: Config,
    client: httpx.AsyncClient,
    *,
    timeout_seconds: float = 20.0,
) -> dict[str, QuotaResult]:
    """Return one QuotaResult per provider in `providers`, keyed by name.

    Probes are dispatched concurrently. Providers without a known probe path
    short-circuit to a static QuotaResult without making network calls.
    """
    out: dict[str, QuotaResult] = {}
    tasks: list[tuple[str, asyncio.Task]] = []

    for p in providers:
        if not p.has_key(config):
            out[p.name] = QuotaResult(p.name, None, None, "No Key")
            continue
        if p.name not in _PROBEABLE:
            out[p.name] = QuotaResult(p.name, None, None, "no quota API")
            continue
        coro = _probe_one(p, config, client, timeout_seconds)
        tasks.append((p.name, asyncio.create_task(coro)))

    for name, task in tasks:
        try:
            out[name] = await task
        except Exception as e:
            out[name] = QuotaResult(name, None, None, f"error: {e.__class__.__name__}")

    return out


async def _probe_one(
    provider: Provider,
    config: Config,
    client: httpx.AsyncClient,
    timeout: float,
) -> QuotaResult:
    try:
        if provider.name == "virustotal":
            return await asyncio.wait_for(_probe_vt(config, client), timeout=timeout)
        if provider.name == "abuseipdb":
            return await asyncio.wait_for(_probe_abuseipdb(config, client), timeout=timeout)
    except asyncio.TimeoutError:
        return QuotaResult(provider.name, None, None, "timeout")
    except httpx.HTTPError as e:
        return QuotaResult(provider.name, None, None, f"error: {e.__class__.__name__}")
    # Fallback — shouldn't be reached given _PROBEABLE guard in probe_quotas
    return QuotaResult(provider.name, None, None, "no quota API")


async def _probe_vt(config: Config, client: httpx.AsyncClient) -> QuotaResult:
    key = config.key_for("virustotal")
    url = f"https://www.virustotal.com/api/v3/users/{key}/overall_quotas"
    resp = await client.get(url, headers={"x-apikey": key})
    if resp.status_code != 200:
        return QuotaResult("virustotal", None, None, f"error: {resp.status_code}")
    try:
        # VT v3 overall_quotas response shape (as of 2026):
        #   {"data": {"api_requests_daily": {"user": {"used": N, "allowed": M}}, ...}}
        # Earlier docs/snippets show an `attributes` wrapper that the live API
        # no longer returns — accessing it raised KeyError ("error: parse").
        daily = resp.json()["data"]["api_requests_daily"]["user"]
    except (KeyError, ValueError, TypeError):
        return QuotaResult("virustotal", None, None, "error: parse")
    return QuotaResult("virustotal", int(daily["used"]), int(daily["allowed"]), "")


async def _probe_abuseipdb(config: Config, client: httpx.AsyncClient) -> QuotaResult:
    key = config.key_for("abuseipdb")
    # 1.1.1.1 is intentionally benign; burns 1 daily check quota —
    # accepted trade-off for live rate-limit visibility.
    resp = await client.get(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": "1.1.1.1", "maxAgeInDays": "1"},
        headers={"Key": key, "Accept": "application/json"},
    )
    limit = resp.headers.get("X-RateLimit-Limit")
    remaining = resp.headers.get("X-RateLimit-Remaining")
    if limit is None or remaining is None:
        return QuotaResult("abuseipdb", None, None, f"error: {resp.status_code}")
    try:
        limit_i, remaining_i = int(limit), int(remaining)
    except ValueError:
        return QuotaResult("abuseipdb", None, None, "error: parse")
    return QuotaResult("abuseipdb", limit_i - remaining_i, limit_i, "")
