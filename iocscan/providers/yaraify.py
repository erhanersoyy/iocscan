from __future__ import annotations

import json
import time

import httpx

from iocscan.core.config import Config
from iocscan.providers.base import HASH_TYPES, IOCType, Provider, ProviderResult, Verdict, err_result as _err

ENDPOINT = "https://yaraify-api.abuse.ch/api/v1/"


class YARAify(Provider):
    name = "yaraify"
    supports = {*HASH_TYPES}
    requires_key = True
    key_alias = "abusech"
    max_rps = 5.0

    async def lookup(
        self, ioc: str, ioc_type: IOCType, client: httpx.AsyncClient, config: Config
    ) -> ProviderResult:
        start = time.perf_counter()
        key = config.key_for("abusech")
        if not key:
            return ProviderResult(self.name, Verdict.ERROR, "", None, "key required (abusech)", 0)
        payload = {"query": "lookup_hash", "search_term": ioc}
        try:
            resp = await client.post(
                ENDPOINT,
                content=json.dumps(payload),
                headers={"Auth-Key": key, "Content-Type": "application/json"},
            )
        except httpx.HTTPError as e:
            return _err(self.name, f"network: {e.__class__.__name__}", start)
        latency = int((time.perf_counter() - start) * 1000)
        if resp.status_code == 429:
            return ProviderResult(self.name, Verdict.ERROR, "", None, "429 rate limit", latency)
        if resp.status_code in (401, 403):
            return ProviderResult(
                self.name, Verdict.ERROR, "", None, "auth failed (Auth-Key required)", latency
            )
        if resp.status_code >= 500:
            return ProviderResult(
                self.name, Verdict.ERROR, "", None, f"{resp.status_code} server", latency
            )
        if resp.status_code >= 400:
            return ProviderResult(
                self.name, Verdict.ERROR, "", None, f"{resp.status_code}", latency
            )
        try:
            data = resp.json()
        except ValueError:
            return ProviderResult(self.name, Verdict.ERROR, "", None, "parse error", latency)
        if data.get("query_status") == "ok":
            tasks = (data.get("data") or {}).get("tasks") or []
            # Collect every rule across all tasks. Dedup is case- and
            # whitespace-insensitive (the same rule reported by two scanners
            # with different casing should appear once); preserve display
            # casing of the first occurrence.
            rules: list[str] = []
            seen: set[str] = set()
            for task in tasks:
                if not isinstance(task, dict):
                    continue
                for result in task.get("static_results") or []:
                    rule = (result.get("rule_name") or "").strip()
                    if not rule:
                        continue
                    key = rule.lower()
                    if key in seen:
                        continue
                    seen.add(key)
                    rules.append(rule)
            if rules:
                details = tuple(f"rule: {r}" for r in rules[1:])
                return ProviderResult(
                    self.name, Verdict.MALICIOUS, rules[0], data, None, latency, details=details
                )
            if tasks:
                # ok status, payload has tasks but no extractable rule names —
                # still a hit; surface the task count so the user knows there
                # is evidence in `raw` even without a named rule.
                return ProviderResult(
                    self.name, Verdict.MALICIOUS, "yara match", data, None, latency,
                    details=(f"tasks: {len(tasks)} (no named rules)",),
                )
        return ProviderResult(self.name, Verdict.CLEAN, "—", data, None, latency)

    def permalink(self, ioc: str, ioc_type: IOCType) -> str | None:
        if ioc_type in HASH_TYPES:
            return f"https://yaraify.abuse.ch/sample/{ioc}/"
        return None
