from __future__ import annotations

import json
import time

import httpx

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Provider, ProviderResult, Verdict, err_result as _err

ENDPOINT = "https://yaraify-api.abuse.ch/api/v1/"


class YARAify(Provider):
    name = "yaraify"
    supports = {IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256}
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
            for task in tasks:
                for result in task.get("static_results") or []:
                    rule = result.get("rule_name")
                    if rule:
                        return ProviderResult(self.name, Verdict.MALICIOUS, rule, data, None, latency)
            # ok status but no rule names — still a hit
            if tasks:
                return ProviderResult(self.name, Verdict.MALICIOUS, "yara match", data, None, latency)
        return ProviderResult(self.name, Verdict.CLEAN, "—", data, None, latency)
