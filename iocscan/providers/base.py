from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx
    from iocscan.core.config import Config


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"


class Verdict(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"
    ERROR = "error"


@dataclass(frozen=True)
class ProviderResult:
    provider: str
    verdict: Verdict
    score: str
    raw: dict | None
    error: str | None
    latency_ms: int


class Provider(ABC):
    name: str
    supports: set[IOCType]
    requires_key: bool = False
    max_rps: float | None = None
    max_per_day: int | None = None
    enrichment_only: bool = False

    @abstractmethod
    async def lookup(
        self, ioc: str, ioc_type: IOCType, client: "httpx.AsyncClient", config: "Config"
    ) -> ProviderResult: ...

    def has_key(self, config: "Config") -> bool:
        return not self.requires_key or bool(config.key_for(self.name))

    def permalink(self, ioc: str, ioc_type: IOCType) -> str | None:
        """Return a human-clickable URL to the provider's web UI for this IOC.

        Default: None (provider has no web UI or template not yet defined).
        Subclasses override to provide a URL template.
        """
        return None


def err_result(name: str, msg: str, start: float) -> ProviderResult:
    """Build an ERROR ProviderResult with the elapsed latency since `start`."""
    latency = int((time.perf_counter() - start) * 1000)
    return ProviderResult(name, Verdict.ERROR, "", None, msg, latency)
