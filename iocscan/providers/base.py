from __future__ import annotations

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

    @abstractmethod
    async def lookup(
        self, ioc: str, ioc_type: IOCType, client: "httpx.AsyncClient", config: "Config"
    ) -> ProviderResult: ...

    def has_key(self, config: "Config") -> bool:
        return not self.requires_key or bool(config.key_for(self.name))
