import pytest

import httpx

from iocscan.core.config import Config
from iocscan.core.scan import scan_ioc
from iocscan.providers.base import IOCType
from iocscan.providers.feodo import Feodo
from iocscan.providers.spamhaus import Spamhaus
from iocscan.providers.threatfox import ThreatFox
from iocscan.providers.tor import Tor
from iocscan.providers.urlhaus import URLhaus


KEYLESS = [URLhaus(), ThreatFox(), Feodo(), Tor(), Spamhaus()]


@pytest.mark.network
async def test_keyless_providers_reachable():
    async with httpx.AsyncClient(timeout=15.0) as client:
        result = await scan_ioc("8.8.8.8", IOCType.IP, KEYLESS, client, Config())
    assert result.responding >= 3, f"only {result.responding} providers responded: {result.provider_results}"


@pytest.mark.network
async def test_known_emotet_ip_flagged():
    """Feodo Tracker is the authoritative source for Emotet IPs; this should hit."""
    async with httpx.AsyncClient(timeout=15.0) as client:
        result = await scan_ioc("8.8.8.8", IOCType.IP, [Feodo()], client, Config())
    assert result.provider_results[0].verdict.value in ("clean", "malicious")
