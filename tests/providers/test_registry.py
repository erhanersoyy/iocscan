from iocscan.providers import ALL_PROVIDERS
from iocscan.providers.base import Provider


def test_thirteen_providers_registered():
    assert len(ALL_PROVIDERS) == 13
    names = {p.name for p in ALL_PROVIDERS}
    assert names == {
        "urlhaus", "threatfox", "feodo", "tor", "spamhaus",
        "virustotal", "abuseipdb", "otx", "greynoise",
        "malwarebazaar", "yaraify", "urlscan", "shodan_internetdb",
    }


def test_all_are_provider_instances():
    for p in ALL_PROVIDERS:
        assert isinstance(p, Provider)


def test_keyless_and_keyed_counts():
    keyless = [p for p in ALL_PROVIDERS if not p.requires_key]
    keyed = [p for p in ALL_PROVIDERS if p.requires_key]
    assert len(keyless) == 8   # URLhaus, ThreatFox, Feodo, Tor, Spamhaus, GreyNoise, URLScan, ShodanInternetDB
    assert len(keyed) == 5     # VirusTotal, AbuseIPDB, OTX, MalwareBazaar, YARAify


def test_mb_yaraify_has_key_via_abusech_alias():
    from iocscan.core.config import Config
    from iocscan.providers.malwarebazaar import MalwareBazaar
    from iocscan.providers.yaraify import YARAify

    cfg = Config(keys={"abusech": "K"})
    assert MalwareBazaar().has_key(cfg) is True
    assert YARAify().has_key(cfg) is True

    cfg_empty = Config()
    assert MalwareBazaar().has_key(cfg_empty) is False
    assert YARAify().has_key(cfg_empty) is False
