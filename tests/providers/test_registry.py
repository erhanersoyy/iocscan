from iocscan.providers import ALL_PROVIDERS
from iocscan.providers.base import Provider


def test_nine_providers_registered():
    assert len(ALL_PROVIDERS) == 9
    names = {p.name for p in ALL_PROVIDERS}
    assert names == {
        "urlhaus", "threatfox", "feodo", "tor", "spamhaus",
        "virustotal", "abuseipdb", "otx", "greynoise",
    }


def test_all_are_provider_instances():
    for p in ALL_PROVIDERS:
        assert isinstance(p, Provider)


def test_five_keyless_four_keyed():
    keyless = [p for p in ALL_PROVIDERS if not p.requires_key]
    keyed = [p for p in ALL_PROVIDERS if p.requires_key]
    assert len(keyless) == 5
    assert len(keyed) == 4
