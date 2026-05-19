"""Per-provider permalink() template tests.

These are pure-function tests (no network, no fixtures) so they live in a
single file rather than scattered across every provider's test module.
"""
from __future__ import annotations

import base64

import pytest

from iocscan.providers.abuseipdb import AbuseIPDB
from iocscan.providers.base import IOCType
from iocscan.providers.feodo import Feodo
from iocscan.providers.greynoise import GreyNoise
from iocscan.providers.malwarebazaar import MalwareBazaar
from iocscan.providers.otx import OTX
from iocscan.providers.shodan_internetdb import ShodanInternetDB
from iocscan.providers.spamhaus import Spamhaus
from iocscan.providers.threatfox import ThreatFox
from iocscan.providers.tor import Tor
from iocscan.providers.urlhaus import URLhaus
from iocscan.providers.urlscan import URLScan
from iocscan.providers.virustotal import VirusTotal
from iocscan.providers.yaraify import YARAify


# --- VirusTotal -------------------------------------------------------------

@pytest.mark.parametrize("ioc,ioc_type,expected_substr", [
    ("1.2.3.4", IOCType.IP, "/gui/ip-address/1.2.3.4"),
    ("evil.com", IOCType.DOMAIN, "/gui/domain/evil.com"),
    ("d41d8cd98f00b204e9800998ecf8427e", IOCType.HASH_MD5, "/gui/file/d41d8cd9"),
    ("a" * 40, IOCType.HASH_SHA1, "/gui/file/" + "a" * 40),
    ("b" * 64, IOCType.HASH_SHA256, "/gui/file/" + "b" * 64),
])
def test_virustotal_permalink(ioc, ioc_type, expected_substr):
    assert expected_substr in VirusTotal().permalink(ioc, ioc_type)


def test_virustotal_permalink_url_uses_unpadded_urlsafe_base64():
    url = "https://evil.com/path"
    pl = VirusTotal().permalink(url, IOCType.URL)
    expected = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
    assert pl == f"https://www.virustotal.com/gui/url/{expected}"


# --- AbuseIPDB --------------------------------------------------------------

def test_abuseipdb_permalink_ip():
    assert AbuseIPDB().permalink("1.2.3.4", IOCType.IP) == "https://www.abuseipdb.com/check/1.2.3.4"


def test_abuseipdb_permalink_returns_none_for_non_ip():
    assert AbuseIPDB().permalink("evil.com", IOCType.DOMAIN) is None
    assert AbuseIPDB().permalink("a" * 32, IOCType.HASH_MD5) is None


# --- OTX --------------------------------------------------------------------

@pytest.mark.parametrize("ioc,ioc_type,expected_substr", [
    ("1.2.3.4", IOCType.IP, "/indicator/ip/1.2.3.4"),
    ("evil.com", IOCType.DOMAIN, "/indicator/domain/evil.com"),
    ("a" * 32, IOCType.HASH_MD5, "/indicator/file/" + "a" * 32),
])
def test_otx_permalink(ioc, ioc_type, expected_substr):
    assert expected_substr in OTX().permalink(ioc, ioc_type)


def test_otx_permalink_url_is_quoted():
    pl = OTX().permalink("https://evil.com/a?b=c", IOCType.URL)
    # `:` `/` `?` `=` all percent-encoded by quote(safe="")
    assert pl == "https://otx.alienvault.com/indicator/url/https%3A%2F%2Fevil.com%2Fa%3Fb%3Dc"


# --- URLhaus ----------------------------------------------------------------

def test_urlhaus_permalink_ip_and_domain():
    assert URLhaus().permalink("1.2.3.4", IOCType.IP) == "https://urlhaus.abuse.ch/host/1.2.3.4/"
    assert URLhaus().permalink("evil.com", IOCType.DOMAIN) == "https://urlhaus.abuse.ch/host/evil.com/"


def test_urlhaus_permalink_url_is_none():
    """URLhaus has no stable per-URL deeplink for arbitrary URLs."""
    assert URLhaus().permalink("https://evil.com/x", IOCType.URL) is None


# --- ThreatFox --------------------------------------------------------------

@pytest.mark.parametrize("ioc,ioc_type", [
    ("1.2.3.4", IOCType.IP),
    ("evil.com", IOCType.DOMAIN),
    ("a" * 64, IOCType.HASH_SHA256),
])
def test_threatfox_permalink_works_for_all_types(ioc, ioc_type):
    pl = ThreatFox().permalink(ioc, ioc_type)
    assert pl is not None
    assert pl.startswith("https://threatfox.abuse.ch/browse.php?search=")


def test_threatfox_permalink_url_is_quoted():
    pl = ThreatFox().permalink("https://evil.com/a?b=c", IOCType.URL)
    assert pl == "https://threatfox.abuse.ch/browse.php?search=https%3A%2F%2Fevil.com%2Fa%3Fb%3Dc"


# --- MalwareBazaar ---------------------------------------------------------

@pytest.mark.parametrize("ioc_type", [IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256])
def test_malwarebazaar_permalink_hash(ioc_type):
    pl = MalwareBazaar().permalink("a" * 64, ioc_type)
    assert pl == "https://bazaar.abuse.ch/sample/" + "a" * 64 + "/"


def test_malwarebazaar_permalink_non_hash_is_none():
    assert MalwareBazaar().permalink("1.2.3.4", IOCType.IP) is None


# --- YARAify ---------------------------------------------------------------

@pytest.mark.parametrize("ioc_type", [IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256])
def test_yaraify_permalink_hash(ioc_type):
    pl = YARAify().permalink("a" * 64, ioc_type)
    assert pl == "https://yaraify.abuse.ch/sample/" + "a" * 64 + "/"


def test_yaraify_permalink_non_hash_is_none():
    assert YARAify().permalink("1.2.3.4", IOCType.IP) is None


# --- GreyNoise -------------------------------------------------------------

def test_greynoise_permalink_ip():
    assert GreyNoise().permalink("1.2.3.4", IOCType.IP) == "https://www.greynoise.io/viz/ip/1.2.3.4"


def test_greynoise_permalink_non_ip_is_none():
    assert GreyNoise().permalink("evil.com", IOCType.DOMAIN) is None


# --- URLScan ---------------------------------------------------------------

def test_urlscan_permalink_url_is_quoted_inside_search_fragment():
    pl = URLScan().permalink("https://evil.com/a?b=c", IOCType.URL)
    assert pl == (
        'https://urlscan.io/search/#page.url%3A%22'
        "https%3A%2F%2Fevil.com%2Fa%3Fb%3Dc"
        '%22'
    )


def test_urlscan_permalink_non_url_is_none():
    assert URLScan().permalink("1.2.3.4", IOCType.IP) is None


# --- ShodanInternetDB ------------------------------------------------------

def test_shodan_internetdb_permalink_ip():
    assert ShodanInternetDB().permalink("1.2.3.4", IOCType.IP) == "https://internetdb.shodan.io/1.2.3.4"


def test_shodan_internetdb_permalink_non_ip_is_none():
    assert ShodanInternetDB().permalink("evil.com", IOCType.DOMAIN) is None


# --- No-deeplink providers (default Provider.permalink() returns None) -----

@pytest.mark.parametrize("provider_cls", [Feodo, Spamhaus, Tor])
def test_bulk_blocklist_providers_have_no_permalink(provider_cls):
    """Feodo / Spamhaus / Tor have no per-IOC web UI — default None is correct."""
    assert provider_cls().permalink("1.2.3.4", IOCType.IP) is None
