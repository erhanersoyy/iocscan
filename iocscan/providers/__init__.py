from iocscan.providers.abuseipdb import AbuseIPDB
from iocscan.providers.feodo import Feodo
from iocscan.providers.greynoise import GreyNoise
from iocscan.providers.malwarebazaar import MalwareBazaar
from iocscan.providers.otx import OTX
from iocscan.providers.spamhaus import Spamhaus
from iocscan.providers.threatfox import ThreatFox
from iocscan.providers.tor import Tor
from iocscan.providers.urlhaus import URLhaus
from iocscan.providers.virustotal import VirusTotal
from iocscan.providers.yaraify import YARAify

ALL_PROVIDERS = [
    URLhaus(),
    ThreatFox(),
    Feodo(),
    Tor(),
    Spamhaus(),
    VirusTotal(),
    AbuseIPDB(),
    OTX(),
    GreyNoise(),
    MalwareBazaar(),
    YARAify(),
]
