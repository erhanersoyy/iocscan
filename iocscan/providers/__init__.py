from iocscan.providers.abuseipdb import AbuseIPDB
from iocscan.providers.circl_hashlookup import CIRCLHashlookup
from iocscan.providers.crtsh import CrtSh
from iocscan.providers.feodo import Feodo
from iocscan.providers.greynoise import GreyNoise
from iocscan.providers.malwarebazaar import MalwareBazaar
from iocscan.providers.otx import OTX
from iocscan.providers.shodan_internetdb import ShodanInternetDB
from iocscan.providers.spamhaus import Spamhaus
from iocscan.providers.team_cymru import TeamCymru
from iocscan.providers.threatfox import ThreatFox
from iocscan.providers.tor import Tor
from iocscan.providers.urlhaus import URLhaus
from iocscan.providers.urlscan import URLScan
from iocscan.providers.virustotal import VirusTotal
from iocscan.providers.whois_age import WhoisAge
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
    CIRCLHashlookup(),
    URLScan(),
    ShodanInternetDB(),
    TeamCymru(),
    WhoisAge(),
    CrtSh(),
]
