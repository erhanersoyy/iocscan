from pathlib import Path
import httpx

from iocscan.core.config import Config
from iocscan.providers.base import IOCType, Verdict
from iocscan.providers.virustotal import VirusTotal

FIX = Path(__file__).parent.parent / "fixtures" / "responses" / "virustotal"


def _c(h):
    return httpx.AsyncClient(transport=httpx.MockTransport(h), timeout=5.0)


async def test_no_key_returns_error_no_network():
    called = []
    def h(req):
        called.append(True)
        return httpx.Response(200, content="{}")
    async with _c(h) as c:
        r = await VirusTotal().lookup("1.2.3.4", IOCType.IP, c, Config())
    assert r.verdict == Verdict.ERROR
    assert r.error == "key required"
    assert called == []


async def test_ip_hit_malicious():
    body = (FIX / "ip_hit.json").read_text()
    def h(req):
        assert req.url.path.endswith("/ip_addresses/1.2.3.4")
        assert req.headers["x-apikey"] == "KEY"
        return httpx.Response(200, content=body)
    async with _c(h) as c:
        cfg = Config(keys={"virustotal": "KEY"})
        r = await VirusTotal().lookup("1.2.3.4", IOCType.IP, c, cfg)
    assert r.verdict == Verdict.MALICIOUS
    assert r.score == "12/70"


async def test_ip_clean():
    body = (FIX / "ip_clean.json").read_text()
    async with _c(lambda req: httpx.Response(200, content=body)) as c:
        cfg = Config(keys={"virustotal": "KEY"})
        r = await VirusTotal().lookup("8.8.8.8", IOCType.IP, c, cfg)
    assert r.verdict == Verdict.CLEAN


async def test_domain_routes_to_domains_endpoint():
    body = (FIX / "ip_clean.json").read_text()
    captured = {}
    def h(req):
        captured["path"] = req.url.path
        return httpx.Response(200, content=body)
    async with _c(h) as c:
        cfg = Config(keys={"virustotal": "KEY"})
        await VirusTotal().lookup("evil.com", IOCType.DOMAIN, c, cfg)
    assert captured["path"].endswith("/domains/evil.com")


async def test_429_rate_limit():
    async with _c(lambda req: httpx.Response(429)) as c:
        cfg = Config(keys={"virustotal": "KEY"})
        r = await VirusTotal().lookup("1.2.3.4", IOCType.IP, c, cfg)
    assert r.verdict == Verdict.ERROR
    assert "429" in r.error


async def test_401_auth_failed():
    async with _c(lambda req: httpx.Response(401)) as c:
        cfg = Config(keys={"virustotal": "BAD"})
        r = await VirusTotal().lookup("1.2.3.4", IOCType.IP, c, cfg)
    assert r.verdict == Verdict.ERROR
    assert "auth" in r.error


async def test_hash_routes_to_files_endpoint():
    body = (FIX / "file_hit.json").read_text()
    captured = {}
    def h(req):
        captured["path"] = req.url.path
        return httpx.Response(200, content=body)
    async with _c(h) as c:
        cfg = Config(keys={"virustotal": "KEY"})
        r = await VirusTotal().lookup(
            "d41d8cd98f00b204e9800998ecf8427e", IOCType.HASH_MD5, c, cfg,
        )
    assert captured["path"].endswith("/files/d41d8cd98f00b204e9800998ecf8427e")
    assert r.verdict == Verdict.MALICIOUS
    assert r.score == "45/70"


async def test_url_routes_to_urls_endpoint_with_base64_id():
    import base64
    url = "https://evil.com/path"
    expected_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
    body = (FIX / "file_hit.json").read_text()  # reuse PR2A fixture; same shape
    captured = {}
    def h(req):
        captured["path"] = req.url.path
        return httpx.Response(200, content=body)
    async with _c(h) as c:
        cfg = Config(keys={"virustotal": "KEY"})
        r = await VirusTotal().lookup(url, IOCType.URL, c, cfg)
    assert captured["path"].endswith(f"/urls/{expected_id}")
    assert r.verdict == Verdict.MALICIOUS
    assert r.score == "45/70"
