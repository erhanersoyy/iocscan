import json

from iocscan.core.scan import ScanResult
from iocscan.providers.base import IOCType, ProviderResult, Verdict
from iocscan.ui.json_out import render_json


def test_json_includes_scan_metadata_and_results():
    r = ProviderResult("vt", Verdict.MALICIOUS, "12/70", {"raw": True}, None, 412)
    scan = ScanResult("1.2.3.4", IOCType.IP, Verdict.MALICIOUS, [r], 1, 1)
    out = json.loads(render_json([scan], min_coverage=3))
    assert "scan" in out
    assert out["scan"]["min_coverage"] == 3
    assert "tool_version" in out["scan"]
    assert "timestamp" in out["scan"]
    assert out["results"][0]["ioc"] == "1.2.3.4"
    assert out["results"][0]["verdict"] == "malicious"
    assert out["results"][0]["coverage"] == {"responding": 1, "total": 1}
    assert out["results"][0]["providers"]["vt"]["verdict"] == "malicious"
    assert out["results"][0]["providers"]["vt"]["raw"] == {"raw": True}


def test_json_includes_errors():
    r = ProviderResult("vt", Verdict.ERROR, "", None, "key required", 0)
    scan = ScanResult("x.com", IOCType.DOMAIN, Verdict.UNKNOWN, [r], 0, 1)
    out = json.loads(render_json([scan], min_coverage=3))
    assert out["results"][0]["providers"]["vt"]["error"] == "key required"
