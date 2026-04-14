import json
import pytest
from pathlib import Path
from output.reporter import Reporter, save_json_report, generate_scan_summary


def make_results():
    return {
        "target": "http://example.com",
        "scan_time": "2026-01-01T00:00:00",
        "modules": {
            "scanner": {"ports": [{"port": 80, "status": "open", "service": "http"}], "open_count": 1},
            "sqli": {"vulnerable": True, "payload": "' OR '1'='1", "vulnerabilities": [{"url": "http://example.com/?id=1", "payload": "' OR '1'='1", "type": "error-based", "evidence": "SQL syntax"}]},
            "xss": {"vulnerable": False, "payload": "", "vulnerabilities": []},
            "fuzzer": {"found": 2, "paths": ["/admin", "/login"], "scanned": 100},
            "subdomain": {"found": 1, "subdomains": [{"subdomain": "api.example.com", "record_type": "A", "value": "1.2.3.4", "verified": True}], "scanned": 50},
        },
    }


def test_save_json_report_writes_valid_json(tmp_path):
    out = tmp_path / "report.json"
    save_json_report(make_results(), str(out))
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["target"] == "http://example.com"


def test_reporter_save_and_load(tmp_path):
    out = tmp_path / "report.json"
    r = Reporter()
    r.save(make_results(), out)
    loaded = r.load(out)
    assert loaded["target"] == "http://example.com"


def test_generate_scan_summary_tallies_correctly():
    summary = generate_scan_summary(make_results())
    assert "scanner" in summary["modules_completed"]
    assert "sqli" in summary["modules_completed"]
    # 1 open port + 1 sqli vuln = 2
    assert summary["vulnerabilities_found"] == 2
    # fuzzer scanned 100 + subdomain 50 = 150
    assert summary["total_requests"] == 150


def test_reporter_save_html(tmp_path):
    out = tmp_path / "report.html"
    r = Reporter()
    r.save_html(make_results(), out)
    assert out.exists()
    content = out.read_text()
    assert "Pynzor Scan Report" in content
    assert "http://example.com" in content
