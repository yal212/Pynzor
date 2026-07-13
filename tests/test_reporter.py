import json
import pytest
from pynzor.output.reporter import (
    Reporter,
    save_json_report,
    generate_scan_summary,
    build_report,
    severity_from_grade,
    highest_severity,
    SCHEMA_VERSION,
    SEVERITY_ORDER,
)


def make_modules():
    return {
        "scanner": {"ports": [{"port": 80, "status": "open", "service": "http"}], "open_count": 1},
        "sqli": {"vulnerable": True, "payload": "' OR '1'='1"},
        "xss": {"vulnerable": False, "payload": ""},
        "fuzzer": {"found": 2, "paths": ["/admin", "/login"], "scanned": 100},
        "subdomain": {"found": 1, "subdomains": [{"subdomain": "api.example.com", "record_type": "A", "value": "1.2.3.4", "verified": True}], "scanned": 50},
    }


def make_results():
    """A normalized full-scan report envelope (current schema)."""
    return build_report(
        module="scan",
        target="http://example.com",
        findings=[
            {"module": "ports", "port": 80, "service": "http"},
            {"module": "sqli", "payload": "' OR '1'='1", "vulnerable": True},
        ],
        severity="high",
        metadata={"scan_time": "2026-01-01T00:00:00", "modules": make_modules()},
        timestamp="2026-01-01T00:00:00",
    )


def test_build_report_has_normalized_top_level_fields():
    """build_report emits the shared envelope with every required field."""
    report = build_report(module="headers", target="http://example.com", findings=[])
    for key in ("schema_version", "target", "timestamp", "module", "findings", "severity", "metadata"):
        assert key in report
    assert report["schema_version"] == SCHEMA_VERSION
    assert report["module"] == "headers"
    assert report["findings"] == []
    assert report["severity"] in SEVERITY_ORDER


@pytest.mark.parametrize(
    "module, findings, severity, metadata",
    [
        ("ports", [{"port": 22, "status": "open", "service": "ssh"}], "info", {"open_count": 1}),
        ("fuzz", [{"url": "http://x/admin", "status": 200, "length": 10, "word": "admin"}], "info", {"mode": "directory", "found_count": 1}),
        ("headers", [{"header": "Content-Security-Policy", "present": False, "risk": "high"}], "medium", {"score": 55, "grade": "C"}),
        ("sqli", [{"url": "http://x/?id=1", "payload": "'", "type": "error", "evidence": "SQL"}], "high", {"vulnerable": True}),
        ("xss", [], "info", {"vulnerable": False}),
        ("subdomain", [{"subdomain": "api.x", "record_type": "A", "value": "1.2.3.4", "verified": True}], "info", {"found_count": 1}),
    ],
)
def test_build_report_per_module(tmp_path, module, findings, severity, metadata):
    """Each module type produces a saveable, round-trippable normalized report."""
    report = build_report(module=module, target="http://example.com", findings=findings, severity=severity, metadata=metadata)
    out = tmp_path / f"{module}.json"
    Reporter().save(report, out)
    loaded = Reporter().load(out)
    assert loaded["module"] == module
    assert loaded["severity"] == severity
    assert loaded["metadata"] == metadata
    assert loaded["findings"] == findings


def test_severity_from_grade():
    assert severity_from_grade("A") == "info"
    assert severity_from_grade("F") == "critical"
    assert severity_from_grade(None) == "critical"


def test_highest_severity():
    assert highest_severity(["info", "high", "low"]) == "high"
    assert highest_severity([]) == "info"


def test_save_json_report_writes_valid_json(tmp_path):
    """save_json_report writes a file containing valid, round-trippable JSON."""
    out = tmp_path / "report.json"
    save_json_report(make_results(), str(out))
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["target"] == "http://example.com"


def test_reporter_save_and_load(tmp_path):
    """Reporter.save then Reporter.load round-trips the results."""
    out = tmp_path / "report.json"
    r = Reporter()
    r.save(make_results(), out)
    loaded = r.load(out)
    assert loaded["target"] == "http://example.com"
    assert loaded["schema_version"] == SCHEMA_VERSION


def test_generate_scan_summary_reads_normalized_envelope():
    """generate_scan_summary tallies modules/vulns/requests from metadata.modules."""
    summary = generate_scan_summary(make_results())
    assert "scanner" in summary["modules_completed"]
    assert "sqli" in summary["modules_completed"]
    # 1 open port + 1 sqli vuln = 2
    assert summary["vulnerabilities_found"] == 2
    # fuzzer scanned 100 + subdomain 50 = 150
    assert summary["total_requests"] == 150
    assert summary["timestamp"] == "2026-01-01T00:00:00"


def test_generate_scan_summary_backward_compatible_with_legacy_layout():
    """Reports saved before the envelope (top-level 'modules') still summarize."""
    legacy = {"target": "http://example.com", "scan_time": "2026-01-01T00:00:00", "modules": make_modules()}
    summary = generate_scan_summary(legacy)
    assert summary["vulnerabilities_found"] == 2
    assert summary["total_requests"] == 150


def test_reporter_save_html(tmp_path):
    """Reporter.save_html renders an HTML report containing the target and title."""
    out = tmp_path / "report.html"
    r = Reporter()
    r.save_html(make_results(), out)
    assert out.exists()
    content = out.read_text()
    assert "Pynzor Scan Report" in content
    assert "http://example.com" in content
    assert "Port Scanner" in content
