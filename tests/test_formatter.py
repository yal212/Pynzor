"""Tests for the Rich console renderer in :mod:`pynzor.output.formatter`.

Output is captured via the module-level console's ``capture()`` context manager;
assertions target stable summary/verdict lines and table titles rather than
width-sensitive table cell contents.
"""

from datetime import datetime

from pynzor.output import formatter as fmt_module
from pynzor.output.formatter import (
    Formatter,
    format_ports_table,
    format_directories_table,
    format_headers_table,
    format_vulns_table,
    format_subdomains_table,
    format_score,
    format_title,
    print_json,
)
from pynzor.modules.scanner import PortResult, ScanResult
from pynzor.modules.fuzzer import FuzzResult, FuzzScanResult
from pynzor.modules.headers import HeaderAnalysis, HeaderResult
from pynzor.modules.sqli import SQLiResult
from pynzor.modules.xss import XSSResult
from pynzor.modules.subdomain import SubdomainResult, SubdomainScanResult


def render(method, *args) -> str:
    """Call a Formatter method under output capture and return the text."""
    formatter = Formatter()
    with fmt_module.console.capture() as capture:
        getattr(formatter, method)(*args)
    return capture.get()


def _now() -> datetime:
    return datetime.now()


# --- scanner -----------------------------------------------------------------


def test_scanner_results_hide_closed_ports():
    result = ScanResult(
        target="example.com",
        start_time=_now(),
        end_time=_now(),
        ports=[
            PortResult(port=80, status="open", service="http", latency=0.012),
            PortResult(port=81, status="closed", service=None, latency=0.0),
        ],
    )
    out = render("print_scanner_results", result)
    assert "Port Scan Results" in out
    assert "80" in out
    assert "Not shown: 1 closed port(s)" in out


def test_scanner_results_show_version_column_when_present():
    result = ScanResult(
        target="example.com",
        start_time=_now(),
        end_time=_now(),
        ports=[
            PortResult(
                port=22,
                status="open",
                service="ssh",
                latency=0.01,
                product="OpenSSH",
                version="9.6",
            ),
        ],
    )
    out = render("print_scanner_results", result)
    assert "Version" in out
    assert "OpenSSH" in out


# --- fuzzer ------------------------------------------------------------------


def test_fuzzer_directory_mode_reports_count_and_filtered():
    result = FuzzScanResult(
        target="https://example.com",
        start_time=_now(),
        end_time=_now(),
        found=[
            FuzzResult(
                url="https://example.com/admin",
                status_code=200,
                discovered=True,
                content_length=123,
                redirect=None,
            )
        ],
        mode="directory",
        baseline_filtered=3,
    )
    out = render("print_fuzzer_results", result)
    assert "Directory Fuzz Results" in out
    assert "Found 1 directories" in out
    assert "Filtered 3 paths" in out


def test_fuzzer_request_mode_and_baseline_note():
    result = FuzzScanResult(
        target="https://example.com/FUZZ",
        start_time=_now(),
        end_time=_now(),
        found=[
            FuzzResult(
                url="https://example.com/FUZZ",
                status_code=200,
                discovered=True,
                content_length=10,
                redirect=None,
                word="admin",
                words=5,
                lines=2,
            )
        ],
        mode="request",
        baseline_detected=True,
        baseline_note="Catch-all baseline detected",
    )
    out = render("print_fuzzer_results", result)
    assert "Request Fuzz Results" in out
    assert "Found 1 matching responses" in out
    assert "Catch-all baseline detected" in out


# --- headers -----------------------------------------------------------------


def test_headers_results_score_grade_and_missing():
    result = HeaderResult(
        target="https://example.com",
        start_time=_now(),
        end_time=_now(),
        analysis=[
            HeaderAnalysis(
                header="Content-Security-Policy",
                present=False,
                value=None,
                risk="high",
                description="",
                recommendation="",
            ),
            HeaderAnalysis(
                header="X-Frame-Options",
                present=True,
                value="DENY",
                risk="medium",
                description="",
                recommendation="",
            ),
        ],
        score=70,
        grade="C",
        missing_headers=["Content-Security-Policy"],
    )
    out = render("print_headers_results", result)
    assert "Security Headers Analysis" in out
    assert "Score: 70/100 (Grade: C)" in out
    assert "Content-Security-Policy" in out


# --- sqli / xss --------------------------------------------------------------


def test_sqli_results_vulnerable_and_clean():
    vuln = SQLiResult(
        target="https://example.com?id=1",
        start_time=_now(),
        end_time=_now(),
        vulnerable=True,
        payload="' OR '1'='1",
    )
    out = render("print_sqli_results", vuln)
    assert "VULNERABLE to SQL Injection" in out
    assert "' OR '1'='1" in out

    clean = SQLiResult(target="x", start_time=_now(), end_time=_now(), vulnerable=False)
    assert "No SQL injection vulnerabilities found" in render("print_sqli_results", clean)


def test_xss_results_vulnerable_and_clean():
    vuln = XSSResult(
        target="https://example.com?q=1",
        start_time=_now(),
        end_time=_now(),
        vulnerable=True,
        payload="<script>alert(1)</script>",
    )
    out = render("print_xss_results", vuln)
    assert "VULNERABLE to XSS" in out

    clean = XSSResult(target="x", start_time=_now(), end_time=_now(), vulnerable=False)
    assert "No XSS vulnerabilities found" in render("print_xss_results", clean)


# --- subdomain ---------------------------------------------------------------


def test_subdomain_results_with_wildcard_note():
    result = SubdomainScanResult(
        target="example.com",
        start_time=_now(),
        end_time=_now(),
        subdomains=[
            SubdomainResult(
                subdomain="api.example.com", record_type="A", value="1.2.3.4", verified=True
            )
        ],
        wildcard_detected=True,
        wildcard_ips=["9.9.9.9"],
        wildcard_filtered=2,
    )
    out = render("print_subdomain_results", result)
    assert "Subdomain Enumeration" in out
    assert "Found 1 subdomains" in out
    assert "Wildcard DNS detected" in out
    assert "Filtered 2 subdomains" in out


# --- status message helpers --------------------------------------------------


def test_status_message_helpers():
    assert "hi" in render("print_success", "hi")
    assert "boom" in render("print_error", "boom")
    assert "warn" in render("print_warning", "warn")
    assert "info" in render("print_info", "info")
    assert "Section" in render("print_header", "Section")


# --- module-level table/panel builders ---------------------------------------


def test_format_table_builders_run():
    assert format_ports_table([{"port": 80, "status": "open", "service": "http"}]).row_count == 1
    assert (
        format_directories_table(
            [{"url": "https://x/a", "status_code": 301, "redirect": "/b"}]
        ).row_count
        == 1
    )
    assert (
        format_headers_table([{"header": "CSP", "present": False, "risk": "high"}]).row_count == 1
    )
    assert (
        format_vulns_table([{"url": "https://x", "type": "sqli", "evidence": "err"}]).row_count == 1
    )
    assert (
        format_subdomains_table(
            [{"subdomain": "a.x", "record_type": "A", "value": "1.1.1.1"}]
        ).row_count
        == 1
    )


def test_format_score_and_title():
    panel = format_score(92, "A")
    title = format_title("Report")
    with fmt_module.console.capture() as capture:
        fmt_module.console.print(panel)
        fmt_module.console.print(title)
    out = capture.get()
    assert "92/100" in out
    assert "Report" in out


def test_print_json_renders_value():
    with fmt_module.console.capture() as capture:
        print_json('{"ok": true}')
    assert "ok" in capture.get()
