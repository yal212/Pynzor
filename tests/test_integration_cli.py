"""Command-level integration tests against a local HTTP fixture.

These exercise the full CLI flow (option parsing -> module -> report writing)
for each command without touching any external network target. The local
server is provided by the ``http_fixture`` fixture in conftest.py.
"""

import glob
import json

from typer.testing import CliRunner

from pynzor.cli.commands import app

runner = CliRunner()


def _load_only_report(output_dir, prefix: str) -> dict:
    """Return the single JSON report written under ``output_dir``."""
    matches = glob.glob(str(output_dir / f"{prefix}_*.json"))
    assert len(matches) == 1, f"expected one {prefix} report, found {matches}"
    return json.loads(open(matches[0]).read())


def _assert_envelope(report: dict, module: str, target_contains: str) -> None:
    assert report["schema_version"] == 1
    assert report["module"] == module
    assert target_contains in report["target"]
    assert isinstance(report["findings"], list)
    assert report["severity"] in ("info", "low", "medium", "high", "critical")
    assert isinstance(report["metadata"], dict)


def test_headers_command(http_fixture, tmp_path):
    result = runner.invoke(app, ["headers", "-t", http_fixture, "-o", str(tmp_path), "--no-color"])
    assert result.exit_code == 0, result.output
    assert "Analyzing headers" in result.output
    report = _load_only_report(tmp_path, "headers")
    _assert_envelope(report, "headers", "127.0.0.1")
    assert "grade" in report["metadata"]


def test_sqli_command_detects_error_signature(http_fixture, tmp_path):
    target = f"{http_fixture}/sqli?id=1"
    result = runner.invoke(app, ["sqli", "-t", target, "-o", str(tmp_path), "--no-color"])
    assert result.exit_code == 0, result.output
    report = _load_only_report(tmp_path, "sqli")
    _assert_envelope(report, "sqli", "127.0.0.1")
    assert report["metadata"]["vulnerable"] is True
    assert report["severity"] == "high"
    assert len(report["findings"]) >= 1


def test_xss_command_detects_reflection(http_fixture, tmp_path):
    target = f"{http_fixture}/xss?q=test"
    result = runner.invoke(app, ["xss", "-t", target, "-o", str(tmp_path), "--no-color"])
    assert result.exit_code == 0, result.output
    report = _load_only_report(tmp_path, "xss")
    _assert_envelope(report, "xss", "127.0.0.1")
    assert report["metadata"]["vulnerable"] is True
    assert report["severity"] == "high"


def test_fuzz_command_finds_known_path(http_fixture, tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\nmissing\n")
    result = runner.invoke(
        app,
        ["fuzz", "-t", http_fixture, "-w", str(wordlist), "-o", str(tmp_path), "--no-color", "-x", ""],
    )
    assert result.exit_code == 0, result.output
    report = _load_only_report(tmp_path, "fuzz")
    _assert_envelope(report, "fuzz", "127.0.0.1")
    found_urls = [f["url"] for f in report["findings"]]
    assert any(u.endswith("/admin") for u in found_urls), found_urls


def test_report_command_round_trips(http_fixture, tmp_path):
    # Produce a report, then re-read it through the `report` command.
    runner.invoke(app, ["headers", "-t", http_fixture, "-o", str(tmp_path), "--no-color"])
    report_path = glob.glob(str(tmp_path / "headers_*.json"))[0]
    result = runner.invoke(app, ["report", report_path])
    assert result.exit_code == 0, result.output
    assert "schema_version" in result.output
    assert "headers" in result.output
