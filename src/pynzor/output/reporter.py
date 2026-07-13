import json
from datetime import datetime
from pathlib import Path
from typing import Any

#: Bumped when the report envelope shape changes in a non-additive way.
SCHEMA_VERSION = 1

#: Severity levels, ordered from least to most severe.
SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")

#: Maps a security-header letter grade to a report severity.
_GRADE_SEVERITY = {"A": "info", "B": "low", "C": "medium", "D": "high", "F": "critical"}


def build_report(
    module: str,
    target: str,
    findings: list | None = None,
    severity: str = "info",
    metadata: dict | None = None,
    timestamp: str | None = None,
) -> dict:
    """Build a normalized report envelope shared by every command.

    All commands emit the same top-level shape so reports can be consumed
    uniformly:

        {schema_version, target, timestamp, module, findings, severity, metadata}

    Args:
        module: Emitting module/command name (e.g. ``"headers"``, ``"scan"``).
        target: The scanned target (URL or domain).
        findings: List of finding dicts specific to the module.
        severity: Overall severity; one of :data:`SEVERITY_ORDER`.
        metadata: Module-specific summary fields (counts, scores, etc.).
        timestamp: ISO-8601 timestamp; defaults to now.

    Returns:
        The normalized report dict.
    """
    return {
        "schema_version": SCHEMA_VERSION,
        "target": target,
        "timestamp": timestamp or datetime.now().isoformat(),
        "module": module,
        "findings": list(findings or []),
        "severity": severity,
        "metadata": metadata or {},
    }


def severity_from_grade(grade: str | None) -> str:
    """Map a security-header letter grade (A-F) to a report severity."""
    return _GRADE_SEVERITY.get((grade or "F").upper(), "critical")


def highest_severity(severities: list[str]) -> str:
    """Return the most severe level from ``severities`` (``"info"`` if empty)."""
    ranked = [s for s in severities if s in SEVERITY_ORDER]
    if not ranked:
        return "info"
    return max(ranked, key=SEVERITY_ORDER.index)


class Reporter:
    """Persists and loads scan results and builds report summaries."""

    def save(self, data: Any, output_path: Path) -> None:
        """Serialize results and write them as JSON.

        Args:
            data: Scan result object or dict to serialize.
            output_path: Destination file path (parent dirs are created).
        """
        serialized = serialize_result(data)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(serialized, f, indent=2, default=str)

    def save_html(self, data: Any, output_path: Path) -> None:
        """Render results to an HTML report via the Jinja2 template.

        Args:
            data: Scan result object or dict to serialize and render.
            output_path: Destination ``.html`` path (parent dirs are created).
        """
        from jinja2 import Environment, FileSystemLoader

        serialized = serialize_result(data)
        summary = generate_scan_summary(serialized)
        templates_dir = Path(__file__).parent / "templates"
        env = Environment(loader=FileSystemLoader(str(templates_dir)))
        template = env.get_template("report.html.j2")
        html = template.render(data=serialized, summary=summary)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            f.write(html)

    def load(self, input_path: Path) -> dict:
        """Load a previously saved JSON report.

        Args:
            input_path: Path to the JSON report file.

        Returns:
            The parsed report as a dict.
        """
        with open(input_path, "r") as f:
            return json.load(f)

    def generate_summary(self, results: dict) -> dict:
        """Build a high-level summary of a results dict.

        Args:
            results: Serialized scan results.

        Returns:
            A summary dict (see :func:`generate_scan_summary`).
        """
        return generate_scan_summary(results)


def serialize_result(obj: Any) -> Any:
    """Recursively convert result objects into JSON-serializable structures.

    Walks ``__dict__`` attributes and lists, converting datetimes to ISO
    strings and nested objects to dicts.

    Args:
        obj: A result object, datetime, list, or primitive.

    Returns:
        A JSON-serializable equivalent of ``obj``.
    """
    if hasattr(obj, "__dict__"):
        result = {}
        for key, value in obj.__dict__.items():
            if isinstance(value, datetime):
                result[key] = value.isoformat()
            elif isinstance(value, list):
                result[key] = [serialize_result(item) for item in value]
            elif hasattr(value, "__dict__"):
                result[key] = serialize_result(value)
            else:
                result[key] = value
        return result
    elif isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, list):
        return [serialize_result(item) for item in obj]
    return obj


def save_json_report(data: Any, output_path: str) -> None:
    """Serialize results and write them to a JSON file path.

    Args:
        data: Scan result object or dict to serialize.
        output_path: Destination file path (parent dirs are created).
    """
    serialized = serialize_result(data)

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, "w") as f:
        json.dump(serialized, f, indent=2, default=str)


def load_json_report(input_path: str) -> dict:
    """Load a JSON report from a file path.

    Args:
        input_path: Path to the JSON report file.

    Returns:
        The parsed report as a dict.
    """
    with open(input_path, "r") as f:
        return json.load(f)


def generate_scan_summary(results: dict) -> dict:
    """Summarize scan results across modules.

    Tallies completed modules, vulnerabilities found, and total requests,
    handling both legacy top-level and current ``modules``-nested layouts.

    Args:
        results: Serialized scan results.

    Returns:
        A summary dict with keys ``target``, ``timestamp``,
        ``modules_completed``, ``vulnerabilities_found``, and
        ``total_requests``.
    """
    summary = {
        "target": results.get("target", "unknown"),
        "timestamp": results.get("timestamp") or datetime.now().isoformat(),
        "modules_completed": [],
        "vulnerabilities_found": 0,
        "total_requests": 0,
    }
    # Per-module outputs may live under metadata.modules (normalized scan
    # envelope), under a top-level "modules" key (older CLI flow), or at the
    # top level (legacy). Normalize so we inspect them uniformly.
    metadata = results.get("metadata")
    if isinstance(metadata, dict) and isinstance(metadata.get("modules"), dict):
        modules = metadata["modules"]
    elif isinstance(results.get("modules"), dict):
        modules = results["modules"]
    else:
        modules = results

    # Scanner
    if "scanner" in modules:
        summary["modules_completed"].append("scanner")
        scanner_data = modules["scanner"]
        ports = scanner_data.get("ports", [])
        open_ports = [p for p in ports if (p.get("status") == "open")]
        summary["vulnerabilities_found"] += len(open_ports)

    # Headers
    if "headers" in modules:
        summary["modules_completed"].append("headers")

    # SQLi
    if "sqli" in modules:
        summary["modules_completed"].append("sqli")
        sqli_data = modules["sqli"]
        # Support both detailed vulnerabilities list and simple vulnerable flag
        vulns = sqli_data.get("vulnerabilities") or (
            [sqli_data] if sqli_data.get("vulnerable") else []
        )
        summary["vulnerabilities_found"] += len(vulns)

    # XSS
    if "xss" in modules:
        summary["modules_completed"].append("xss")
        xss_data = modules["xss"]
        vulns = xss_data.get("vulnerabilities") or (
            [xss_data] if xss_data.get("vulnerable") else []
        )
        summary["vulnerabilities_found"] += len(vulns)

    # Fuzzer
    if "fuzzer" in modules or "fuzz" in modules:
        summary["modules_completed"].append("fuzz")
        fuzz_data = modules.get("fuzzer") or modules.get("fuzz") or {}
        summary["total_requests"] += fuzz_data.get("scanned", 0)

    # Subdomain
    if "subdomain" in modules:
        summary["modules_completed"].append("subdomain")
        summary["total_requests"] += modules["subdomain"].get("scanned", 0)

    return summary
