import json
from datetime import datetime
from pathlib import Path
from typing import Any


class Reporter:
    def save(self, data: Any, output_path: Path) -> None:
        serialized = serialize_result(data)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(serialized, f, indent=2, default=str)

    def save_html(self, data: Any, output_path: Path) -> None:
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
        with open(input_path, "r") as f:
            return json.load(f)

    def generate_summary(self, results: dict) -> dict:
        return generate_scan_summary(results)


def serialize_result(obj: Any) -> Any:
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
    serialized = serialize_result(data)

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, "w") as f:
        json.dump(serialized, f, indent=2, default=str)


def load_json_report(input_path: str) -> dict:
    with open(input_path, "r") as f:
        return json.load(f)


def generate_scan_summary(results: dict) -> dict:
    summary = {
        "target": results.get("target", "unknown"),
        "timestamp": datetime.now().isoformat(),
        "modules_completed": [],
        "vulnerabilities_found": 0,
        "total_requests": 0,
    }
    # Results may be stored at the top-level (legacy) or under a "modules"
    # key (current CLI flow). Normalize to inspect module outputs uniformly.
    modules = (
        results.get("modules") if isinstance(results.get("modules"), dict) else results
    )

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
        fuzz_data = modules.get("fuzzer") or modules.get("fuzz")
        summary["total_requests"] += fuzz_data.get("scanned", 0)

    # Subdomain
    if "subdomain" in modules:
        summary["modules_completed"].append("subdomain")
        summary["total_requests"] += modules["subdomain"].get("scanned", 0)

    return summary
