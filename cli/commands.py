import asyncio
import typer
import json
from pathlib import Path
from datetime import datetime

from cli.options import (
    target,
    output_dir,
    report_format,
    verbose,
    wordlist,
    threads,
    no_color,
    config_file,
)
from utils.http_client import HTTPClient
from utils.validators import normalize_url, extract_domain
from modules import scanner, fuzzer, headers, sqli, xss, subdomain
from output.reporter import Reporter
from output.formatter import Formatter

app = typer.Typer(help="Pynzor - Web pentesting CLI")

reporter = Reporter()
formatter = Formatter()


def load_config(config_path: Path = None):
    import yaml

    default_config = Path(__file__).parent.parent / "config.yaml"
    config_file_path = config_path or default_config
    with open(config_file_path) as f:
        return yaml.safe_load(f)


@app.command()
def scan(
    target: str = target,
    output_dir: str = output_dir,
    format: str = report_format,
    verbose: bool = verbose,
    no_color: bool = no_color,
    config_file: Path = config_file,
):
    """Run all modules (full scan)"""
    config = load_config(config_file)
    formatter.no_color = no_color

    normalized = normalize_url(target)
    domain = extract_domain(normalized)

    typer.echo(f"Running full scan on {normalized}")

    results = {
        "target": normalized,
        "scan_time": datetime.now().isoformat(),
        "modules": {},
    }

    async def run_all():
        http = HTTPClient(config["http"])

        formatter.print_header("Port Scanner")
        scanner_result = await scanner.scan(
            domain, ports=config["scanner"]["common_ports"]
        )
        results["modules"]["scanner"] = {
            "ports": [
                {"port": p.port, "status": p.status, "service": p.service}
                for p in scanner_result.ports
            ],
            "open_count": len([p for p in scanner_result.ports if p.status == "open"]),
        }
        formatter.print_scanner_results(scanner_result)

        formatter.print_header("Directory Fuzzer")
        fuzzer_result = await fuzzer.fuzz(
            normalized, config["fuzzer"]["wordlist"], config["fuzzer"]["threads"]
        )
        results["modules"]["fuzzer"] = {
            "found": fuzzer_result.found_count,
            "paths": fuzzer_result.found_paths[:20],
        }
        formatter.print_fuzzer_results(fuzzer_result)

        formatter.print_header("Security Headers")
        headers_result = await headers.analyze(normalized, http)
        results["modules"]["headers"] = {
            "score": headers_result.score,
            "missing": headers_result.missing_headers,
        }
        formatter.print_headers_results(headers_result)

        formatter.print_header("SQL Injection")
        sqli_result = await sqli.probe(normalized, http)
        results["modules"]["sqli"] = {
            "vulnerable": sqli_result.vulnerable,
            "payload": sqli_result.payload,
        }
        formatter.print_sqli_results(sqli_result)

        formatter.print_header("XSS Detection")
        xss_result = await xss.detect(normalized, http)
        results["modules"]["xss"] = {
            "vulnerable": xss_result.vulnerable,
            "payload": xss_result.payload,
        }
        formatter.print_xss_results(xss_result)

        formatter.print_header("Subdomain Enumeration")
        subdomain_result = await subdomain.enumerate(
            domain, config["subdomain"]["wordlist"], config["subdomain"]["threads"]
        )
        results["modules"]["subdomain"] = {
            "found": len(subdomain_result.subdomains),
            "subdomains": subdomain_result.subdomains[:20],
        }
        formatter.print_subdomain_results(subdomain_result)

        await http.close()

    asyncio.run(run_all())

    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True, parents=True)
    report_file = output_path / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    reporter.save(results, report_file)
    typer.echo(f"\nReport saved to: {report_file}")


@app.command()
def fuzz(
    target: str = target,
    wordlist: Path = wordlist,
    threads: int = threads,
):
    """Directory/file fuzzing"""


@app.command()
def headers(
    target: str = target,
):
    """Security header analysis"""


@app.command()
def sqli(
    target: str = target,
):
    """SQL injection probe"""


@app.command()
def xss(
    target: str = target,
):
    """Reflected XSS detection"""


@app.command()
def subdomain(
    target: str = target,
):
    """Subdomain enumeration"""


@app.command()
def report(
    input_file: Path = typer.Argument(..., exists=True),
):
    """Re-generate report from JSON"""
