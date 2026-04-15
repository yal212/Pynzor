import asyncio
import typer
import json
from contextlib import contextmanager
from pathlib import Path
from datetime import datetime
from rich.console import Console

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
from utils.http_client import HTTPClient, ClientConfig
from utils.validators import normalize_url, extract_domain
import modules
from output.reporter import Reporter
from output.formatter import Formatter

app = typer.Typer(help="Pynzor - Web pentesting CLI")

reporter = Reporter()
formatter = Formatter()
console = Console()


@contextmanager
def spinner(msg: str, use_color: bool = True):
    if use_color:
        with console.status(f"[cyan]{msg}[/cyan]", spinner="dots"):
            yield
    else:
        console.print(msg + "...")
        yield


def load_config(config_path: Path | None = None):
    import yaml

    default_config = Path(__file__).parent.parent / "config.yaml"
    config_file_path = config_path or default_config
    config_base = config_file_path.parent

    with open(config_file_path) as f:
        config = yaml.safe_load(f)

    # Resolve relative wordlist paths against the config file's directory.
    # Required when running as a PyInstaller exe: CWD != bundle root (_MEIPASS).
    for section in ("fuzzer", "subdomain"):
        wl = config.get(section, {}).get("wordlist")
        if wl and not Path(wl).is_absolute():
            config[section]["wordlist"] = str(config_base / wl)
    for key, wl in config.get("wordlists", {}).items():
        if wl and not Path(wl).is_absolute():
            config["wordlists"][key] = str(config_base / wl)

    return config


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
        http_config = ClientConfig(
            timeout=config["http"].get("timeout", 10),
            max_retries=config["http"].get("max_retries", 3),
            rate_limit=config["http"].get("rate_limit", 0.1),
            user_agent=config["http"].get("user_agent"),
            follow_redirects=config["http"].get("follow_redirects", True),
            verify_ssl=config["http"].get("verify_ssl", True),
        )
        http = HTTPClient(http_config)

        formatter.print_header("Port Scanner")
        with spinner("Scanning ports", not no_color):
            scanner_result = await modules.scan(
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
        with spinner("Fuzzing directories", not no_color):
            fuzzer_result = await modules.fuzz(
                normalized, config["fuzzer"]["wordlist"], config["fuzzer"]["threads"]
            )
        results["modules"]["fuzzer"] = {
            "found": len(fuzzer_result.found),
            "paths": [r.url for r in fuzzer_result.found[:20]],
        }
        formatter.print_fuzzer_results(fuzzer_result)

        formatter.print_header("Security Headers")
        with spinner("Analyzing headers", not no_color):
            headers_result = await modules.analyze(normalized, http)
        results["modules"]["headers"] = {
            "score": headers_result.score,
            "missing": headers_result.missing_headers,
        }
        formatter.print_headers_results(headers_result)

        formatter.print_header("SQL Injection")
        with spinner("Probing for SQL injection", not no_color):
            sqli_result = await modules.probe(normalized, None)
        results["modules"]["sqli"] = {
            "vulnerable": sqli_result.vulnerable,
            "payload": sqli_result.payload,
        }
        formatter.print_sqli_results(sqli_result)

        formatter.print_header("XSS Detection")
        with spinner("Detecting XSS", not no_color):
            xss_result = await modules.detect(normalized, None)
        results["modules"]["xss"] = {
            "vulnerable": xss_result.vulnerable,
            "payload": xss_result.payload,
        }
        formatter.print_xss_results(xss_result)

        formatter.print_header("Subdomain Enumeration")
        with spinner("Enumerating subdomains", not no_color):
            subdomain_result = await modules.enumerate(
                domain, config["subdomain"]["wordlist"], config["subdomain"]["threads"]
            )
        results["modules"]["subdomain"] = {
            "found": len(subdomain_result.subdomains),
            "subdomains": subdomain_result.subdomains[:20],
        }
        formatter.print_subdomain_results(subdomain_result)

        # HTTPClient exposes an async close() method for explicit shutdown
        # (also usable via the async context manager). Ensure we close it here.
        await http.close()

    asyncio.run(run_all())

    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True, parents=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    if format in ("json", "both"):
        report_file = output_path / f"scan_{timestamp}.json"
        reporter.save(results, report_file)
        typer.echo(f"\nJSON report saved to: {report_file}")
    if format in ("html", "both"):
        report_file = output_path / f"scan_{timestamp}.html"
        reporter.save_html(results, report_file)
        typer.echo(f"HTML report saved to: {report_file}")


@app.command()
def fuzz(
    target: str = target,
    wordlist: Path = wordlist,
    threads: int = threads,
    output_dir: str = output_dir,
    no_color: bool = no_color,
    config_file: Path = config_file,
):
    """Directory/file fuzzing"""
    config = load_config(config_file)
    formatter.no_color = no_color

    normalized = normalize_url(target)
    wordlist_path = str(wordlist) if wordlist else config["fuzzer"]["wordlist"]

    typer.echo(f"Fuzzing directories on {normalized}")

    async def run_fuzz():
        with spinner("Fuzzing directories", not no_color):
            result = await modules.fuzz(normalized, wordlist_path, threads)
        formatter.print_fuzzer_results(result)
        return result

    result = asyncio.run(run_fuzz())

    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True, parents=True)
    report_file = output_path / f"fuzz_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    reporter.save(
        {"target": normalized, "found": [r.url for r in result.found]}, report_file
    )
    typer.echo(f"\nReport saved to: {report_file}")


@app.command()
def headers_cmd(
    target: str = target,
    output_dir: str = output_dir,
    no_color: bool = no_color,
    config_file: Path = config_file,
):
    """Security header analysis"""
    config = load_config(config_file)
    formatter.no_color = no_color

    normalized = normalize_url(target)

    typer.echo(f"Analyzing headers on {normalized}")

    async def run_headers():
        with spinner("Analyzing headers", not no_color):
            result = await modules.analyze(normalized, None)
        formatter.print_headers_results(result)
        return result

    result = asyncio.run(run_headers())

    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True, parents=True)
    report_file = (
        output_path / f"headers_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )
    reporter.save(
        {"target": normalized, "score": result.score, "grade": result.grade},
        report_file,
    )
    typer.echo(f"\nReport saved to: {report_file}")


@app.command()
def sqli(
    target: str = target,
    output_dir: str = output_dir,
    no_color: bool = no_color,
    config_file: Path = config_file,
):
    """SQL injection probe"""
    config = load_config(config_file)
    formatter.no_color = no_color

    normalized = normalize_url(target)

    typer.echo(f"Probing for SQL injection on {normalized}")

    async def run_sqli():
        with spinner("Probing for SQL injection", not no_color):
            result = await modules.probe(normalized)
        formatter.print_sqli_results(result)
        return result

    result = asyncio.run(run_sqli())

    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True, parents=True)
    report_file = output_path / f"sqli_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    reporter.save(
        {
            "target": normalized,
            "vulnerable": result.vulnerable,
            "payload": result.payload,
        },
        report_file,
    )
    typer.echo(f"\nReport saved to: {report_file}")


@app.command()
def xss(
    target: str = target,
    output_dir: str = output_dir,
    no_color: bool = no_color,
    config_file: Path = config_file,
):
    """Reflected XSS detection"""
    config = load_config(config_file)
    formatter.no_color = no_color

    normalized = normalize_url(target)

    typer.echo(f"Detecting XSS on {normalized}")

    async def run_xss():
        with spinner("Detecting XSS", not no_color):
            result = await modules.detect(normalized)
        formatter.print_xss_results(result)
        return result

    result = asyncio.run(run_xss())

    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True, parents=True)
    report_file = output_path / f"xss_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    reporter.save(
        {
            "target": normalized,
            "vulnerable": result.vulnerable,
            "payload": result.payload,
        },
        report_file,
    )
    typer.echo(f"\nReport saved to: {report_file}")


@app.command()
def subdomain(
    target: str = target,
    output_dir: str = output_dir,
    no_color: bool = no_color,
    config_file: Path = config_file,
    threads: int = threads,
):
    """Subdomain enumeration"""
    config = load_config(config_file)
    formatter.no_color = no_color

    domain = extract_domain(target)

    typer.echo(f"Enumerating subdomains of {domain}")

    async def run_subdomain():
        with spinner("Enumerating subdomains", not no_color):
            result = await modules.enumerate(
                domain, config["subdomain"]["wordlist"], threads
            )
        formatter.print_subdomain_results(result)
        return result

    result = asyncio.run(run_subdomain())

    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True, parents=True)
    report_file = (
        output_path / f"subdomain_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )
    reporter.save({"target": domain, "subdomains": result.subdomains}, report_file)
    typer.echo(f"\nReport saved to: {report_file}")


@app.command()
def report(
    input_file: Path = typer.Argument(..., exists=True),
):
    """Re-generate report from JSON"""
    data = reporter.load(input_file)
    formatter.print_header(f"Report: {input_file.name}")
    import json
    from rich.console import Console

    console = Console()
    console.print_json(json.dumps(data, indent=2))
