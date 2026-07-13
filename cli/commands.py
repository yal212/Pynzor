import asyncio
import typer
import json
from contextlib import contextmanager
from pathlib import Path
from datetime import datetime
from importlib.metadata import PackageNotFoundError, version
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
    no_baseline,
    include_wildcard,
    extensions as extensions_opt,
    recursive as recursive_opt,
    depth as depth_opt,
    method as method_opt,
    header as header_opt,
    data as data_opt,
    match_codes as match_codes_opt,
    filter_codes as filter_codes_opt,
    filter_size as filter_size_opt,
    filter_words as filter_words_opt,
    filter_lines as filter_lines_opt,
    ports as ports_opt,
    service_detection as service_detection_opt,
    output_normal as output_normal_opt,
    scan_threads as scan_threads_opt,
)
from utils.http_client import HTTPClient, ClientConfig
from utils.validators import normalize_url, extract_domain
import modules
from output.reporter import Reporter
from output.formatter import Formatter

APP_NAME = "Pynzor"


def get_version() -> str:
    """Return the installed package version, falling back for source checkouts."""
    try:
        return version(APP_NAME)
    except PackageNotFoundError:
        return "0.0.0"


def version_callback(value: bool) -> None:
    """Print version and exit when --version is provided."""
    if value:
        typer.echo(f"{APP_NAME} {get_version()}")
        raise typer.Exit()


app = typer.Typer(help="Pynzor - CTF/lab web recon CLI for authorized testing")

reporter = Reporter()
formatter = Formatter()
console = Console()


@app.callback()
def cli(
    version: bool = typer.Option(
        False,
        "--version",
        callback=version_callback,
        is_eager=True,
        help="Show the Pynzor version and exit.",
    ),
) -> None:
    """Fast CTF/lab web reconnaissance for authorized targets."""


def _parse_int_list(value: str | None, param: str = "value") -> list[int] | None:
    """Parse a comma-separated string of integers.

    Args:
        value: Comma-separated integers, or None/empty.
        param: Parameter name used in error messages.

    Returns:
        The parsed list, or None if ``value`` is empty.

    Raises:
        typer.BadParameter: If any element is not an integer.
    """
    if not value:
        return None
    try:
        return [int(p.strip()) for p in value.split(",") if p.strip()]
    except ValueError:
        raise typer.BadParameter(
            f"expected comma-separated integers, got: {value!r}", param_hint=param
        )


def _parse_str_list(value: str | None) -> list[str] | None:
    """Parse a comma-separated string into a list of trimmed strings.

    Args:
        value: Comma-separated values, or None/empty.

    Returns:
        The parsed list, or None if ``value`` is empty.
    """
    if not value:
        return None
    return [p.strip() for p in value.split(",") if p.strip()]


def _parse_headers(values: list[str] | None) -> dict[str, str]:
    """Parse ``Name: value`` header strings into a dict.

    Args:
        values: Header strings, each in ``Name: value`` form.

    Returns:
        A mapping of header name to value.

    Raises:
        typer.BadParameter: If any entry lacks a colon separator.
    """
    headers: dict[str, str] = {}
    for raw in values or []:
        if ":" not in raw:
            raise typer.BadParameter(f"Invalid header (expected 'Name: value'): {raw}")
        name, _, val = raw.partition(":")
        headers[name.strip()] = val.strip()
    return headers


@contextmanager
def spinner(msg: str, use_color: bool = True):
    """Context manager showing a status spinner (or plain text in no-color mode).

    Args:
        msg: Status message to display.
        use_color: If True, show an animated rich spinner; otherwise print
            ``msg + "..."`` once.

    Yields:
        Control to the wrapped block while the spinner is active.
    """
    if use_color:
        with console.status(f"[cyan]{msg}[/cyan]", spinner="dots"):
            yield
    else:
        console.print(msg + "...")
        yield


def load_config(config_path: Path | None = None):
    """Load the YAML config, resolving relative wordlist paths.

    Relative ``wordlist`` paths (under ``fuzzer``/``subdomain`` and the
    ``wordlists`` map) are resolved against the config file's directory so the
    CLI works when run as a bundled executable.

    Args:
        config_path: Path to a config file; defaults to the bundled
            ``config.yaml`` beside this module.

    Returns:
        The parsed configuration dict.
    """
    import yaml

    default_config = Path(__file__).parent / "config.yaml"
    config_file_path = config_path or default_config
    config_base = config_file_path.parent

    with open(config_file_path, encoding="utf-8") as f:
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
        """Run every module in sequence and collect their results."""
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
    no_baseline: bool = no_baseline,
    extensions: str | None = extensions_opt,
    recursive: bool = recursive_opt,
    depth: int | None = depth_opt,
    method: str = method_opt,
    header: list[str] | None = header_opt,
    data: str | None = data_opt,
    match_codes: str | None = match_codes_opt,
    filter_codes: str | None = filter_codes_opt,
    filter_size: int | None = filter_size_opt,
    filter_words: int | None = filter_words_opt,
    filter_lines: int | None = filter_lines_opt,
):
    """Directory/file fuzzing (gobuster-style) or FUZZ-keyword request fuzzing (ffuf-style)"""
    config = load_config(config_file)
    formatter.no_color = no_color
    fuzzer_cfg = config.get("fuzzer", {})

    headers = _parse_headers(header)
    request_mode = modules.is_request_mode(
        target, headers=headers, data=data, method=method
    )

    # FUZZ-mode keeps the keyword-bearing target intact (only ensuring a
    # scheme so requests resolve); directory-mode normalizes to a clean base URL.
    if request_mode:
        normalized = target.strip()
        if not normalized.startswith(("http://", "https://")):
            normalized = f"https://{normalized}"
    else:
        normalized = normalize_url(target)
    wordlist_path = str(wordlist) if wordlist else fuzzer_cfg["wordlist"]

    # Extensions: -x omitted -> config default (directory mode only);
    # -x "" -> explicit opt-out (bare words only); -x "php,html" -> those.
    if extensions is None:
        ext_list = None if request_mode else fuzzer_cfg.get("extensions")
    else:
        ext_list = _parse_str_list(extensions)

    effective_depth = depth if depth is not None else fuzzer_cfg.get("recursion_depth", 1)

    match_list = _parse_int_list(match_codes, "--match-codes")
    if match_list is None and request_mode:
        match_list = fuzzer_cfg.get("match_codes")
    filter_list = _parse_int_list(filter_codes, "--filter-codes")

    if not request_mode:
        dropped = [
            name
            for name, given in (
                ("--match-codes", bool(match_codes)),
                ("--filter-codes", bool(filter_codes)),
                ("--filter-size", filter_size is not None),
                ("--filter-words", filter_words is not None),
                ("--filter-lines", filter_lines is not None),
            )
            if given
        ]
        if dropped:
            typer.echo(
                f"Warning: {', '.join(dropped)} only apply to request fuzzing "
                "(FUZZ keyword / -X / -d); ignored in directory mode."
            )
    else:
        dropped = [
            name
            for name, given in (
                ("--extensions", extensions is not None),
                ("--recursive", recursive),
                ("--depth", depth is not None),
            )
            if given
        ]
        if dropped:
            typer.echo(
                f"Warning: {', '.join(dropped)} only apply to directory fuzzing; "
                "ignored in request mode."
            )

    if request_mode:
        typer.echo(f"Fuzzing requests on {normalized}")
    else:
        typer.echo(f"Fuzzing directories on {normalized}")

    async def run_fuzz():
        """Run the fuzzer with the resolved options and print results."""
        with spinner("Fuzzing", not no_color):
            result = await modules.fuzz(
                normalized,
                wordlist_path,
                threads,
                use_baseline=not no_baseline,
                extensions=ext_list,
                recursive=recursive,
                depth=effective_depth,
                method=method,
                headers=headers or None,
                data=data,
                match_codes=match_list,
                filter_codes=filter_list,
                filter_size=filter_size,
                filter_words=filter_words,
                filter_lines=filter_lines,
            )
        formatter.print_fuzzer_results(result)
        return result

    result = asyncio.run(run_fuzz())

    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True, parents=True)
    report_file = output_path / f"fuzz_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    reporter.save(
        {
            "target": normalized,
            "mode": result.mode,
            "found": [
                {
                    "url": r.url,
                    "status": r.status_code,
                    "length": r.content_length,
                    "word": r.word,
                }
                for r in result.found
            ],
        },
        report_file,
    )
    typer.echo(f"\nReport saved to: {report_file}")


@app.command()
def ports(
    target: str = target,
    ports: str | None = ports_opt,
    service_detection: bool = service_detection_opt,
    output_normal: Path | None = output_normal_opt,
    output_dir: str = output_dir,
    threads: int | None = scan_threads_opt,
    no_color: bool = no_color,
    config_file: Path = config_file,
):
    """Port scan with optional service/version detection (nmap-style)"""
    from modules.scanner import parse_ports, format_nmap_text

    config = load_config(config_file)
    formatter.no_color = no_color

    host = extract_domain(normalize_url(target))
    scanner_cfg = config.get("scanner", {})
    try:
        port_list = parse_ports(ports) if ports else scanner_cfg.get("common_ports")
    except ValueError as e:
        raise typer.BadParameter(str(e), param_hint="--ports")

    # --threads overrides; otherwise fall back to the config's concurrency.
    concurrent = threads if threads is not None else scanner_cfg.get("concurrent", 50)

    typer.echo(f"Scanning ports on {host}")

    async def run_ports():
        """Run the port scan with the resolved options and print results."""
        with spinner("Scanning ports", not no_color):
            result = await modules.scan(
                host,
                ports=port_list,
                timeout=scanner_cfg.get("timeout", 3),
                concurrent=concurrent,
                service_detection=service_detection,
                banner_timeout=scanner_cfg.get("banner_timeout", 2),
            )
        formatter.print_scanner_results(result)
        return result

    result = asyncio.run(run_ports())

    if output_normal:
        output_normal.parent.mkdir(exist_ok=True, parents=True)
        output_normal.write_text(format_nmap_text(result))
        typer.echo(f"Plain-text report saved to: {output_normal}")

    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True, parents=True)
    report_file = output_path / f"ports_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    reporter.save(
        {
            "target": host,
            "ports": [
                {
                    "port": p.port,
                    "status": p.status,
                    "service": p.service,
                    "product": p.product,
                    "version": p.version,
                    "banner": p.banner,
                }
                for p in result.ports
                if p.status != "closed"
            ],
        },
        report_file,
    )
    typer.echo(f"\nReport saved to: {report_file}")


@app.command(name="headers")
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
        """Run header analysis and print results."""
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
        """Run the SQL injection probe and print results."""
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
        """Run XSS detection and print results."""
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
    include_wildcard: bool = include_wildcard,
):
    """Subdomain enumeration"""
    config = load_config(config_file)
    formatter.no_color = no_color

    domain = extract_domain(target)

    typer.echo(f"Enumerating subdomains of {domain}")

    async def run_subdomain():
        """Run subdomain enumeration and print results."""
        with spinner("Enumerating subdomains", not no_color):
            result = await modules.enumerate(
                domain,
                config["subdomain"]["wordlist"],
                threads,
                include_wildcard=include_wildcard,
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
