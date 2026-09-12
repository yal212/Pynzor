import asyncio
import typer
import json
from contextlib import contextmanager
from pathlib import Path
from datetime import datetime
from importlib.metadata import PackageNotFoundError, version
from rich.console import Console

from pynzor.cli.options import (
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
    tui_target as tui_target_opt,
)
from pynzor.core import runner
from pynzor.core.config import load_config
from pynzor.core.parsing import parse_headers
from pynzor.utils.validators import extract_domain, normalize_url
from pynzor.output.reporter import Reporter
from pynzor.output.formatter import Formatter

APP_NAME = "Pynzor"

# Section titles and spinner labels for the full scan, keyed by module id.
SCAN_SECTIONS = {
    "ports": ("Port Scanner", "Scanning ports"),
    "fuzz": ("Directory Fuzzer", "Fuzzing directories"),
    "headers": ("Security Headers", "Analyzing headers"),
    "sqli": ("SQL Injection", "Probing for SQL injection"),
    "xss": ("XSS Detection", "Detecting XSS"),
    "subdomain": ("Subdomain Enumeration", "Enumerating subdomains"),
}


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


def _bad_param(exc: ValueError, param_hint: str):
    """Re-raise a core ValueError as a Typer parameter error."""
    return typer.BadParameter(str(exc), param_hint=param_hint)


def _save(report: dict, output_dir: str, module: str) -> Path:
    """Write a report envelope to a timestamped JSON file and echo the path."""
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True, parents=True)
    report_file = output_path / f"{module}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    reporter.save(report, report_file)
    typer.echo(f"\nReport saved to: {report_file}")
    return report_file


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

    printers = {
        "ports": formatter.print_scanner_results,
        "fuzz": formatter.print_fuzzer_results,
        "headers": formatter.print_headers_results,
        "sqli": formatter.print_sqli_results,
        "xss": formatter.print_xss_results,
        "subdomain": formatter.print_subdomain_results,
    }

    # One spinner is active at a time; the runner calls start/done in order.
    active: list = []

    def on_start(module: str) -> None:
        """Print the section header and open a spinner for this module."""
        title, label = SCAN_SECTIONS[module]
        formatter.print_header(title)
        ctx = spinner(label, not no_color)
        ctx.__enter__()
        active.append(ctx)

    def on_done(module: str, result) -> None:
        """Close the spinner and render this module's results."""
        active.pop().__exit__(None, None, None)
        printers[module](result)

    typer.echo(f"Running full scan on {normalize_url(target)}")

    _, report = asyncio.run(
        runner.run_full_scan(target, config, on_module_start=on_start, on_module_done=on_done)
    )

    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True, parents=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if format in ("json", "both"):
        report_file = output_path / f"scan_{timestamp}.json"
        reporter.save(report, report_file)
        typer.echo(f"\nJSON report saved to: {report_file}")
    if format in ("html", "both"):
        report_file = output_path / f"scan_{timestamp}.html"
        reporter.save_html(report, report_file)
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

    try:
        headers = parse_headers(header)
    except ValueError as e:
        raise _bad_param(e, "--header")

    try:
        opts = runner.resolve_fuzz_options(
            target,
            config,
            wordlist=str(wordlist) if wordlist else None,
            threads=threads,
            no_baseline=no_baseline,
            extensions=extensions,
            recursive=recursive,
            depth=depth,
            method=method,
            headers=headers,
            data=data,
            match_codes=match_codes,
            filter_codes=filter_codes,
            filter_size=filter_size,
            filter_words=filter_words,
            filter_lines=filter_lines,
        )
    except ValueError as e:
        raise _bad_param(e, "--match-codes/--filter-codes")

    if opts.ignored_flags:
        applies_to = "request fuzzing (FUZZ keyword / -X / -d)"
        ignored_in = "directory mode"
        if opts.request_mode:
            applies_to, ignored_in = "directory fuzzing", "request mode"
        typer.echo(
            f"Warning: {', '.join(opts.ignored_flags)} only apply to {applies_to}; "
            f"ignored in {ignored_in}."
        )

    mode_label = "requests" if opts.request_mode else "directories"
    typer.echo(f"Fuzzing {mode_label} on {opts.target}")

    async def run():
        """Run the fuzzer and print its results while the spinner is up."""
        with spinner("Fuzzing", not no_color):
            result, report = await runner.run_fuzz(opts)
        formatter.print_fuzzer_results(result)
        return report

    _save(asyncio.run(run()), output_dir, "fuzz")


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
    from pynzor.modules.scanner import parse_ports, format_nmap_text

    config = load_config(config_file)
    formatter.no_color = no_color

    try:
        port_list = parse_ports(ports) if ports else None
    except ValueError as e:
        raise _bad_param(e, "--ports")

    host = extract_domain(normalize_url(target))
    typer.echo(f"Scanning ports on {host}")

    async def run():
        """Run the port scan and print its results while the spinner is up."""
        with spinner("Scanning ports", not no_color):
            result, report = await runner.run_ports(
                target,
                config,
                ports=port_list,
                service_detection=service_detection,
                threads=threads,
            )
        formatter.print_scanner_results(result)
        return result, report

    result, report = asyncio.run(run())

    if output_normal:
        output_normal.parent.mkdir(exist_ok=True, parents=True)
        output_normal.write_text(format_nmap_text(result))
        typer.echo(f"Plain-text report saved to: {output_normal}")

    _save(report, output_dir, "ports")


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

    typer.echo(f"Analyzing headers on {normalize_url(target)}")

    async def run():
        """Run header analysis and print its results while the spinner is up."""
        with spinner("Analyzing headers", not no_color):
            result, report = await runner.run_headers(target, config)
        formatter.print_headers_results(result)
        return report

    _save(asyncio.run(run()), output_dir, "headers")


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

    typer.echo(f"Probing for SQL injection on {normalize_url(target)}")

    async def run():
        """Run the SQL injection probe and print its results."""
        with spinner("Probing for SQL injection", not no_color):
            result, report = await runner.run_sqli(target, config)
        formatter.print_sqli_results(result)
        return report

    _save(asyncio.run(run()), output_dir, "sqli")


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

    typer.echo(f"Detecting XSS on {normalize_url(target)}")

    async def run():
        """Run XSS detection and print its results."""
        with spinner("Detecting XSS", not no_color):
            result, report = await runner.run_xss(target, config)
        formatter.print_xss_results(result)
        return report

    _save(asyncio.run(run()), output_dir, "xss")


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

    typer.echo(f"Enumerating subdomains of {extract_domain(target)}")

    async def run():
        """Run subdomain enumeration and print its results."""
        with spinner("Enumerating subdomains", not no_color):
            result, report = await runner.run_subdomain(
                target, config, threads=threads, include_wildcard=include_wildcard
            )
        formatter.print_subdomain_results(result)
        return report

    _save(asyncio.run(run()), output_dir, "subdomain")


@app.command()
def report(
    input_file: Path = typer.Argument(..., exists=True),
):
    """Re-generate report from JSON"""
    data = reporter.load(input_file)
    formatter.print_header(f"Report: {input_file.name}")
    from rich.console import Console

    console = Console()
    console.print_json(json.dumps(data, indent=2))


@app.command()
def tui(
    target: str | None = tui_target_opt,
    config_file: Path = config_file,
):
    """Launch the interactive dashboard (also the default with no arguments)"""
    from pynzor.tui.app import run_tui

    raise typer.Exit(run_tui(load_config(config_file), target=target))
