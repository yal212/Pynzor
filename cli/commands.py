import typer
from pathlib import Path
from cli.options import target, output_dir, report_format, verbose, wordlist, threads

app = typer.Typer(help="Pynzor - Web pentesting CLI")


@app.command()
def scan(
    target: str = target,
    output_dir: str = output_dir,
    format: str = report_format,
    verbose: bool = verbose,
):
    """Run all modules (full scan)"""
    typer.echo(f"Running full scan on {target}")


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
