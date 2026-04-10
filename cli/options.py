import typer
from typing import Optional
from pathlib import Path

target = typer.Option(
    ...,
    "--target",
    "-t",
    help="Target URL or domain (required)",
)

output_dir = typer.Option(
    "./reports",
    "--output",
    "-o",
    help="Directory to save reports",
    exists=False,
)

report_format = typer.Option(
    "json",
    "--format",
    "-f",
    help="Report format: json, html, both",
)

verbose = typer.Option(
    False,
    "--verbose",
    "-v",
    help="Enable verbose output",
)

no_color = typer.Option(
    False,
    "--no-color",
    help="Disable colored output",
)

config_file = typer.Option(
    None,
    "--config",
    "-c",
    help="Path to custom config.yaml",
    exists=True,
)

wordlist = typer.Option(
    None,
    "--wordlist",
    "-w",
    help="Custom wordlist path",
    exists=True,
)

threads = typer.Option(
    20,
    "--threads",
    help="Number of threads"
)
