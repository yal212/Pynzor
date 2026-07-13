import typer

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

threads = typer.Option(20, "--threads", help="Number of threads")

scan_threads = typer.Option(
    None,
    "--threads",
    help="Concurrent port probes (default: config 'concurrent', 50)",
)

no_baseline = typer.Option(
    False,
    "--no-baseline",
    help="Disable SPA/catch-all baseline filtering (report all matching paths)",
)

extensions = typer.Option(
    None,
    "--extensions",
    "-x",
    help="Comma-separated file extensions to append (e.g. php,html,txt)",
)

recursive = typer.Option(
    False,
    "--recursive",
    "-r",
    help="Recurse into discovered directories",
)

depth = typer.Option(
    None,
    "--depth",
    help="Maximum recursion depth with --recursive (default: config recursion_depth)",
)

method = typer.Option(
    "GET",
    "--method",
    "-X",
    help="HTTP method for request fuzzing (e.g. POST)",
)

header = typer.Option(
    None,
    "--header",
    "-H",
    help="Custom header 'Name: value' (repeatable); value may contain FUZZ",
)

data = typer.Option(
    None,
    "--data",
    "-d",
    help="Raw request body for request fuzzing; may contain FUZZ",
)

match_codes = typer.Option(
    None,
    "--match-codes",
    "-mc",
    help="Comma-separated status codes to keep (request fuzzing)",
)

filter_codes = typer.Option(
    None,
    "--filter-codes",
    "-fc",
    help="Comma-separated status codes to drop (request fuzzing)",
)

filter_size = typer.Option(
    None,
    "--filter-size",
    "-fs",
    help="Drop responses of this exact byte size (request fuzzing)",
)

filter_words = typer.Option(
    None,
    "--filter-words",
    "-fw",
    help="Drop responses with this exact word count (request fuzzing)",
)

filter_lines = typer.Option(
    None,
    "--filter-lines",
    "-fl",
    help="Drop responses with this exact line count (request fuzzing)",
)

ports = typer.Option(
    None,
    "--ports",
    "-p",
    help="Ports to scan: '80,443', '1-1000', or '22,80,8000-8100'",
)

service_detection = typer.Option(
    False,
    "--service-detection",
    "-sV",
    help="Grab banners and detect service versions on open ports",
)

output_normal = typer.Option(
    None,
    "--output-normal",
    "-oN",
    help="Write a plain-text (nmap-style) scan report to this path",
)

include_wildcard = typer.Option(
    False,
    "--include-wildcard",
    help="Include subdomains matching wildcard DNS (off by default to reduce false positives)",
)
