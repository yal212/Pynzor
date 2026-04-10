# Pynzor — Web pentesting, sharpened.

> An open-source Python CLI I built - scan ports, fuzz directories, hunt headers, and probe for vulns, all from one tool. No setup headaches, just point it at a target and go.

---

## Table of Contents

1. [Overview](#overview)
2. [Project Structure](#project-structure)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [CLI Usage](#cli-usage)
6. [Modules](#modules)
   - [Scanner](#scanner)
   - [Fuzzer](#fuzzer)
   - [Header Checker](#header-checker)
   - [SQL Injection Probe](#sql-injection-probe)
   - [XSS Detector](#xss-detector)
   - [Subdomain Enumerator](#subdomain-enumerator)
7. [Utilities](#utilities)
   - [HTTP Client](#http-client)
   - [Logger](#logger)
   - [Validators](#validators)
8. [Output & Reporting](#output--reporting)
9. [Wordlists](#wordlists)
10. [Testing](#testing)
11. [Adding a New Module](#adding-a-new-module)
12. [Dependencies](#dependencies)
13. [Ethics & Legal Notice](#ethics--legal-notice)
14. [Contributing](#contributing)
15. [License](#license)

---

## Overview

`Pynzor` is a Python CLI tool that bundles the most common web reconnaissance and vulnerability probing techniques into a single, easy-to-use interface. It is intended for use on systems and targets you own or have explicit written permission to test.

**Key features:**

- Modular architecture — each technique is an isolated Python module
- Rich terminal output with colour-coded severity levels
- JSON and HTML report export
- Async HTTP engine via `httpx` for fast parallel requests
- Bundled wordlists so it works out of the box
- Fully tested with `pytest`

---

## Project Structure

```
Pynzor/
├── main.py                  # CLI entry point
├── cli/
│   ├── __init__.py
│   ├── commands.py          # Typer command definitions
│   └── options.py           # Shared flags and argument types
├── modules/
│   ├── __init__.py
│   ├── scanner.py           # Port and service detection
│   ├── fuzzer.py            # Directory and parameter fuzzing
│   ├── headers.py           # HTTP security header analysis
│   ├── sqli.py              # Basic SQL injection probing
│   ├── xss.py               # Reflected XSS detection
│   └── subdomain.py         # Subdomain enumeration
├── utils/
│   ├── __init__.py
│   ├── http_client.py       # httpx wrapper with retries and UA spoofing
│   ├── logger.py            # Rich console output helpers
│   └── validators.py        # URL and input sanitisation
├── output/
│   ├── __init__.py
│   ├── reporter.py          # JSON / HTML report generation
│   └── formatter.py         # Rich table formatters
├── wordlists/
│   ├── common-dirs.txt      # Common web directories
│   ├── common-params.txt    # Common GET/POST parameter names
│   └── subdomains.txt       # Common subdomain prefixes
├── tests/
│   ├── conftest.py
│   ├── test_scanner.py
│   ├── test_fuzzer.py
│   ├── test_headers.py
│   └── test_validators.py
├── pyproject.toml
├── config.yaml
└── README.md
```

---

## Installation

### Requirements

- Python 3.10 or higher
- pip or [uv](https://github.com/astral-sh/uv)

### From source

```bash
git clone https://github.com/yourusername/Pynzor.git
cd Pynzor
pip install -e .
```

### With uv (recommended for Hack Club projects)

```bash
uv sync
uv run Pynzor --help
```

After installation the `Pynzor` command is available globally.

---

## Configuration

`config.yaml` holds global defaults. All values can be overridden at runtime via CLI flags.

```yaml
# config.yaml

http:
  timeout: 10          # seconds per request
  retries: 3
  user_agent: "Pynzor/1.0 (educational)"
  follow_redirects: true
  rate_limit: 50       # max requests per second

output:
  directory: "./reports"
  format: "json"       # json | html | both

scanner:
  ports: [80, 443, 8080, 8443, 3000, 5000]

fuzzer:
  threads: 20
  extensions: [".php", ".html", ".bak", ".env"]
  status_codes: [200, 201, 301, 302, 403]

subdomain:
  resolver: "8.8.8.8"
  threads: 50
```

---

## CLI Usage

### Global flags

```
Pynzor [OPTIONS] COMMAND [ARGS]...

Options:
  --target   -t   TEXT     Target URL or domain (required for most commands)
  --output   -o   PATH     Directory to save reports
  --format   -f   TEXT     Report format: json, html, both [default: json]
  --verbose  -v            Enable verbose output
  --no-color               Disable colour output
  --config   -c   PATH     Path to custom config.yaml
  --help                   Show this message and exit
```

### Commands

| Command      | Description                              |
|--------------|------------------------------------------|
| `scan`       | Full scan — runs all enabled modules     |
| `fuzz`       | Directory and parameter fuzzing          |
| `headers`    | HTTP security header analysis            |
| `sqli`       | SQL injection probe                      |
| `xss`        | Reflected XSS detection                  |
| `subdomain`  | Subdomain enumeration                    |
| `report`     | Re-generate a report from saved JSON     |

### Examples

```bash
# Run a full scan and save an HTML report
Pynzor scan -t https://example.com -f html

# Directory fuzzing with a custom wordlist
Pynzor fuzz -t https://example.com --wordlist ./mylist.txt --threads 30

# Check security headers only
Pynzor headers -t https://example.com

# Subdomain enumeration
Pynzor subdomain -t example.com

# SQL injection probe on a specific parameter
Pynzor sqli -t "https://example.com/item?id=1"

# XSS scan with verbose output
Pynzor xss -t https://example.com -v
```

---

## Modules

### Scanner

**File:** `modules/scanner.py`

Performs lightweight port scanning and service fingerprinting on the target host. Uses async TCP connection attempts — no raw sockets, no root required.

**Function signature:**

```python
async def run(target: str, ports: list[int], timeout: float) -> list[ScanResult]
```

**`ScanResult` dataclass:**

```python
@dataclass
class ScanResult:
    port: int
    open: bool
    banner: str | None
    service: str | None
```

**What it checks:**

- Common web ports (80, 443, 8080, 8443, 3000, 5000, 8000)
- Grabs HTTP banner from open ports
- Detects TLS vs plain HTTP

**Example output:**

```
PORT     STATE   SERVICE    BANNER
80       open    http       Apache/2.4.54
443      open    https      nginx/1.23
8080     closed  —          —
```

---

### Fuzzer

**File:** `modules/fuzzer.py`

Sends requests for each entry in a wordlist to discover hidden directories, files, and endpoints. Supports common file extension appending.

**Function signature:**

```python
async def run(
    target: str,
    wordlist: Path,
    extensions: list[str],
    threads: int,
    status_codes: list[int],
) -> list[FuzzResult]
```

**`FuzzResult` dataclass:**

```python
@dataclass
class FuzzResult:
    url: str
    status_code: int
    content_length: int
    redirect_to: str | None
```

**What it checks:**

- Iterates every word in the wordlist, optionally appending extensions
- Filters results by status code whitelist
- Reports content-length to help identify real pages vs. honeypots

**Example output:**

```
URL                              STATUS   SIZE
/admin                           200      4321 B
/backup.zip                      200      1.2 MB
/config.php.bak                  403      512 B
/.env                            200      89 B    ← HIGH
```

---

### Header Checker

**File:** `modules/headers.py`

Fetches the target's HTTP response headers and audits them against a checklist of security best practices.

**Function signature:**

```python
async def run(target: str) -> list[HeaderFinding]
```

**`HeaderFinding` dataclass:**

```python
@dataclass
class HeaderFinding:
    header: str
    present: bool
    value: str | None
    severity: Literal["info", "low", "medium", "high"]
    recommendation: str
```

**Headers checked:**

| Header                        | Severity if missing |
|-------------------------------|---------------------|
| `Strict-Transport-Security`   | high                |
| `Content-Security-Policy`     | high                |
| `X-Content-Type-Options`      | medium              |
| `X-Frame-Options`             | medium              |
| `Referrer-Policy`             | low                 |
| `Permissions-Policy`          | low                 |
| `Server` (info disclosure)    | low                 |
| `X-Powered-By` (info disclose)| low                 |

---

### SQL Injection Probe

**File:** `modules/sqli.py`

Injects a set of classic SQL injection payloads into URL query parameters and form fields, then analyses the response for error messages or behavioural differences.

**Function signature:**

```python
async def run(target: str, params: list[str] | None) -> list[SqliResult]
```

**`SqliResult` dataclass:**

```python
@dataclass
class SqliResult:
    parameter: str
    payload: str
    evidence: str        # matched error string or timing delta
    severity: Literal["low", "medium", "high", "critical"]
```

**Techniques used:**

- **Error-based** — detects MySQL, PostgreSQL, MSSQL, SQLite error strings in responses
- **Boolean-based** — compares response length for `AND 1=1` vs `AND 1=2`
- **Time-based blind** — measures response time for `SLEEP(3)` / `WAITFOR DELAY` payloads

> **Note:** This module is intentionally non-destructive. It does not run `DROP`, `DELETE`, or `UPDATE` statements.

---

### XSS Detector

**File:** `modules/xss.py`

Tests URL parameters and input fields for reflected cross-site scripting by injecting harmless marker payloads and checking if they appear unescaped in the response body.

**Function signature:**

```python
async def run(target: str) -> list[XssResult]
```

**`XssResult` dataclass:**

```python
@dataclass
class XssResult:
    url: str
    parameter: str
    payload: str
    context: Literal["html", "attribute", "js", "css"]
    severity: Literal["medium", "high"]
```

**Payload strategy:**

- Unique token payloads (e.g. `xss-probe-<uuid>`) are injected first to find reflection
- Context-specific payloads are then chosen based on where the token appears in the DOM
- No actual script execution — detection only

---

### Subdomain Enumerator

**File:** `modules/subdomain.py`

Resolves entries from the bundled subdomain wordlist against the target domain using async DNS lookups.

**Function signature:**

```python
async def run(domain: str, wordlist: Path, resolver: str, threads: int) -> list[SubdomainResult]
```

**`SubdomainResult` dataclass:**

```python
@dataclass
class SubdomainResult:
    subdomain: str
    ip_addresses: list[str]
    cname: str | None
    alive: bool          # HTTP 2xx/3xx on port 80 or 443
```

**What it does:**

- Performs async DNS A/CNAME record lookups for each wordlist entry
- Optionally probes discovered subdomains over HTTP/HTTPS to confirm they are live
- Detects wildcard DNS to avoid false positives

---

## Utilities

### HTTP Client

**File:** `utils/http_client.py`

A thin wrapper around `httpx.AsyncClient` that adds retries, rate limiting, and a consistent user-agent header.

```python
from utils.http_client import get_client

async with get_client() as client:
    response = await client.get("https://example.com")
```

**Features:**

- Configurable timeout, retries, and follow-redirects
- Semaphore-based rate limiting
- Raises `TargetUnreachableError` on connection failure
- Strips cookies between requests by default (stateless mode)

---

### Logger

**File:** `utils/logger.py`

Wraps the [Rich](https://github.com/Textualize/rich) library for consistent, coloured terminal output.

```python
from utils.logger import log

log.info("Scanning target...")
log.success("Found open port: 443")
log.warning("Missing header: X-Frame-Options")
log.critical("Possible SQLi in ?id= parameter")
log.debug("Raw response: ...")   # only shown with --verbose
```

**Severity colours:**

| Level      | Colour  |
|------------|---------|
| `info`     | blue    |
| `success`  | green   |
| `warning`  | yellow  |
| `critical` | red     |
| `debug`    | grey    |

---

### Validators

**File:** `utils/validators.py`

Input sanitisation helpers used by the CLI layer before any module receives a target.

```python
from utils.validators import validate_url, validate_domain

url = validate_url("https://example.com")          # returns parsed URL or raises
domain = validate_domain("example.com")            # strips scheme, path, port
```

**Checks performed:**

- URL must include a scheme (`http://` or `https://`)
- Host must resolve in DNS (optional, skippable with `--no-resolve`)
- Rejects private/loopback addresses unless `--allow-local` is passed
- Rejects inputs longer than 2048 characters

---

## Output & Reporting

### JSON report

All module results are serialised to a single JSON file.

```json
{
  "target": "https://example.com",
  "timestamp": "2025-04-10T14:22:00Z",
  "summary": {
    "total_findings": 12,
    "critical": 1,
    "high": 3,
    "medium": 5,
    "low": 3
  },
  "findings": [
    {
      "module": "headers",
      "severity": "high",
      "title": "Missing Content-Security-Policy",
      "detail": "No CSP header found. ...",
      "recommendation": "Add a Content-Security-Policy header..."
    }
  ]
}
```

### HTML report

A self-contained single-file HTML report with a sortable findings table. Generated from a Jinja2 template at `output/template.html`. No external CDN dependencies — all styles are inlined.

```bash
Pynzor scan -t https://example.com -f html
# Saves to ./reports/example.com_2025-04-10.html
```

---

## Wordlists

Bundled wordlists are stored in `wordlists/`. All lists are plain text, one entry per line, no comments.

| File                  | Entries | Source / Notes                        |
|-----------------------|---------|---------------------------------------|
| `common-dirs.txt`     | ~2 500  | Curated from SecLists raft-medium     |
| `common-params.txt`   | ~500    | Common GET/POST parameter names       |
| `subdomains.txt`      | ~10 000 | Curated from SecLists subdomains-top  |

You can supply your own wordlist to any module that accepts one via `--wordlist`.

---

## Testing

Tests live in `tests/` and use `pytest` with `pytest-asyncio` for async module tests. A mock HTTP server (via `respx`) is used so tests never make real network requests.

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=Pynzor --cov-report=term-missing

# Run only a specific module's tests
pytest tests/test_fuzzer.py -v
```

**Test conventions:**

- Each module has a corresponding `test_<module>.py`
- `conftest.py` provides shared fixtures: mock client, sample responses, temp wordlists
- Tests are marked `@pytest.mark.asyncio` where needed
- Aim for >80% coverage before shipping

---

## Adding a New Module

1. Create `modules/mymodule.py` with a `run()` async function that returns a list of dataclass results.
2. Register the command in `cli/commands.py`:

```python
@app.command()
def mymodule(target: str = typer.Option(..., "--target", "-t")):
    """Short description shown in --help."""
    results = asyncio.run(modules.mymodule.run(target))
    formatter.print_table(results)
```

3. Add a `Finding` converter so results flow into the report:

```python
# output/reporter.py
def to_finding(result: MyResult) -> Finding:
    return Finding(module="mymodule", severity=result.severity, ...)
```

4. Write tests in `tests/test_mymodule.py`.
5. Document it in this file under [Modules](#modules).

---

## Dependencies

Defined in `pyproject.toml`:

```toml
[project]
name = "Pynzor"
version = "0.1.0"
requires-python = ">=3.10"

dependencies = [
    "typer[all]>=0.12",
    "httpx>=0.27",
    "rich>=13",
    "dnspython>=2.6",
    "beautifulsoup4>=4.12",
    "pyyaml>=6",
    "jinja2>=3.1",
]

[project.optional-dependencies]
dev = [
    "pytest>=8",
    "pytest-asyncio>=0.23",
    "respx>=0.21",
    "pytest-cov>=5",
]

[project.scripts]
Pynzor = "main:app"
```

---

## Ethics & Legal Notice

This tool is intended for **authorised testing only**.

- Only run `Pynzor` against systems you own or have explicit written permission to test.
- Unauthorised scanning and probing is illegal in most jurisdictions (e.g. Computer Fraud and Abuse Act in the US, Computer Misuse Act in the UK).
- The authors are not responsible for any misuse of this software.
- When in doubt, use a deliberately vulnerable practice target such as [DVWA](https://github.com/digininja/DVWA), [HackTheBox](https://www.hackthebox.com/), or [TryHackMe](https://tryhackme.com/).

---

## Contributing

Pull requests are welcome. Please:

1. Fork the repo and create a feature branch: `git checkout -b feat/my-module`
2. Follow the [Adding a New Module](#adding-a-new-module) guide
3. Ensure all tests pass: `pytest`
4. Open a PR with a clear description of what the module does and what targets it is safe to use against

---

## License

MIT License — see `LICENSE` for details.
