<div align="center">

```
██████╗ ██╗   ██╗███╗   ██╗███████╗ ██████╗ ██████╗
██╔══██╗╚██╗ ██╔╝████╗  ██║╚══███╔╝██╔═══██╗██╔══██╗
██████╔╝ ╚████╔╝ ██╔██╗ ██║  ███╔╝ ██║   ██║██████╔╝
██╔═══╝   ╚██╔╝  ██║╚██╗██║ ███╔╝  ██║   ██║██╔══██╗
██║        ██║   ██║ ╚████║███████╗╚██████╔╝██║  ██║
╚═╝        ╚═╝   ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
```

**Web pentesting, sharpened.**

[![PyPI version](https://img.shields.io/pypi/v/Pynzor?color=blue)](https://pypi.org/project/Pynzor/)
[![Python](https://img.shields.io/pypi/pyversions/Pynzor)](https://pypi.org/project/Pynzor/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE.md)
[![GitHub Stars](https://img.shields.io/github/stars/yal212/Pynzor?style=social)](https://github.com/yal212/Pynzor/stargazers)

Scan ports · Fuzz directories · Hunt headers · Probe for SQLi & XSS · Enumerate subdomains

[Demo](#demo) · [Install](#install) · [Usage](#usage) · [Commands](#commands) · [Download](#download)

</div>

---

## Demo

[Watch the demo on YouTube](https://youtu.be/oFKiFmnZOr4?si=Bz5Yv-VGd-BdK28)

---

## Features

- **One command, full scan** — run every module against a target in a single invocation
- **Modular architecture** — each technique is an isolated Python module, easy to extend
- **Rich terminal output** — color-coded severity levels, live spinners, clean layout
- **JSON & HTML reports** — export results for sharing or archiving
- **Async HTTP engine** — `httpx`-powered parallel requests for speed
- **Bundled wordlists** — works out of the box, no setup required
- **Fully tested** — `pytest` test suite with async support

---

## Install

### pipx (recommended for CLI users)

[pipx](https://pipx.pypa.io/) installs Pynzor into its own isolated venv, keeping your system Python clean:

```bash
pipx install Pynzor
```

### pip

```bash
pip install Pynzor
```

### From source

```bash
git clone https://github.com/yal212/Pynzor.git
cd Pynzor
pip install -e .
```

### uv

```bash
uv sync
uv run Pynzor --help
```

---

## Download

No Python required — grab a prebuilt binary from [GitHub Releases](https://github.com/yal212/Pynzor/releases/latest):

| Platform | File | Run |
|----------|------|-----|
| Windows  | `Pynzor.exe` | `Pynzor.exe --help` |
| macOS    | `Pynzor-macos` | `chmod +x Pynzor-macos && ./Pynzor-macos --help` |
| Linux    | `Pynzor-linux` | `chmod +x Pynzor-linux && ./Pynzor-linux --help` |

> **macOS note:** If blocked by Gatekeeper, run `xattr -d com.apple.quarantine ./Pynzor-macos` or allow it via System Settings → Privacy & Security.

---

## Usage

### Full scan with HTML report

```bash
Pynzor scan -t https://example.com -f html
```

<details>
<summary>Sample output</summary>

```
Running full scan on https://example.com

╭─ Port Scanner ─╮
╰────────────────╯
 Port   Status   Service     Latency
 80     open     http        0.042s
 443    open     https       0.039s
 22     closed                0.012s

╭─ Directory Fuzzer ─╮
╰────────────────────╯
 URL                         Status   Size
 https://example.com/admin   401      92
 https://example.com/api     200      4213
Found 2 directories

╭─ Security Headers ─╮
╰────────────────────╯
 Header                      Status   Risk
 Strict-Transport-Security   ✓        high
 Content-Security-Policy     ✗        high
Score: 65/100 (Grade: D)

JSON report saved to: reports/scan_20260421_141203.json
HTML report saved to: reports/scan_20260421_141203.html
```
</details>

### Directory fuzzing

```bash
Pynzor fuzz -t https://example.com --wordlist ./mylist.txt --threads 30
```

<details>
<summary>Sample output</summary>

```
Fuzzing directories on https://example.com
! SPA/catch-all detected (probe '/pynzor-baseline-4f3a...' returned 200,
  4213 bytes). Filtering matches.
 URL                         Status   Size
 https://example.com/admin   401      92
 https://example.com/api/v1  200      1842
Found 2 directories
Filtered 128 paths matching catch-all baseline (use --no-baseline to disable)
```

Baseline filtering protects against SPAs and reverse proxies that return
`200 OK` + the same body for every path. Use `--no-baseline` to see raw
results.
</details>

### Security header analysis

```bash
Pynzor headers -t https://example.com
```

<details>
<summary>Sample output</summary>

```
Analyzing headers on https://example.com
 Header                      Status   Risk
 Strict-Transport-Security   ✓        high
 Content-Security-Policy     ✗        high
 X-Frame-Options             ✓        high
 X-Content-Type-Options      ✓        medium
 Referrer-Policy             ✗        medium
Score: 70/100 (Grade: C)
Missing: Content-Security-Policy, Referrer-Policy
```
</details>

### Subdomain enumeration

```bash
Pynzor subdomain -t https://example.com
```

<details>
<summary>Sample output</summary>

```
Enumerating subdomains of example.com
! Wildcard DNS detected → 203.0.113.42. Subdomains resolving to these IPs
  are filtered (use --include-wildcard to show them).
 Subdomain                 Status
 api.example.com           responded
 mail.example.com          responded
Found 2 subdomains
Filtered 87 subdomains matching wildcard DNS
```

Wildcard detection probes two random subdomains first; if both resolve to
the same IP set, matching wordlist hits are filtered to avoid false
positives.
</details>

### SQL injection probe

```bash
Pynzor sqli -t "https://example.com/item?id=1"
```

### XSS detection

```bash
Pynzor xss -t https://example.com -v
```

### Sample reports

- [Sample JSON report](docs/samples/sample_report.json)
- [Sample HTML report](docs/samples/sample_report.html) — open in a browser

---

## Commands

| Command | Description |
|---------|-------------|
| `scan` | Full scan — run all modules |
| `fuzz` | Directory & file fuzzing |
| `headers` | Security header analysis |
| `sqli` | SQL injection probe |
| `xss` | Reflected XSS detection |
| `subdomain` | Subdomain enumeration |
| `report` | Re-generate report from JSON |

---

## Configuration

Source installs include a `config.yaml` for fine-tuning:

- HTTP timeout, retries, user-agent string
- Rate limiting and redirect behavior
- Output format and directory
- Port lists, wordlist paths, thread counts

---

## Disclaimer

Pynzor is for **authorized testing only**. Only use it on systems you own or have explicit written permission to test. Unauthorized use is illegal and unethical.

---

<div align="center">

MIT License — see [LICENSE](LICENSE.md) · Made by [yal212](https://github.com/yal212)

</div>
