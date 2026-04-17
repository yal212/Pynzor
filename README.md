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

[Watch the demo on YouTube](https://youtu.be/0LFTOfkyf2A)

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

### pip (recommended)

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

### Directory fuzzing

```bash
Pynzor fuzz -t https://example.com --wordlist ./mylist.txt --threads 30
```

### Security header analysis

```bash
Pynzor headers -t https://example.com
```

### Subdomain enumeration

```bash
Pynzor subdomain -t https://example.com
```

### SQL injection probe

```bash
Pynzor sqli -t "https://example.com/item?id=1"
```

### XSS detection

```bash
Pynzor xss -t https://example.com -v
```

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
