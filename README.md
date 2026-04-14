# Pynzor

Web pentesting, sharpened.

> An open-source Python CLI I built - scan ports, fuzz directories, hunt headers, and probe for vulns, all from one tool. No setup headaches, just point it to a target and go.

## Demo

<video src="demo/Pyznor-demo.mp4" controls width="100%"></video>

## Key Features

- **Modular architecture** - each technique is an isolated Python module
- **Rich terminal output** with color-coded severity levels
- **Loading indicators** - spinner feedback during every scan so you know it's working
- **JSON and HTML report** export
- **Async HTTP engine** via `httpx` for fast parallel requests
- **Bundled wordlists** - works out of the box
- **Fully tested** with `pytest`

## Installation

```bash
git clone https://github.com/yal212/Pynzor.git
cd Pynzor
pip install -e .
```

Or with uv (recommended):
```bash
uv sync
uv run Pynzor --help
```

## Quick Usage

### Run a full scan and save an HTML report

```bash
Pynzor scan -t https://example.com -f html
```

### Directory fuzzing

```bash
Pynzor fuzz -t https://example.com --wordlist ./mylist.txt --threads 30
```

### Check security headers

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

### XSS scan with verbose output

```bash
Pynzor xss -t https://example.com -v
```

## Commands

| Command | Description |
|---------|-------------|
| scan | Full scan - run all modules |
| fuzz | Directory fuzzing |
| headers | Security header analysis |
| sqli | SQL injection probe |
| xss | Reflected XSS detection |
| subdomain | Subdomain enumeration |
| report | Re-generate report from JSON |

## Configuration

Edit `config.yaml` to customize:
- HTTP timeout, retries, user-agent
- Rate limiting
- Output format and directory
- Port lists, wordlist paths
- Thread count

## Requirements

- Python 3.10+
- pip or uv

## Disclaimer

For authorized testing only. Only use on systems you own or have explicit written permission to test.

---

MIT License - see LICENSE for details.
