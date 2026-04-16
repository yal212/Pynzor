# Pynzor

Web pentesting, sharpened.

> An open-source Python CLI - scan ports, fuzz directories, hunt headers, and probe for vulns, all from one tool. No setup headaches, just point it to a target and go.

## Demo

![Pynzor Demo](https://youtu.be/0LFTOfkyf2A)

## Key Features

- **Modular architecture** - each technique is an isolated Python module
- **Rich terminal output** with color-coded severity levels
- **Loading indicators** - spinner feedback during every scan so you know it's working
- **JSON and HTML report** export
- **Async HTTP engine** via `httpx` for fast parallel requests
- **Bundled wordlists** - works out of the box
- **Fully tested** with `pytest`

## Download

No Python required. Grab the latest binary from [GitHub Releases](https://github.com/yal212/Pynzor/releases):

| Platform | File |
|----------|------|
| Windows  | `Pynzor.exe` |
| macOS    | `Pynzor-macos` |
| Linux    | `Pynzor-linux` |

**Windows:**
```
Pynzor.exe --help
```

**macOS:**
```bash
chmod +x Pynzor-macos
./Pynzor-macos --help
```

**Linux:**
```bash
chmod +x Pynzor-linux
./Pynzor-linux --help
```

## Install from Source

Requires Python 3.10+.

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

## Commands

| Command | Description |
|---------|-------------|
| `scan` | Full scan - run all modules |
| `fuzz` | Directory fuzzing |
| `headers` | Security header analysis |
| `sqli` | SQL injection probe |
| `xss` | Reflected XSS detection |
| `subdomain` | Subdomain enumeration |
| `report` | Re-generate report from JSON |

## Configuration

Edit `config.yaml` to customize behavior (source installs only):

- HTTP timeout, retries, user-agent
- Rate limiting
- Output format and directory
- Port lists and wordlist paths
- Thread counts

## Disclaimer

For authorized testing only. Only use on systems you own or have explicit written permission to test.

---

MIT License - see LICENSE for details.
