<div align="center">

```
██████╗ ██╗   ██╗███╗   ██╗███████╗ ██████╗ ██████╗
██╔══██╗╚██╗ ██╔╝████╗  ██║╚══███╔╝██╔═══██╗██╔══██╗
██████╔╝ ╚████╔╝ ██╔██╗ ██║  ███╔╝ ██║   ██║██████╔╝
██╔═══╝   ╚██╔╝  ██║╚██╗██║ ███╔╝  ██║   ██║██╔══██╗
██║        ██║   ██║ ╚████║███████╗╚██████╔╝██║  ██║
╚═╝        ╚═╝   ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
```

**CTF and lab web recon from one clean Python CLI.**

[![PyPI version](https://img.shields.io/pypi/v/Pynzor?color=blue)](https://pypi.org/project/Pynzor/)
[![Python](https://img.shields.io/pypi/pyversions/Pynzor)](https://pypi.org/project/Pynzor/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE.md)
[![GitHub Stars](https://img.shields.io/github/stars/yal212/Pynzor?style=social)](https://github.com/yal212/Pynzor/stargazers)

Ports · Directories · Headers · SQLi probes · XSS probes · Subdomains · JSON/HTML reports

[Install](#install) · [Quickstart](#quickstart) · [Commands](#commands) · [Demo](#demo) · [Safety](#safety)

</div>

---

## Why Pynzor

Pynzor is built for fast, authorized web recon in CTFs, training labs, and internal test environments. It gives you the common first-pass checks in one place without turning into an exploitation framework.

- **CTF/lab friendly**: quick scans, bundled wordlists, readable terminal output.
- **Recon coverage**: port checks, directory fuzzing, security headers, SQLi/XSS detection probes, and subdomain enumeration.
- **Async-first**: `httpx`-powered HTTP workflows with configurable concurrency.
- **Operator output**: colorized tables for humans plus JSON/HTML reports for notes and handoff.
- **Safe by design**: detection and probing only. No dumping, shelling, persistence, or destructive payloads.

## Install

Use `pipx` for an isolated CLI install:

```bash
pipx install Pynzor
Pynzor --help
```

The CLI is available as both `Pynzor` and the lowercase `pynzor` — the two are
interchangeable, so use whichever you prefer.

Install with `pip` if you prefer managing the environment yourself:

```bash
pip install Pynzor
```

Run from source:

```bash
git clone https://github.com/yal212/Pynzor.git
cd Pynzor
uv sync
uv run Pynzor --help
```

## Quickstart

Run a full recon pass and write reports:

```bash
Pynzor scan -t https://target.lab -f both
```

Check exposed ports with service detection:

```bash
Pynzor ports -t target.lab -p 22,80,443,8000-9000 -sV -oN notes/ports.txt
```

Fuzz web content with the bundled directory wordlist:

```bash
Pynzor fuzz -t https://target.lab --threads 30
```

Use ffuf-style request fuzzing with the `FUZZ` keyword:

```bash
Pynzor fuzz -t https://target.lab/login -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=admin&password=FUZZ' \
  -w ./wordlists/passwords.txt -fc 401
```

Review a saved JSON report:

```bash
Pynzor report docs/samples/sample_report.json
```

## Commands

| Command | Purpose |
|---------|---------|
| `Pynzor scan` | Run the full recon workflow against a target. |
| `Pynzor ports` | Scan TCP ports with optional service/version detection. |
| `Pynzor fuzz` | Run directory fuzzing or `FUZZ`-keyword request fuzzing. |
| `Pynzor headers` | Score common security headers. |
| `Pynzor sqli` | Probe URL parameters for SQL injection indicators. |
| `Pynzor xss` | Probe reflected XSS indicators. |
| `Pynzor subdomain` | Enumerate subdomains from a wordlist. |
| `Pynzor report` | Print a saved JSON report. |

Global helpers:

```bash
Pynzor --help
Pynzor --version
```

## Reports

Pynzor writes reports to `./reports` by default.

```bash
Pynzor scan -t https://target.lab -f json
Pynzor scan -t https://target.lab -f html
Pynzor scan -t https://target.lab -f both
```

Sample outputs:

- [Sample JSON report](docs/samples/sample_report.json)
- [Sample HTML report](docs/samples/sample_report.html)

## Demo

The tracked terminal walkthrough is in [docs/demo/terminal-demo.md](docs/demo/terminal-demo.md). It shows the expected launch flow without requiring public targets or destructive actions.

Video demo:

- [Watch the demo on YouTube](https://youtu.be/oFKiFmnZOr4?si=Bz5Yv-VGd-BdK28)

## Configuration

Pynzor ships a single canonical default config, bundled inside the package at
`src/pynzor/cli/config.yaml`. It is loaded automatically on every run — no setup
required. To customize, copy it somewhere writable and point `--config` at your
copy:

```bash
# copy the bundled default out of the installed package
python -c "import importlib.resources as r, shutil; shutil.copy(r.files('pynzor.cli') / 'config.yaml', 'pynzor.config.yaml')"
Pynzor scan -t https://target.lab --config ./pynzor.config.yaml
```

Bundled wordlists (`src/pynzor/cli/wordlists/`) and the HTML report template are
resolved relative to the config file, so both editable installs and standalone
binaries find them without any extra configuration.

Configurable areas:

- HTTP timeout, retries, user-agent, redirect behavior, and SSL verification.
- Scanner ports, timeouts, service detection, and concurrency.
- Fuzzer status codes, request match/filter rules, extensions, recursion depth, and wordlists.
- Subdomain wordlist and concurrency.
- Output format and report directory.

## Download Binaries

Tagged GitHub releases build PyInstaller binaries for Windows, macOS, and Linux:

| Platform | File | Run |
|----------|------|-----|
| Windows | `Pynzor.exe` | `Pynzor.exe --help` |
| macOS | `Pynzor-macos` | `chmod +x Pynzor-macos && ./Pynzor-macos --help` |
| Linux | `Pynzor-linux` | `chmod +x Pynzor-linux && ./Pynzor-linux --help` |

The binaries are self-contained: the default config, wordlists, and HTML report
template are bundled inside and resolved at runtime, so reports can be written to
any output directory you pass with `-o`. Each release build is smoke-tested
(`--version`, `--help`, `headers --help`) on its native runner in CI.

Platform notes:

- **macOS** — binaries are unsigned. If Gatekeeper blocks the binary, allow it
  from System Settings or clear the quarantine attribute:

  ```bash
  xattr -d com.apple.quarantine ./Pynzor-macos
  ```

  Built on Apple Silicon runners (`arm64`); run under Rosetta on Intel Macs if
  needed.
- **Linux** — built on `ubuntu-latest` against that image's glibc; very old
  distros may not be compatible. Prefer `pipx install Pynzor` there.
- **Windows** — TLS uses the bundled `certifi` CA store, so HTTPS targets work
  without a system Python.
- **UPX** — the spec enables UPX compression; if a corporate AV flags the
  binary, rebuild with `upx=False` in `Pynzor.spec`.

## Development

```bash
uv sync
uv run pytest
uv run Pynzor --help
```

The project targets Python 3.10+ and keeps dependencies intentionally small.

## Safety

Pynzor is for authorized testing only. Use it only on systems you own, CTF/lab targets you are allowed to test, or environments where you have explicit written permission. Unauthorized scanning or probing can be illegal and harmful.

Pynzor performs detection-oriented probes and recon. It does not include destructive payloads, exploit chains, credential dumping, persistence, or data exfiltration features.

## License

MIT License. See [LICENSE.md](LICENSE.md).
