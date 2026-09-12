<div align="center">

# Pynzor

**Web recon for CTFs and labs — an interactive dashboard, or a clean Python CLI.**

[![PyPI version](https://img.shields.io/pypi/v/Pynzor?color=blue)](https://pypi.org/project/Pynzor/)
[![Python](https://img.shields.io/pypi/pyversions/Pynzor)](https://pypi.org/project/Pynzor/)
[![CI](https://github.com/yal212/Pynzor/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/yal212/Pynzor/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://github.com/yal212/Pynzor/blob/main/LICENSE.md)
[![GitHub Stars](https://img.shields.io/github/stars/yal212/Pynzor?style=social)](https://github.com/yal212/Pynzor/stargazers)

Ports · Directories · Headers · SQLi · XSS · Subdomains · JSON/HTML reports

[Install](#install) · [Dashboard](#dashboard) · [Quickstart](#quickstart) · [Commands](#commands) · [Documentation](#documentation) · [Safety](#safety)

</div>

---

## Overview

Pynzor runs the common first-pass web checks for CTFs, training labs, and
internal test environments, without turning into an exploitation framework.

- **Interactive by default** — run `Pynzor` with no arguments for a full-screen
  dashboard with live progress, streaming results, and one-key export.
- **Recon coverage** — port checks, directory fuzzing, security headers,
  SQLi/XSS detection probes, and subdomain enumeration.
- **Async-first** — `httpx`-powered HTTP workflows with configurable concurrency.
- **Operator output** — colorized tables for humans, JSON/HTML reports for notes
  and handoff.
- **CTF/lab friendly** — quick scans, bundled wordlists, readable terminal output.
- **Safe by design** — detection and probing only. No dumping, shelling,
  persistence, or destructive payloads.

## Install

Use `pipx` for an isolated CLI install:

```bash
pipx install Pynzor
Pynzor --help
```

The CLI is available as both `Pynzor` and the lowercase `pynzor`; the two are
interchangeable.

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

Standalone binaries for Windows, macOS, and Linux are attached to every tagged
release — see [docs/binaries.md](https://github.com/yal212/Pynzor/blob/main/docs/binaries.md).

## Dashboard

Run `Pynzor` with no arguments in a terminal and you get the dashboard, laid out
like `lazygit`: a column of side panels you jump to by number, a main panel that
always shows whatever the focused panel is pointing at, a command log, and a
bottom bar listing the keys that work right here.

![The Pynzor dashboard mid-scan: a column of five numbered panels — Status, Modules, Options, Findings, Reports — beside a results table of fuzzing hits, with a command log showing the equivalent Pynzor CLI commands and a row of keybindings along the bottom.](https://raw.githubusercontent.com/yal212/Pynzor/main/docs/images/dashboard.svg)

Five side panels, jumped to with `1`-`5` or cycled with `<tab>`. The main panel
re-renders for whatever your cursor is on:

| # | Panel | The main panel then shows |
| --- | --- | --- |
| 1 | Status | The session: target, selection, findings, equivalent CLI command |
| 2 | Modules | That module's progress, verdict, and findings table |
| 3 | Options | The highlighted option's help, value, and `config.yaml` path |
| 4 | Findings | The highlighted finding, expanded field by field |
| 5 | Reports | The saved report envelope |

Essential keys:

| Key | Scope | Does |
| --- | --- | --- |
| `<tab>` | Panels | Next panel |
| `<space>` | Modules | Toggle module |
| `r` | Run | Run |
| `s` | Run | Stop |
| `e` | Run | Export reports |
| `c` | Run | Copy CLI command |
| `/` | View | Filter |
| `x` | App | Menu |
| `?` | App | Keybindings |
| `q` | App | Quit |

Press `?` in the app for the full cheatsheet, or see
[docs/dashboard.md](https://github.com/yal212/Pynzor/blob/main/docs/dashboard.md)
for the complete keybinding reference and panel behaviour.

Export (`e`) writes the same `schema_version: 1` JSON the CLI writes, through the
same reporter — dashboard output and `Pynzor <command>` output are interchangeable.

Launch it with a target already filled in:

```bash
Pynzor tui -t https://target.lab
```

**The CLI is unchanged.** Passing any argument takes the normal flag-driven
path, and a bare run that is not attached to a terminal (a pipe, a script, CI)
prints help exactly as it always has.

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
| `Pynzor tui` | Launch the interactive dashboard (the default with no arguments). |

Run `Pynzor --help` or `Pynzor --version` for the global helpers.

## Reports

Pynzor writes reports to `./reports` by default, in JSON, HTML, or both:

```bash
Pynzor scan -t https://target.lab -f json
Pynzor scan -t https://target.lab -f html
Pynzor scan -t https://target.lab -f both
```

Review a saved report without rescanning:

```bash
Pynzor report docs/samples/sample_report.json
```

Sample outputs:
[JSON](https://github.com/yal212/Pynzor/blob/main/docs/samples/sample_report.json) ·
[HTML](https://github.com/yal212/Pynzor/blob/main/docs/samples/sample_report.html)

## Documentation

| Guide | Covers |
|-------|--------|
| [Dashboard](https://github.com/yal212/Pynzor/blob/main/docs/dashboard.md) | Full keybinding reference, panel behaviour, regenerating the screenshot |
| [Configuration](https://github.com/yal212/Pynzor/blob/main/docs/configuration.md) | The bundled default config, every configurable area, tuning rate limits for a lab |
| [Binaries](https://github.com/yal212/Pynzor/blob/main/docs/binaries.md) | Standalone release builds and per-platform notes |
| [Terminal demo](https://github.com/yal212/Pynzor/blob/main/docs/demo/terminal-demo.md) | A written walkthrough, and how to replay or re-record the asciinema cast |
| [Changelog](https://github.com/yal212/Pynzor/blob/main/CHANGELOG.md) | Release history |
| [Releasing](https://github.com/yal212/Pynzor/blob/main/RELEASING.md) | The maintainer release process |

A recorded terminal session is tracked as an asciinema cast at
[docs/demo/pynzor-demo.cast](https://github.com/yal212/Pynzor/blob/main/docs/demo/pynzor-demo.cast);
there is also a [video demo on YouTube](https://youtu.be/oFKiFmnZOr4?si=Bz5Yv-VGd-BdK28).

## Development

```bash
uv sync
uv run pytest
uv run Pynzor --help
```

The project targets Python 3.10+ and keeps dependencies intentionally small. The
dashboard is built on [Textual](https://textual.textualize.io/), which is pure
Python and shares the `rich` renderer the CLI already uses.

## Safety

Pynzor is for authorized testing only. Use it only on systems you own, CTF/lab
targets you are allowed to test, or environments where you have explicit written
permission. Unauthorized scanning or probing can be illegal and harmful.

Pynzor performs detection-oriented probes and recon. It does not include
destructive payloads, exploit chains, credential dumping, persistence, or data
exfiltration features.

## License

MIT. See [LICENSE.md](https://github.com/yal212/Pynzor/blob/main/LICENSE.md).
