# Pynzor Terminal Demo

This walkthrough is safe to replay in a CTF or local lab. Replace `target.lab` with an authorized target from your environment.

## 1. Confirm Install

```bash
Pynzor --version
Pynzor --help
```

Expected shape:

```text
Pynzor 1.1.0

Commands:
  scan       Run all modules (full scan)
  fuzz       Directory/file fuzzing or FUZZ-keyword request fuzzing
  ports      Port scan with optional service/version detection
  headers    Security header analysis
  sqli       SQL injection probe
  xss        Reflected XSS detection
  subdomain  Subdomain enumeration
  report     Re-generate report from JSON
```

## 2. First-Pass Recon

```bash
Pynzor scan -t https://target.lab -f both
```

What to look for:

- Open ports and likely services.
- Interesting web paths from the bundled directory wordlist.
- Missing security headers.
- SQLi/XSS probe indicators.
- Subdomains from the bundled subdomain wordlist.

## 3. Focused Port Check

```bash
Pynzor ports -t target.lab -p 22,80,443,8000-9000 -sV -oN notes/ports.txt
```

Use this when a box exposes multiple web services or uncommon HTTP ports.

## 4. Directory Fuzzing

```bash
Pynzor fuzz -t https://target.lab --threads 30
```

For extension-heavy CTF targets:

```bash
Pynzor fuzz -t https://target.lab -x php,html,txt --recursive --depth 2
```

## 5. Request Fuzzing

```bash
Pynzor fuzz -t https://target.lab/login -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=admin&password=FUZZ' \
  -w ./wordlists/passwords.txt -fc 401
```

This is ffuf-style substitution. Pynzor replaces `FUZZ` with each wordlist entry and applies match/filter options.

## 6. Report Review

```bash
Pynzor report docs/samples/sample_report.json
```

Reports are written to `./reports` unless `--output` points elsewhere.

## Recording the Cast

A recorded terminal session is tracked as an asciinema cast at
[pynzor-demo.cast](pynzor-demo.cast). It walks through `--version`, `headers`,
`ports`, `fuzz`, and `report` against a local `127.0.0.1` fixture — no public
target is scanned. Replay it locally with:

```bash
asciinema play docs/demo/pynzor-demo.cast
```

Regenerate it at any time. The script captures real CLI output against the
local fixture, so no external network is used:

```bash
uv run python docs/demo/record_demo.py
```

To record manually instead, start a local fixture and run `asciinema rec` while
you drive the commands above yourself.

## Safety Note

Only run these commands against systems you own, CTF/lab infrastructure, or targets where you have explicit authorization.
