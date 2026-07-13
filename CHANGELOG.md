# Changelog

All notable changes to Pynzor are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Command-level integration tests that run every command against a local HTTP
  fixture on `127.0.0.1`, with no external network access.
- Installed-wheel and per-platform binary smoke-test jobs in CI.
- Reproducible asciinema terminal demo (`docs/demo/pynzor-demo.cast`) plus a
  self-contained generator (`docs/demo/record_demo.py`) that records the flow
  against a local fixture.
- `CHANGELOG.md` and `RELEASING.md`.

### Changed
- Refactored the package to a `src/pynzor/` layout.
- Consolidated configuration into a single canonical default bundled inside the
  package (`src/pynzor/cli/config.yaml`), loaded automatically on every run.
- Normalized the report schema across all commands to a shared envelope
  (`schema_version: 1`, `module`, `target`, `findings`, `severity`, `metadata`).
- Updated the PyInstaller spec for the src layout so bundled config, wordlists,
  and the HTML report template resolve at runtime in standalone binaries.

## [1.1.0] - 2026-06-18

### Added
- Directory/file fuzzing and ffuf-style `FUZZ`-keyword request fuzzing in the
  `fuzz` command (custom method, headers, body, and match/filter rules).
- Port scanning with optional service/version detection (`ports -sV`).
- Security header scoring (`headers`).
- SQL injection probe (`sqli`) and reflected XSS probe (`xss`).
- Subdomain enumeration from a bundled wordlist (`subdomain`).
- JSON and HTML report output, plus a `report` command to print saved JSON
  reports.
- Fuzzer baseline detection for SPA/proxy catch-all responses
  (`--no-baseline` opts out).
- Subdomain wildcard-DNS detection and filtering
  (`--include-wildcard` opts in).

## [1.0.8] - 2026-04-25

### Added
- Bundled wordlists and per-command sample output in the README.

### Fixed
- Post-ship correctness and UX fixes across the recon commands.

## [1.0.0] - 2026-04-14

### Added
- Initial release: async `httpx`-powered web recon CLI with colorized terminal
  output, `pipx`/`pip` install, and a bundled default configuration.

[Unreleased]: https://github.com/yal212/Pynzor/compare/v1.0.8...HEAD
[1.0.8]: https://github.com/yal212/Pynzor/releases/tag/v1.0.8
[1.0.0]: https://github.com/yal212/Pynzor/releases/tag/v1.0.0
