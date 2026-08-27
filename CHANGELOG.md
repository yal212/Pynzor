# Changelog

All notable changes to Pynzor are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Interactive dashboard.** Running `Pynzor` with no arguments in a terminal
  now launches a full-screen Textual app: pick modules, watch per-module
  progress bars fill and hits stream into tables live, drill into any finding,
  edit options in place, browse past reports, and export with one key. Also
  reachable as `Pynzor tui [-t TARGET]`.
- Optional `on_progress` callbacks on every module (`pynzor.core.events`), so a
  frontend can render live progress and stream findings as they are found.
  Omitting the callback leaves the existing code paths untouched.
- `pynzor.core`: a Typer-free service layer (`config`, `runner`, `models`,
  `events`, `parsing`) shared by the CLI and the dashboard, so both produce
  identical report envelopes from identical option resolution.
- A footer in the dashboard showing the exact equivalent CLI command for the
  current configuration, generated from the same flag metadata the options
  form uses.
- Command-level integration tests that run every command against a local HTTP
  fixture on `127.0.0.1`, with no external network access.
- Pilot-driven tests for the dashboard and contract tests for the progress
  callbacks.
- Installed-wheel and per-platform binary smoke-test jobs in CI.
- Reproducible asciinema terminal demo (`docs/demo/pynzor-demo.cast`) plus a
  self-contained generator (`docs/demo/record_demo.py`) that records the flow
  against a local fixture.
- `CHANGELOG.md` and `RELEASING.md`.

### Fixed
- **Dashboard lag.** `Static.update()` defaults to `layout=True`, so every
  progress repaint forced a full-screen layout pass — 535 of them (33.8/s)
  during a default fuzz run. Fixed-size updates now pass `layout=False`, and
  painting moved off the per-event path onto a 15 fps flush, so UI cost no
  longer scales with wordlist size. The same run now measures 6 layout passes.
  Guarded by a regression test that counts layout passes.
- `sqli.rate_limit` and `xss.rate_limit` in `config.yaml` were read by nothing:
  the modules each constructed their own `ClientConfig` with a hardcoded value.
  Rate limit and timeout now resolve from the module's config section, then the
  `http` section, then the previously hardcoded value. Shipped defaults are
  unchanged, so scan behaviour against real targets is identical.

### Known issues
- [#16](https://github.com/yal212/Pynzor/issues/16) — `HTTPClient._rate_limit`
  reads and writes `_last_request_time` without a
  lock, so concurrent requests can clear the check together and the effective
  rate is looser than configured (~184 req/s at `rate_limit: 0.1`). Left as-is
  deliberately: making it a strict global limiter would slow every scan down
  relative to previous releases.
- [#17](https://github.com/yal212/Pynzor/issues/17) — a custom `--config` file
  must be complete; a partial override crashes with an unhandled `KeyError`.
- [#18](https://github.com/yal212/Pynzor/issues/18) — in the dashboard's
  options panel, clearing the extensions field falls back to
  the config default rather than opting out. The CLI's `-x ""` opt-out has no
  equivalent in the form yet.

### Changed
- Rate limit and timeout are now configurable per module (`fuzzer.rate_limit`
  and `subdomain.rate_limit` added to `config.yaml` at their existing values),
  resolved through `pynzor.core.runner.client_config_for` so the CLI and the
  dashboard stay in step.
- Report-envelope construction moved out of the individual command bodies into
  `pynzor.core.runner`, removing the duplication across all eight commands.
  Emitted reports are byte-identical to the previous output.
- `Formatter.no_color` is now instance state rather than a class attribute, and
  `Formatter` accepts an injected console instead of writing to a module global.
- Pinned ruff's rule selection in `pyproject.toml`. `ruff>=0.6` is unpinned and
  ruff's *default* selection has grown across releases, so a new ruff would
  silently start failing CI on unchanged code.
- Refactored the package to a `src/pynzor/` layout.
- Consolidated configuration into a single canonical default bundled inside the
  package (`src/pynzor/cli/config.yaml`), loaded automatically on every run.
- Normalized the report schema across all commands to a shared envelope
  (`schema_version: 1`, `module`, `target`, `findings`, `severity`, `metadata`).
- Updated the PyInstaller spec for the src layout so bundled config, wordlists,
  and the HTML report template resolve at runtime in standalone binaries, and
  extended it to collect Textual's data files and dynamically-resolved widgets.

### Dependencies
- Added `textual>=0.79`. It is pure Python with no compiled extensions, comes
  from the authors of `rich` (already a dependency), and reuses that renderer —
  hand-rolling the dashboard on `rich.Live` would have cost far more code for a
  worse result.

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

[Unreleased]: https://github.com/yal212/Pynzor/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/yal212/Pynzor/releases/tag/v1.1.0
[1.0.8]: https://github.com/yal212/Pynzor/releases/tag/v1.0.8
[1.0.0]: https://github.com/yal212/Pynzor/releases/tag/v1.0.0
