# Changelog

All notable changes to Pynzor are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- [#17](https://github.com/yal212/Pynzor/issues/17) — a `--config` file is now
  an overlay, deep-merged onto the bundled default, so it only has to carry the
  keys it changes. A partial file used to crash with an unhandled
  `KeyError: 'scanner'` / `KeyError: 'wordlist'` and a traceback that named
  neither the file nor the missing section. Relative `wordlist` paths are
  resolved per file before the merge, so a config copied elsewhere keeps
  pointing at the shipped wordlists unless it overrides them — the
  `FileNotFoundError` that used to follow a copied config is gone too. A file
  that is unreadable, malformed, or not a mapping is now a `--config`
  parameter error naming the file, not a traceback.
- [#18](https://github.com/yal212/Pynzor/issues/18) — the dashboard's options
  panel can express the CLI's `-x ""` opt-out. Clearing Fuzz's Extensions field
  now reaches the runner as an explicit "bare words only" rather than folding
  back to the config's eight extensions: the row reads `none` instead of `—`,
  the CLI preview shows `--extensions ''`, the option's detail pane spells out
  all three states, and the status line says what clearing it did. `d` still
  restores the config default.

## [1.2.0] - 2026-09-12

### Added
- **A lazygit-shaped dashboard.** The two-panel layout is now a column of five
  stacked side panels — Status, Modules, Options, Findings, Reports — jumped to
  with `1`-`5` or cycled with `<tab>`, beside a main panel that always renders
  whatever the focused panel's cursor is on. All five panels stay open and
  share the height, as lazygit does by default, so focus moves the border
  rather than reflowing the column; the jump numbers are drawn into the
  borders. `<enter>` or `l` pushes focus into the main panel and `<esc>` or
  `h` pops back; `<c-d>`/`<c-u>` scroll it without giving up your place in
  the list.
- **Context-sensitive keybinding bar.** The bottom row lists the keys that work
  in the focused panel, with the app and version pinned right — replacing
  Textual's single global footer. `x` opens a menu of every action available
  right now, and `?` a cheatsheet grouped by scope.
- **Command log panel.** The bottom-right panel transcribes the exact
  `Pynzor <command>` each module corresponds to as it runs, plus what the run
  did. `@` hides it.
- **Findings panel.** Every finding from the last run, flattened across
  modules, with its full detail in the main panel. `<enter>` on a results row
  jumps straight to it.
- **Popups for everything that is not navigation.** Setting the target,
  editing an option, the action menu, and quitting mid-scan are all centred
  modals, so text entry is the only place the app is ever in insert mode.
- `+`/`_` cycle the main panel between normal, half, and full screen; `/`
  filters a list panel.
- **One keymap.** `pynzor.tui.keymap` is now the single source of truth for
  every key: the app's bindings, each panel's bindings, the hint bar, the `x`
  menu, the `?` card, and the README table are all generated from it, and
  tests assert nothing is bound or documented outside it.
- **The terminal's own colours.** The dashboard draws in the sixteen ANSI
  colours and leaves the background alone, so it inherits your terminal theme
  and a translucent terminal stays translucent behind it — lazygit's palette
  mapped onto Pynzor's panels: green marks the focused border, blue the
  selected row, and an unfocused panel marks its cursor with weight alone.
  Note that `background: transparent` in Textual does not do this: it is
  alpha-0 black and paints over the terminal. Only `ansi_default` gets
  through.
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
- An equivalent-CLI-command line for the current configuration, generated from
  the same flag metadata the options form uses, shown in the Status panel's
  main view and written into the command log.
- Command-level integration tests that run every command against a local HTTP
  fixture on `127.0.0.1`, with no external network access.
- Pilot-driven tests for the dashboard and contract tests for the progress
  callbacks.
- Installed-wheel and per-platform binary smoke-test jobs in CI.
- Reproducible asciinema terminal demo (`docs/demo/pynzor-demo.cast`) plus a
  self-contained generator (`docs/demo/record_demo.py`) that records the flow
  against a local fixture.
- Generated dashboard screenshot in the README (`docs/images/dashboard.svg`)
  plus its generator (`docs/images/make_screenshot.py`), which runs the real
  dashboard against a local fixture, lets a scan finish, and exports what
  Textual rendered — replacing the hand-drawn ASCII mockup that could drift
  from the actual layout.
- `CHANGELOG.md` and `RELEASING.md`.

### Fixed
- **Every command except `--version` crashed on Windows.** The startup banner is
  drawn with block characters, and a Windows console hands the process a legacy
  code page (cp1252/cp437) that cannot encode them, so `print(BANNER)` raised
  `UnicodeEncodeError` and took the command down with it — `--version` survived
  only because it is the one path that skips the banner. Affected the standalone
  Windows binary and `pip install` alike, for as long as the banner has existed.
  stdout and stderr are now switched to UTF-8 before anything is printed, and
  the banner degrades to an ASCII rendering of itself on a console that still
  cannot take it. Note that routing it through Rich would not have helped: Rich
  raises on the same stream. Guarded by tests that print through a cp1252 stream
  and by a CI smoke run under `PYTHONIOENCODING=cp1252`, which reproduces the
  Windows failure without a Windows runner.
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

### Changed
- The dashboard's panels are now bordered and titled, and the one holding focus
  wears the accent border. The status line, CLI preview, and key hints span the
  full width instead of sitting inside the results panel, and the app pins its
  own colour theme so the palette is the same on every terminal.
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
- Added `textual>=1.0`. It is pure Python with no compiled extensions, comes
  from the authors of `rich` (already a dependency), and reuses that renderer —
  hand-rolling the dashboard on `rich.Live` would have cost far more code for a
  worse result. The floor is 1.0 rather than 0.79 because the stylesheet uses
  `text-overflow` and the app registers a `textual.theme.Theme`, neither of
  which exists in 0.79.

## 1.1.0 - 2026-06-18 (never released; first shipped in 1.2.0)

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

[Unreleased]: https://github.com/yal212/Pynzor/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/yal212/Pynzor/releases/tag/v1.2.0
[1.0.8]: https://github.com/yal212/Pynzor/releases/tag/v1.0.8
[1.0.0]: https://github.com/yal212/Pynzor/releases/tag/v1.0.0
