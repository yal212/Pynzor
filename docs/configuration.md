# Configuration

Pynzor ships a single canonical default config, bundled inside the package at
`src/pynzor/cli/config.yaml`. It is loaded automatically on every run — no setup
required.

To customise, copy it somewhere writable and point `--config` at your copy:

```bash
# copy the bundled default out of the installed package
python -c "import importlib.resources as r, shutil; shutil.copy(r.files('pynzor.cli') / 'config.yaml', 'pynzor.config.yaml')"
Pynzor scan -t https://target.lab --config ./pynzor.config.yaml
```

Bundled wordlists (`src/pynzor/cli/wordlists/`) and the HTML report template are
resolved relative to the config file, so both editable installs and standalone
binaries find them without any extra configuration.

## What is configurable

- HTTP timeout, retries, user-agent, redirect behavior, and SSL verification.
- Per-module request rate limits (`fuzzer`, `sqli`, `xss`, `subdomain`).
- Scanner ports, timeouts, service detection, and concurrency.
- Fuzzer status codes, request match/filter rules, extensions, recursion depth,
  and wordlists.
- Subdomain wordlist and concurrency.
- Output format and report directory.

## Going faster in a lab

Every module's request rate is configurable. The shipped defaults are
deliberately polite; against a local target you can drop them.

Copy the bundled default as shown above — a config file must currently be
complete, since some commands read their section directly
([#17](https://github.com/yal212/Pynzor/issues/17)) — then change the rate
limits:

```yaml
fuzzer:
  rate_limit: 0        # default 0.1s between requests
  threads: 50
sqli:
  rate_limit: 0        # default 0.2
xss:
  rate_limit: 0        # default 0.2
```

```bash
Pynzor fuzz -t http://127.0.0.1:8888 -c my-lab.yaml
Pynzor tui -c my-lab.yaml
```

Only turn this down on targets you own. The defaults exist so Pynzor does not
trip rate limiting or WAFs on shared CTF infrastructure.
