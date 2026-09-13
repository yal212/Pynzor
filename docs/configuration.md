# Configuration

Pynzor ships a single canonical default config, bundled inside the package at
`src/pynzor/cli/config.yaml`. It is loaded automatically on every run — no setup
required.

To customise, write a file holding only the keys you want to change and point
`--config` at it:

```bash
cat > my-lab.yaml <<'YAML'
fuzzer:
  rate_limit: 0
YAML
Pynzor scan -t https://target.lab --config ./my-lab.yaml
```

A `--config` file is an **overlay**: it is deep-merged onto the bundled default,
so anything it leaves out keeps its shipped value. Sections merge key by key;
lists and scalars replace outright, so `scanner: {common_ports: [80]}` means
exactly that one port rather than adding to the shipped twenty. The one thing an
overlay cannot do is *remove* a key.

If you would rather start from the whole file and edit it down, copy the bundled
default out of the installed package:

```bash
python -c "import importlib.resources as r, shutil; shutil.copy(r.files('pynzor.cli') / 'config.yaml', 'pynzor.config.yaml')"
```

Bundled wordlists (`src/pynzor/cli/wordlists/`) and the HTML report template are
resolved relative to the config file that names them. Paths you do not override
keep pointing at the shipped wordlists wherever your own file lives; a relative
`wordlist` you *do* set resolves beside your file. Both editable installs and
standalone binaries find them without any extra configuration.

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

An overlay with just the rate limits in it is enough:

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
