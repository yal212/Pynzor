# Pynzor TODO

## Core Features
- [ ] Implement port scanner module (`modules/scanner.py`)
- [ ] Implement directory fuzzer module (`modules/fuzzer.py`)
- [ ] Implement header checker module (`modules/headers.py`)
- [ ] Implement SQL injection probe module (`modules/sqli.py`)
- [ ] Implement XSS detector module (`modules/xss.py`)
- [ ] Implement subdomain enumerator module (`modules/subdomain.py`)

## CLI & Infrastructure
- [ ] Create CLI entry point (`main.py`)
- [ ] Implement typer command definitions (`cli/commands.py`)
- [ ] Add shared flags and argument types (`cli/options.py`)
- [ ] Implement URL/validators (`utils/validators.py`)

## Output & Reporting
- [ ] Build JSON report generation (`output/reporter.py`)
- [ ] Build HTML report with Jinja2 template (`output/template.html`)
- [ ] Implement Rich table formatters (`output/formatter.py`)

## Testing
- [ ] Write tests for scanner module (`tests/test_scanner.py`)
- [ ] Write tests for fuzzer module (`tests/test_fuzzer.py`)
- [ ] Write tests for headers module (`tests/test_headers.py`)
- [ ] Write tests for validators (`tests/test_validators.py`)
- [ ] Set up conftest.py with fixtures (`tests/conftest.py`)
- [ ] Achieve >80% test coverage

## Wordlists
- [ ] Curate `wordlists/common-dirs.txt` (~2500 entries)
- [ ] Curate `wordlists/common-params.txt` (~500 entries)
- [ ] Curate `wordlists/subdomains.txt` (~10000 entries)

## Documentation
- [x] Create README.md
- [x] Create LICENSE file
- [ ] Document all modules in Docs.md

## Configuration
- [ ] Create `config.yaml` with defaults
- [ ] Set up `pyproject.toml` with dependencies

## Polish
- [ ] Add User-Agent spoofing to HTTP client
- [ ] Implement rate limiting in HTTP client
- [ ] Add retry logic to HTTP client
- [ ] Implement --verbose flag debugging
- [ ] Add --no-color support
