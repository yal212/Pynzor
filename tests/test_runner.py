"""Service-layer tests.

The runners are the contract between the CLI and the TUI: the same option
resolution and the same report envelope, whoever calls them.
"""

import pytest

from pynzor.core import runner
from pynzor.core.config import load_config
from pynzor.core.models import all_specs, config_default, spec_for
from pynzor.core.parsing import parse_headers, parse_int_list, parse_str_list


@pytest.fixture
def real_config():
    """The bundled config, as every frontend loads it."""
    return load_config()


# ------------------------------------------------------------------- parsing


def test_parse_int_list_rejects_non_integers():
    """A malformed code list raises a plain ValueError, not a Typer error."""
    assert parse_int_list("200,301, 404") == [200, 301, 404]
    assert parse_int_list("") is None
    assert parse_int_list(None) is None
    with pytest.raises(ValueError, match="comma-separated integers"):
        parse_int_list("200,abc", "--match-codes")


def test_parse_str_list_trims_and_drops_blanks():
    """Whitespace and empty entries never reach the modules."""
    assert parse_str_list(" php , html ,, ") == ["php", "html"]
    assert parse_str_list("") is None


def test_parse_headers_requires_a_colon():
    """A header without a colon is rejected with the offending value."""
    assert parse_headers(["X-A: 1", "X-B:2"]) == {"X-A": "1", "X-B": "2"}
    with pytest.raises(ValueError, match="Name: value"):
        parse_headers(["broken"])


# ---------------------------------------------------- fuzz option resolution


def test_fuzz_directory_mode_applies_config_defaults(real_config):
    """Directory mode picks up the config wordlist, extensions, and depth."""
    opts = runner.resolve_fuzz_options("example.com", real_config)

    assert opts.request_mode is False
    assert opts.target == "https://example.com"
    assert opts.wordlist_path == real_config["fuzzer"]["wordlist"]
    assert opts.extensions == real_config["fuzzer"]["extensions"]
    assert opts.ignored_flags == []


def test_fuzz_request_mode_detected_from_keyword(real_config):
    """A FUZZ keyword switches modes and leaves the target untouched."""
    opts = runner.resolve_fuzz_options("https://example.com/FUZZ", real_config)

    assert opts.request_mode is True
    assert opts.target == "https://example.com/FUZZ"
    # Directory-only defaults must not leak into request mode.
    assert opts.extensions is None


def test_fuzz_flags_wrong_for_the_mode_are_collected(real_config):
    """Mode-inappropriate flags are reported, not silently applied."""
    directory = runner.resolve_fuzz_options("example.com", real_config, filter_size=100)
    assert directory.ignored_flags == ["--filter-size"]
    assert directory.filter_size == 100  # collected, but the module ignores it

    request = runner.resolve_fuzz_options(
        "https://example.com/FUZZ", real_config, recursive=True, depth=3
    )
    assert request.ignored_flags == ["--recursive", "--depth"]


def test_fuzz_empty_extensions_is_an_explicit_opt_out(real_config):
    """`-x ""` means bare words only, distinct from omitting the flag."""
    assert runner.resolve_fuzz_options("example.com", real_config, extensions="").extensions is None


def test_fuzz_resolves_against_a_partial_config(tmp_path):
    """A --config holding one key still supplies fuzzer.wordlist (#17).

    ``resolve_fuzz_options`` indexes ``fuzzer_cfg["wordlist"]`` directly; it
    used to raise KeyError: 'wordlist' for any config that omitted it.
    """
    partial = tmp_path / "partial.yaml"
    partial.write_text("sqli:\n  rate_limit: 0.5\n")
    opts = runner.resolve_fuzz_options("example.com", load_config(partial))

    assert opts.wordlist_path == load_config()["fuzzer"]["wordlist"]
    assert opts.threads == 20


def test_fuzz_bad_code_list_raises_value_error(real_config):
    """Malformed codes surface as ValueError for the frontend to present."""
    with pytest.raises(ValueError):
        runner.resolve_fuzz_options("https://x/FUZZ", real_config, match_codes="200,nope")


# ------------------------------------------------------------------- runners


async def test_run_headers_builds_the_shared_envelope(http_fixture, real_config):
    """The envelope a runner returns is what both frontends save."""
    result, report = await runner.run_headers(http_fixture, real_config)

    assert report["schema_version"] == 1
    assert report["module"] == "headers"
    assert report["target"] == http_fixture
    assert report["metadata"] == {"score": result.score, "grade": result.grade}
    # Only missing headers are findings.
    assert len(report["findings"]) == len([a for a in result.analysis if not a.present])


async def test_run_ports_excludes_closed_ports(real_config):
    """Closed ports stay out of the report, matching the CLI's table."""
    result, report = await runner.run_ports("127.0.0.1", real_config, ports=[80, 443])

    assert report["module"] == "ports"
    assert report["target"] == "127.0.0.1"
    assert all(f["status"] != "closed" for f in report["findings"])
    assert report["metadata"]["open_count"] == len([p for p in result.ports if p.status == "open"])


async def test_run_sqli_marks_severity_high(http_fixture, real_config):
    """A confirmed finding drives the envelope's severity, not just its body."""
    result, report = await runner.run_sqli(f"{http_fixture}/sqli?id=1", real_config)

    assert result.vulnerable is True
    assert report["severity"] == "high"
    assert len(report["findings"]) == len(result.vulnerabilities)


async def test_run_full_scan_reports_each_module_in_order(http_fixture, real_config, tmp_path):
    """The full scan drives its frontend through start/done callbacks, in order."""
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("admin\n")
    config = dict(real_config)
    config["fuzzer"] = {**real_config["fuzzer"], "wordlist": str(wordlist), "threads": 5}
    config["subdomain"] = {**real_config["subdomain"], "wordlist": str(wordlist), "threads": 5}
    config["scanner"] = {**real_config["scanner"], "common_ports": [80]}

    started: list[str] = []
    finished: list[str] = []

    results, report = await runner.run_full_scan(
        http_fixture,
        config,
        on_module_start=started.append,
        on_module_done=lambda name, _result: finished.append(name),
    )

    assert started == list(runner.SCAN_SEQUENCE)
    assert finished == list(runner.SCAN_SEQUENCE)
    assert set(results) == set(runner.SCAN_SEQUENCE)
    assert report["module"] == "scan"
    assert set(report["metadata"]["modules"]) == {
        "scanner",
        "fuzzer",
        "headers",
        "sqli",
        "xss",
        "subdomain",
    }


# --------------------------------------------------------------- module table


def test_every_spec_resolves_its_runner():
    """The table's runner names must all exist in core.runner."""
    for spec in all_specs():
        assert callable(spec.runner)
        assert spec.runner.__name__ == spec.runner_name


def test_option_defaults_come_from_config(real_config):
    """Options seed from config.yaml, per AGENTS.md 11 -- not hardcoded literals."""
    threads = next(o for o in spec_for("subdomain").options if o.key == "threads")
    assert config_default(threads, real_config) == real_config["subdomain"]["threads"]

    # A key absent from the config falls back to the spec's literal.
    assert config_default(threads, {}) == threads.default


def test_specs_are_unique_and_complete():
    """Six modules, distinct ids, each with table columns to render."""
    specs = all_specs()
    assert len(specs) == 6
    assert len({s.id for s in specs}) == 6
    assert all(s.columns for s in specs)


# ------------------------------------------------------- per-module HTTP config


def test_client_config_defaults_match_the_old_hardcoded_values(real_config):
    """Wiring rate limits to config must not change any shipped default.

    Before this was configurable each module constructed its own
    ``ClientConfig(rate_limit=...)``; those values are the baseline.
    """
    expected = {"fuzz": 0.1, "sqli": 0.2, "xss": 0.2, "subdomain": 0.1}
    for module_id, rate_limit in expected.items():
        assert runner.client_config_for(real_config, module_id).rate_limit == rate_limit


def test_module_section_overrides_the_http_section(real_config):
    """A module's own rate_limit wins over the global http one."""
    config = {**real_config, "sqli": {**real_config["sqli"], "rate_limit": 0.9}}
    assert runner.client_config_for(config, "sqli").rate_limit == 0.9
    # Its neighbours are unaffected.
    assert runner.client_config_for(config, "xss").rate_limit == 0.2


def test_http_section_is_the_fallback():
    """With no module override, the http section supplies the value."""
    config = {"http": {"rate_limit": 0.5, "timeout": 7}}
    # "headers" has no per-module fallback of its own.
    resolved = runner.client_config_for(config, "headers")
    assert resolved.rate_limit == 0.5
    assert resolved.timeout == 7


def test_fuzz_section_is_named_fuzzer_in_config(real_config):
    """The module id is `fuzz` but its config section is `fuzzer`."""
    config = {**real_config, "fuzzer": {**real_config["fuzzer"], "rate_limit": 0.7}}
    assert runner.client_config_for(config, "fuzz").rate_limit == 0.7


def test_an_empty_config_still_resolves(real_config):
    """A config missing every optional section must not raise."""
    assert runner.client_config_for({}, "fuzz").rate_limit == 0.1


async def test_rate_limit_from_config_reaches_the_module(http_fixture, real_config, tmp_path):
    """The resolved config actually governs the request rate, end to end."""
    import time

    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("\n".join(f"w{i}" for i in range(12)))

    async def timed(rate_limit: float) -> float:
        config = {
            **real_config,
            "fuzzer": {
                **real_config["fuzzer"],
                "wordlist": str(wordlist),
                "extensions": [],
                "rate_limit": rate_limit,
                "threads": 1,
            },
        }
        opts = runner.resolve_fuzz_options(http_fixture, config, threads=1)
        start = time.perf_counter()
        result, _ = await runner.run_fuzz(opts)
        assert result.scanned == 12
        return time.perf_counter() - start

    fast = await timed(0.0)
    slow = await timed(0.05)
    # 12 serialized requests at 50ms is ~0.6s of enforced delay; the unthrottled
    # run against a local fixture is far quicker.
    assert slow > fast + 0.2, f"rate_limit ignored: {fast:.3f}s vs {slow:.3f}s"
