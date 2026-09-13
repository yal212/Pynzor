"""The single table describing every recon module and its options.

The TUI's module rail, its per-module options form, and its CLI-command
preview are all generated from this one table, so a seventh module only ever
has to be described in one place -- and the preview can never drift from the
real flags.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Literal

FieldKind = Literal["text", "int", "bool", "path"]


@dataclass(frozen=True)
class OptionSpec:
    """One editable option: how to render it, and which CLI flag it maps to."""

    key: str
    """Keyword argument name passed to the module's runner."""

    flag: str
    """The CLI flag this option corresponds to, e.g. ``--threads``."""

    label: str
    kind: FieldKind = "text"
    help: str = ""
    config_path: tuple[str, ...] | None = None
    """Dotted path into config.yaml supplying the default (AGENTS.md 11)."""

    default: Any = None
    """Fallback used only when ``config_path`` is absent or missing."""

    empty_opts_out: bool = False
    """True when clearing the field means 'pass the flag empty' -- an explicit
    opt-out -- rather than 'fall back to the config default'.

    Only set on options whose CLI flag distinguishes the two, as ``-x ""``
    (bare words only) differs from ``-x`` omitted (the config's extensions)."""


@dataclass(frozen=True)
class ModuleSpec:
    """Everything a frontend needs to present and run one module."""

    id: str
    label: str
    description: str
    runner_name: str
    """Name of the coroutine in ``pynzor.core.runner`` that runs this module."""

    columns: tuple[str, ...]
    """Result-table column headers, in order."""

    options: tuple[OptionSpec, ...] = field(default_factory=tuple)
    needs_host: bool = False
    """True when the module takes a bare host rather than a full URL."""

    @property
    def runner(self) -> Callable[..., Any]:
        """Resolve this module's runner coroutine.

        Looked up by name at call time rather than captured at import: it keeps
        this table free of an import cycle with ``core.runner``, and it means a
        test can substitute a runner without rebuilding the table.
        """
        from pynzor.core import runner

        return getattr(runner, self.runner_name)


def _specs() -> tuple[ModuleSpec, ...]:
    """Build the module table."""
    return (
        ModuleSpec(
            id="ports",
            label="Ports",
            description="Scan TCP ports with optional service/version detection",
            runner_name="run_ports",
            columns=("Port", "Status", "Service", "Version"),
            needs_host=True,
            options=(
                OptionSpec(
                    "ports",
                    "--ports",
                    "Ports",
                    "text",
                    "e.g. 22,80,443,8000-9000",
                    ("scanner", "common_ports"),
                ),
                OptionSpec(
                    "threads",
                    "--threads",
                    "Concurrency",
                    "int",
                    "Simultaneous port probes",
                    ("scanner", "concurrent"),
                    50,
                ),
                OptionSpec(
                    "service_detection",
                    "-sV",
                    "Service detection",
                    "bool",
                    "Grab and parse banners on open ports",
                    ("scanner", "service_detection"),
                    False,
                ),
            ),
        ),
        ModuleSpec(
            id="fuzz",
            label="Fuzz",
            description="Directory fuzzing, or FUZZ-keyword request fuzzing",
            runner_name="run_fuzz",
            columns=("Status", "URL", "Length", "Redirect"),
            options=(
                OptionSpec(
                    "wordlist",
                    "--wordlist",
                    "Wordlist",
                    "path",
                    "Path to the wordlist file",
                    ("fuzzer", "wordlist"),
                ),
                OptionSpec(
                    "threads",
                    "--threads",
                    "Threads",
                    "int",
                    "Concurrent requests",
                    ("fuzzer", "threads"),
                    20,
                ),
                OptionSpec(
                    "extensions",
                    "--extensions",
                    "Extensions",
                    "text",
                    "Comma-separated, e.g. php,html; blank means none (bare words only)",
                    ("fuzzer", "extensions"),
                    empty_opts_out=True,
                ),
                OptionSpec(
                    "recursive", "--recursive", "Recursive", "bool", "Recurse into found dirs"
                ),
                OptionSpec(
                    "depth",
                    "--depth",
                    "Depth",
                    "int",
                    "Recursion depth",
                    ("fuzzer", "recursion_depth"),
                    1,
                ),
                OptionSpec(
                    "no_baseline", "--no-baseline", "Disable baseline", "bool", "Skip SPA baseline"
                ),
                OptionSpec("method", "--method", "Method", "text", "HTTP method", None, "GET"),
                OptionSpec("data", "--data", "Body", "text", "Request body (enables FUZZ mode)"),
                OptionSpec(
                    "match_codes",
                    "--match-codes",
                    "Match codes",
                    "text",
                    "Request mode only",
                    ("fuzzer", "match_codes"),
                ),
                OptionSpec(
                    "filter_codes", "--filter-codes", "Filter codes", "text", "Request mode only"
                ),
                OptionSpec(
                    "filter_size", "--filter-size", "Filter size", "int", "Request mode only"
                ),
                OptionSpec(
                    "filter_words", "--filter-words", "Filter words", "int", "Request mode only"
                ),
                OptionSpec(
                    "filter_lines", "--filter-lines", "Filter lines", "int", "Request mode only"
                ),
            ),
        ),
        ModuleSpec(
            id="headers",
            label="Headers",
            description="Score common security headers",
            runner_name="run_headers",
            columns=("Header", "Present", "Risk", "Recommendation"),
        ),
        ModuleSpec(
            id="sqli",
            label="SQLi",
            description="Probe URL parameters for SQL injection indicators",
            runner_name="run_sqli",
            columns=("Type", "Payload", "URL", "Evidence"),
        ),
        ModuleSpec(
            id="xss",
            label="XSS",
            description="Probe for reflected XSS indicators",
            runner_name="run_xss",
            columns=("Type", "Payload", "URL", "Evidence"),
        ),
        ModuleSpec(
            id="subdomain",
            label="Subdomains",
            description="Enumerate subdomains from a wordlist",
            runner_name="run_subdomain",
            columns=("Subdomain", "Type", "Value", "Verified"),
            needs_host=True,
            options=(
                OptionSpec(
                    "threads",
                    "--threads",
                    "Threads",
                    "int",
                    "Concurrent resolutions",
                    ("subdomain", "threads"),
                    20,
                ),
                OptionSpec(
                    "include_wildcard",
                    "--include-wildcard",
                    "Include wildcard",
                    "bool",
                    "Keep results matching a wildcard DNS record",
                ),
            ),
        ),
    )


_CACHE: tuple[ModuleSpec, ...] | None = None


def all_specs() -> tuple[ModuleSpec, ...]:
    """Return every module spec, in display order."""
    global _CACHE
    if _CACHE is None:
        _CACHE = _specs()
    return _CACHE


def spec_for(module_id: str) -> ModuleSpec:
    """Look up one module spec by id.

    Raises:
        KeyError: If no module has that id.
    """
    for spec in all_specs():
        if spec.id == module_id:
            return spec
    raise KeyError(module_id)


def config_default(spec: OptionSpec, config: dict) -> Any:
    """Resolve an option's default from config.yaml, falling back to its literal.

    Per AGENTS.md 11 the config file is authoritative; ``OptionSpec.default``
    is only the last resort when the key is absent.
    """
    if spec.config_path:
        node: Any = config
        for key in spec.config_path:
            if not isinstance(node, dict) or key not in node:
                return spec.default
            node = node[key]
        return node
    return spec.default
