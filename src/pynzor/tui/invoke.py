"""Turn one module's panel options into the runner call they describe.

The options panel holds every value as text, because that is what a text field
produces. The runners declare real types. This is the single place that
translates between the two, kept out of the app so the coercion rules are
testable without a running UI.
"""

from typing import Any

from pynzor.core import runner
from pynzor.core.events import ProgressCallback
from pynzor.core.parsing import parse_int_list
from pynzor.tui.state import ModuleState


async def invoke(
    module: ModuleState, target: str, config: dict, on_progress: ProgressCallback
) -> tuple[Any, dict]:
    """Call the runner for one module with its resolved options.

    Every module takes the same three arguments; the three with tunable
    options need those unpacked from the panel's string values into the
    types the runner signatures declare, which is all this does.

    Returns:
        The ``(result, report envelope)`` pair the CLI gets from the same call.
    """
    spec = module.spec
    opts = module.options

    if spec.id == "ports":
        return await runner.run_ports(
            target,
            config,
            ports=parse_int_list(_as_text(opts.get("ports")), "--ports"),
            service_detection=bool(opts.get("service_detection")),
            threads=_as_int(opts.get("threads")),
            on_progress=on_progress,
        )
    if spec.id == "fuzz":
        resolved = runner.resolve_fuzz_options(
            target,
            config,
            wordlist=_as_text(opts.get("wordlist")),
            threads=_as_int(opts.get("threads")) or 20,
            no_baseline=bool(opts.get("no_baseline")),
            extensions=_as_text(opts.get("extensions")),
            recursive=bool(opts.get("recursive")),
            depth=_as_int(opts.get("depth")),
            method=_as_text(opts.get("method")) or "GET",
            data=_as_text(opts.get("data")),
            match_codes=_as_text(opts.get("match_codes")),
            filter_codes=_as_text(opts.get("filter_codes")),
            filter_size=_as_int(opts.get("filter_size")),
            filter_words=_as_int(opts.get("filter_words")),
            filter_lines=_as_int(opts.get("filter_lines")),
        )
        return await runner.run_fuzz(resolved, on_progress=on_progress)
    if spec.id == "subdomain":
        return await runner.run_subdomain(
            target,
            config,
            threads=_as_int(opts.get("threads")),
            include_wildcard=bool(opts.get("include_wildcard")),
            on_progress=on_progress,
        )
    return await spec.runner(target, config, on_progress=on_progress)


def _as_text(value: Any) -> str | None:
    """Coerce an option value to the comma-separated text the parsers expect."""
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        return ",".join(str(v) for v in value) or None
    text = str(value).strip()
    return text or None


def _as_int(value: Any) -> int | None:
    """Coerce an option value to an int, or None when blank or malformed."""
    text = _as_text(value)
    if text is None:
        return None
    try:
        return int(text)
    except ValueError:
        return None
