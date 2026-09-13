"""Render the equivalent CLI command for the dashboard's current state.

Built from the same ``ModuleSpec`` flag metadata the options form uses, so the
preview cannot drift from the flags ``Pynzor <command>`` actually accepts.
"""

import shlex
from typing import Any

from pynzor.core.models import config_default
from pynzor.tui.state import ModuleState, SessionState


def _flag_args(module: ModuleState, config: dict) -> list[str]:
    """Render only the options that differ from their config.yaml default."""
    args: list[str] = []
    for spec in module.spec.options:
        value = module.options.get(spec.key)
        if value is None or value == config_default(spec, config):
            continue
        if spec.kind == "bool":
            if value:
                args.append(spec.flag)
            continue
        if value == "" or value == [] or value == ():
            # Blank normally means "unset", which is no flag at all -- unless
            # blank is the choice, in which case the empty flag is the point.
            if not spec.empty_opts_out:
                continue
            args.extend([spec.flag, ""])
            continue
        args.extend([spec.flag, _render(value)])
    return args


def _render(value: Any) -> str:
    """Render an option value the way the CLI parses it back."""
    if isinstance(value, (list, tuple)):
        return ",".join(str(v) for v in value)
    return str(value)


def command_for(module: ModuleState, state: SessionState) -> str:
    """Build the CLI command for one module, ready to paste into a writeup."""
    target = state.target or "<target>"
    args = ["Pynzor", module.spec.id, "-t", target, *_flag_args(module, state.config)]
    # An empty argument has to be quoted or it vanishes from the line, which
    # would turn `--extensions ''` into a bare `--extensions`.
    return " ".join(shlex.quote(a) if not a or " " in a else a for a in args)


def preview(state: SessionState) -> str:
    """Build the preview line for the whole session.

    Every module selected with default options collapses to a single
    ``Pynzor scan``; otherwise each selected module gets its own command,
    joined by ``&&`` the way you would actually run them.
    """
    selected = state.selected_modules
    if not selected:
        return "Pynzor --help"

    if len(selected) == len(state.modules) and not any(
        _flag_args(m, state.config) for m in selected
    ):
        target = state.target or "<target>"
        return f"Pynzor scan -t {target} -f both"

    return " && ".join(command_for(m, state) for m in selected)
