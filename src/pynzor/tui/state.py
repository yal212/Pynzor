"""Session state for the dashboard.

The single source of truth every widget reads. Holds the target, the resolved
per-module options, and each module's run status, progress, result, and report
envelope. Nothing here knows about Textual, so it is testable on its own.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pynzor.core.models import ModuleSpec, all_specs, config_default


class Status(str, Enum):
    """Where one module is in its lifecycle."""

    IDLE = "idle"
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    CANCELLED = "cancelled"
    FAILED = "failed"

    @property
    def glyph(self) -> str:
        """Single-character status marker for the module rail."""
        return {
            Status.IDLE: "·",
            Status.QUEUED: "…",
            Status.RUNNING: "▸",
            Status.DONE: "✔",
            Status.CANCELLED: "■",
            Status.FAILED: "✗",
        }[self]


@dataclass
class ModuleState:
    """Everything known about one module in the current session."""

    spec: ModuleSpec
    selected: bool = True
    status: Status = Status.IDLE
    done: int = 0
    total: int = 0
    note: str | None = None
    error: str | None = None
    result: Any = None
    report: dict | None = None
    options: dict[str, Any] = field(default_factory=dict)
    rows: list[Any] = field(default_factory=list)
    """Row-index -> underlying finding object, for the drill-down pane."""

    pending_rows: list[tuple[Any, tuple[str, ...]]] = field(default_factory=list)
    """Findings streamed in since the last repaint, waiting to be batched
    into the table. Progress events arrive far faster than the UI can usefully
    repaint, so they buffer here instead of touching a widget each time."""

    dirty: bool = False
    """Set when a progress event changes this module; cleared once painted."""

    @property
    def percent(self) -> float:
        """Completion as a 0-100 float; 0 when the total is not yet known."""
        if self.total <= 0:
            return 0.0
        return min(100.0, 100.0 * self.done / self.total)

    @property
    def summary(self) -> str:
        """Short right-aligned status text for the module rail."""
        if self.status is Status.FAILED:
            return "error"
        if self.status is Status.RUNNING:
            if self.note:
                return self.note
            return f"{self.done}/{self.total}" if self.total else "running"
        if self.status is Status.DONE:
            return f"{len(self.rows)} found" if self.rows else "clean"
        if self.status is Status.CANCELLED:
            return "stopped"
        return ""

    def reset(self) -> None:
        """Clear run output, keeping the user's option choices."""
        self.status = Status.IDLE
        self.done = self.total = 0
        self.note = self.error = None
        self.result = self.report = None
        self.rows = []
        self.pending_rows = []
        self.dirty = False


@dataclass
class SessionState:
    """The whole dashboard session."""

    config: dict
    target: str = ""
    modules: dict[str, ModuleState] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Build one ModuleState per spec, seeding options from config.yaml."""
        if self.modules:
            return
        for spec in all_specs():
            self.modules[spec.id] = ModuleState(
                spec=spec,
                options={o.key: config_default(o, self.config) for o in spec.options},
            )

    @property
    def selected_modules(self) -> list[ModuleState]:
        """The modules a run would execute, in display order."""
        return [m for m in self.modules.values() if m.selected]

    @property
    def total_findings(self) -> int:
        """Findings across every module that has produced a report."""
        return sum(len(m.report["findings"]) for m in self.modules.values() if m.report)

    def reset_runs(self) -> None:
        """Clear every module's run output before a new run."""
        for module in self.modules.values():
            module.reset()
