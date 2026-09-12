"""Session state for the dashboard.

The single source of truth every widget reads. Holds the target, the resolved
per-module options, each module's run status, progress, result, and report
envelope, and the chrome state the lazygit-style layout needs: which side panel
has focus, which sub-view the main panel is showing, and the command log.
Nothing here knows about Textual, so it is testable on its own.
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

    table_rows: list[tuple[str, ...]] = field(default_factory=list)
    """The rendered cells for each entry in ``rows``, index for index.

    The Findings panel labels a cross-module row from its rendered cells, and
    re-deriving them would mean calling ``row_for`` a second time with the
    module id the flat list has deliberately forgotten."""

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
        self.table_rows = []
        self.pending_rows = []
        self.dirty = False


@dataclass(frozen=True)
class FindingRef:
    """One finding, tagged with the module it came from.

    The Findings panel is a flat cross-module list, so a row has to remember
    which module produced it to label itself and to find its detail pairs.
    """

    module_id: str
    module_label: str
    index: int
    """Position in the owning module's ``rows``, so the two stay in step."""

    item: Any
    row: tuple[str, ...]

    @property
    def summary(self) -> str:
        """How this finding reads in the flat list: module, then what names it.

        Blank and yes/no cells are dropped: a boolean says nothing about which
        finding this is, and the row is already clipped to the panel width, so
        every column spent on one costs a column of the name.
        """
        noise = {"-", "", "yes", "no"}
        cells = [cell for cell in self.row[:2] if cell not in noise]
        return f"{self.module_label}  {' '.join(cells)}".rstrip()


@dataclass
class SessionState:
    """The whole dashboard session."""

    config: dict
    target: str = ""
    modules: dict[str, ModuleState] = field(default_factory=dict)

    focused_panel: str = "modules"
    """Which side panel owns the keyboard; drives the main view and hint bar."""

    main_sub_view: str = "findings"
    """Which sub-tab the Modules main view shows: ``findings`` or ``report``."""

    main_size: int = 0
    """Main-panel size step, cycled by ``+``/``_``: 0 normal, 1 half, 2 full."""

    log_visible: bool = True
    command_log: list[str] = field(default_factory=list)
    """Commands and outcomes, newest last -- lazygit's bottom-right panel."""

    filter_text: str = ""
    """Substring filter applied to the list panels by ``/``."""

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

    @property
    def findings(self) -> list[FindingRef]:
        """Every finding from the last run, flattened in module order.

        Rebuilt on demand rather than maintained incrementally: a run emits
        thousands of progress events and this list only ever has to be right
        when someone looks at the Findings panel.
        """
        refs: list[FindingRef] = []
        for module in self.modules.values():
            for index, item in enumerate(module.rows):
                row = module.table_rows[index] if index < len(module.table_rows) else ()
                refs.append(FindingRef(module.spec.id, module.spec.label, index, item, row))
        return refs

    def log(self, line: str) -> None:
        """Append one line to the command log, keeping it bounded."""
        self.command_log.append(line)
        # A long session must not grow the log without limit; the panel only
        # ever shows the last handful of lines anyway.
        del self.command_log[:-200]

    def reset_runs(self) -> None:
        """Clear every module's run output before a new run."""
        for module in self.modules.values():
            module.reset()
