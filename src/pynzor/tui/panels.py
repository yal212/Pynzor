"""The five stacked side panels.

lazygit's left column, panel for panel: a one-line Status block on top and four
list panels under it, each jumped to by number and each owning its own
contextual keys. All five stay open and share the height, as lazygit does by
default; focus moves the border, not the layout.

Every panel answers the same three questions -- what does it focus, what does
it show, and what is under the cursor -- so the app can drive all five through
one interface instead of five special cases.
"""

from typing import Any, ClassVar

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widget import Widget
from textual.widgets import Label, ListItem, ListView, Static

from pynzor.core.models import OptionSpec, config_default
from pynzor.tui.keymap import PANEL_ORDER, PANEL_TITLES, PanelId, bindings_for
from pynzor.tui.state import FindingRef, ModuleState, SessionState, Status


class FilterableRow(ListItem):
    """A list row that can say what it is, so ``/`` can match against it.

    Asking the row rather than reading its Labels back: a widget does not hand
    its source text back in a form that is stable across Textual versions, and
    the row already knows what it is showing.
    """

    @property
    def filter_text(self) -> str:
        """The text ``/`` matches against."""
        return ""


class SidePanel(Vertical):
    """One bordered panel in the left column.

    Subclasses declare their ``panel_id``, which supplies both the border title
    and the contextual keybindings -- so a panel cannot exist without being
    described in the keymap.
    """

    panel_id: ClassVar[PanelId] = ""

    def __init__(self, state: SessionState) -> None:
        super().__init__(id=f"panel-{self.panel_id}", classes="side-panel")
        self.state = state

    def panel_title(self, suffix: str = "") -> str:
        """This panel's border title: jump number, name, then any suffix.

        lazygit's showPanelJumps defaults to on, so the digit you press to get
        here is drawn into the border. Derived from ``PANEL_ORDER`` rather than
        stored: the number *is* the position, and a second copy of it would be
        one more thing able to disagree with the ``1``-``5`` bindings.

        Composed here rather than in ``PANEL_TITLES`` because that table also
        titles the cheatsheet's sections, and those are compared against the
        docs -- a number belongs in a border, not in a heading.

        A method rather than an f-string at each call site: a panel that
        re-titles itself as its context changes must not have to remember to
        put the number back, which is exactly the bug this replaces.
        """
        jump = PANEL_ORDER.index(self.panel_id) + 1
        return f"{jump} {PANEL_TITLES[self.panel_id]}{suffix}"

    def on_mount(self) -> None:
        """Title the border from the keymap's table."""
        self.border_title = self.panel_title()

    def focus_target(self) -> Widget:
        """The widget that should actually take focus when this panel is picked.

        Defaults to the panel itself, which is right for panels with no cursor;
        list panels return their ListView so ``j``/``k`` have something to move.
        """
        return self

    def refresh_panel(self) -> None:
        """Repaint from session state. Cheap enough to call on any focus change."""

    def selected(self) -> Any:
        """Whatever the cursor is on, or None. The app uses this for the main view."""
        return None


class ListPanel(SidePanel):
    """A side panel whose body is a single ListView."""

    def compose(self) -> ComposeResult:
        """One list, filling the panel."""
        yield ListView(id=f"list-{self.panel_id}")

    @property
    def list_view(self) -> ListView:
        """This panel's list."""
        return self.query_one(ListView)

    def focus_target(self) -> Widget:
        """List panels put the cursor in the list."""
        return self.list_view

    def home_cursor(self) -> None:
        """Put the cursor on the first row.

        `ListView.append` leaves `index` at None, so a freshly rebuilt list has
        no highlighted child -- which reads as "nothing selected" to every
        caller of `selected()` and makes the first `j` a no-op that only sets
        the cursor rather than moving it.
        """
        listview = self.list_view
        if listview.index is None and len(listview.children):
            listview.index = 0


# ------------------------------------------------------------------ 1: status


class StatusPanel(SidePanel):
    """Target and session summary -- lazygit's repo/branch block.

    Focusable in its own right: there is nothing here to move a cursor over,
    but it still has to be reachable with ``1`` and still owns the key that
    edits the target.
    """

    panel_id = "status"
    BINDINGS = bindings_for("status")
    can_focus = True

    def compose(self) -> ComposeResult:
        """Target on the first line so it survives the panel being collapsed."""
        yield Static("", id="status-target")
        yield Static("", id="status-summary")

    def refresh_panel(self) -> None:
        """Repaint the target line and the counts line."""
        target = self.state.target or "[$text-muted]no target — press enter[/]"
        self.query_one("#status-target", Static).update(target, layout=False)

        selected = len(self.state.selected_modules)
        findings = self.state.total_findings
        running = any(m.status is Status.RUNNING for m in self.state.modules.values())
        # "running" goes first, not last: this line ellipsises at 80 columns,
        # and the one word worth never losing is the one that says a scan is
        # still in flight.
        prefix = "[$warning]running[/] · " if running else ""
        self.query_one("#status-summary", Static).update(
            f"{prefix}{selected}/{len(self.state.modules)} modules · {findings} findings",
            layout=False,
        )


# ----------------------------------------------------------------- 2: modules


class ModuleRow(FilterableRow):
    """One module: selection marker, status glyph, label, right-aligned summary."""

    def __init__(self, module: ModuleState) -> None:
        super().__init__(id=f"row-{module.spec.id}")
        self.module = module
        # Cached on mount: refresh_row runs on every repaint, and re-querying
        # the DOM each time is pure waste.
        self._glyph: Label | None = None
        self._summary: Label | None = None
        self._painted_status: Status | None = None
        self._painted_selected: bool | None = None

    def compose(self) -> ComposeResult:
        """Lay out the marker, label, and right-aligned status summary."""
        yield Horizontal(
            Label(self._marker(), classes="rail-glyph"),
            Label(self.module.spec.label, classes="rail-label"),
            Label("", classes="rail-summary"),
            classes="rail-line",
        )

    def _marker(self) -> str:
        """Render the selection marker plus the module's status glyph.

        Filled/hollow circles rather than ``[x]``/``[ ]``: Label content is
        parsed as Rich markup, which silently eats square-bracket pairs.
        """
        box = "◉" if self.module.selected else "○"
        return f"{box} {self.module.status.glyph}"

    @property
    def filter_text(self) -> str:
        """Match on the module's name and what it does."""
        return f"{self.module.spec.label} {self.module.spec.description}"

    def on_mount(self) -> None:
        """Cache the two labels this row repaints."""
        self._glyph = self.query_one(".rail-glyph", Label)
        self._summary = self.query_one(".rail-summary", Label)

    def refresh_row(self) -> None:
        """Repaint this row from its module's current state.

        Both labels are fixed-width in the stylesheet, so `layout=False` is
        safe -- and necessary: `Static.update` otherwise forces a full-screen
        layout pass, which is what made the dashboard feel laggy.
        """
        if self._glyph is None or self._summary is None:
            return

        status, selected = self.module.status, self.module.selected
        if (status, selected) != (self._painted_status, self._painted_selected):
            self._glyph.update(self._marker(), layout=False)
            # Class changes invalidate styles, so only touch them on a real
            # status transition rather than on every progress tick.
            self.set_class(status is Status.RUNNING, "running")
            self.set_class(status is Status.DONE, "done")
            self.set_class(status is Status.FAILED, "failed")
            self._painted_status, self._painted_selected = status, selected

        self._summary.update(self.module.summary, layout=False)


class ModulesPanel(ListPanel):
    """The six recon modules, their selection state, and their live progress."""

    panel_id = "modules"
    BINDINGS = bindings_for("modules")

    def compose(self) -> ComposeResult:
        """One row per module, built once and repainted in place ever after."""
        yield ListView(
            *(ModuleRow(m) for m in self.state.modules.values()), id=f"list-{self.panel_id}"
        )

    def refresh_panel(self) -> None:
        """Repaint every row."""
        for row in self.query(ModuleRow):
            row.refresh_row()

    def selected(self) -> ModuleState | None:
        """The module under the cursor."""
        item = self.list_view.highlighted_child
        return item.module if isinstance(item, ModuleRow) else None


# ----------------------------------------------------------------- 3: options


class OptionRow(ListItem):
    """One editable option: its label and its current value."""

    def __init__(self, module: ModuleState, spec: OptionSpec) -> None:
        super().__init__(id=f"opt-{module.spec.id}-{spec.key}")
        self.module = module
        self.spec = spec

    def compose(self) -> ComposeResult:
        """Label left, value right -- the value column is fixed width."""
        yield Horizontal(
            Label(self.spec.label, classes="opt-label"),
            Label(self.value_text(), classes="opt-value"),
            classes="opt-line",
        )

    def value_text(self) -> str:
        """Render the current value the way the CLI would take it."""
        value = self.module.options.get(self.spec.key)
        if self.spec.kind == "bool":
            return "on" if value else "off"
        if value is None or value == "":
            return "—"
        if isinstance(value, (list, tuple)):
            return ",".join(str(v) for v in value)
        return str(value)

    def refresh_row(self) -> None:
        """Repaint the value cell after an edit."""
        self.query_one(".opt-value", Label).update(self.value_text(), layout=False)


class OptionsPanel(ListPanel):
    """Options for whichever module the Modules panel has under its cursor.

    Rebuilt when that cursor moves rather than kept in sync incrementally: the
    cursor only moves when a person presses a key, so the cost is irrelevant
    and the alternative is six forms to keep straight.
    """

    panel_id = "options"
    BINDINGS = bindings_for("options")

    def __init__(self, state: SessionState) -> None:
        super().__init__(state)
        self.module: ModuleState | None = None

    async def show_module(self, module: ModuleState | None) -> None:
        """Rebuild the form for one module."""
        if module is self.module:
            return
        self.module = module
        listview = self.list_view
        # `clear` is awaitable: appending before the removal settles raises
        # DuplicateIds when the same option key is listed twice.
        await listview.clear()
        self.border_title = self.panel_title(f" — {module.spec.label}" if module else "")
        if module is None:
            return
        if not module.spec.options:
            listview.append(ListItem(Label(f"{module.spec.label} has no options.")))
            return
        for spec in module.spec.options:
            listview.append(OptionRow(module, spec))
        self.home_cursor()

    def refresh_panel(self) -> None:
        """Repaint every value cell."""
        for row in self.query(OptionRow):
            row.refresh_row()

    def selected(self) -> OptionRow | None:
        """The option row under the cursor."""
        item = self.list_view.highlighted_child
        return item if isinstance(item, OptionRow) else None

    def default_for(self, row: OptionRow) -> Any:
        """The value this option would take from config.yaml (AGENTS.md 11)."""
        return config_default(row.spec, self.state.config)


# ---------------------------------------------------------------- 4: findings


class FindingRow(FilterableRow):
    """One finding in the flat cross-module list."""

    def __init__(self, ref: FindingRef, index: int) -> None:
        super().__init__(id=f"finding-{index}")
        self.ref = ref

    def compose(self) -> ComposeResult:
        """A single line; the detail lives in the main panel."""
        yield Label(self.ref.summary)

    @property
    def filter_text(self) -> str:
        """Match on every rendered cell, not just the two the summary shows."""
        return f"{self.ref.module_label} {' '.join(self.ref.row)}"


class FindingsPanel(ListPanel):
    """Every finding from the last run, across all modules.

    The old dashboard could only show one module's findings at a time, behind
    whichever tab was forward. A flat list is the thing you actually want after
    a scan: what did this target give up, in one place.
    """

    panel_id = "findings"
    BINDINGS = bindings_for("findings")

    async def rebuild(self) -> None:
        """Reflatten from session state.

        Called when a module finishes, never from the progress path: a run
        emits thousands of events and this list only has to be right by the
        time someone looks at it.
        """
        listview = self.list_view
        await listview.clear()
        refs = self.state.findings
        if not refs:
            listview.append(ListItem(Label("No findings yet — press r to run.")))
            return
        for index, ref in enumerate(refs):
            listview.append(FindingRow(ref, index))
        self.home_cursor()

    def selected(self) -> FindingRef | None:
        """The finding under the cursor."""
        item = self.list_view.highlighted_child
        return item.ref if isinstance(item, FindingRow) else None


# ----------------------------------------------------------------- 5: reports


class ReportRow(FilterableRow):
    """One saved JSON report on disk."""

    def __init__(self, path, index: int) -> None:
        super().__init__(id=f"report-{index}")
        self.path = path

    def compose(self) -> ComposeResult:
        """Just the filename; the envelope is rendered in the main panel."""
        yield Label(self.path.name)

    @property
    def filter_text(self) -> str:
        """Match on the filename, which carries the module and the timestamp."""
        return self.path.name


class ReportsPanel(ListPanel):
    """Saved report envelopes, newest first."""

    panel_id = "reports"
    BINDINGS = bindings_for("reports")

    async def rebuild(self, directory) -> None:
        """List the JSON reports in ``directory``, newest first."""
        listview = self.list_view
        await listview.clear()
        if not directory.is_dir():
            listview.append(ListItem(Label(f"No report directory at {directory}")))
            return
        files = sorted(directory.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not files:
            listview.append(ListItem(Label(f"No reports in {directory}")))
            return
        for index, path in enumerate(files[:50]):
            listview.append(ReportRow(path, index))
        self.home_cursor()

    def selected(self):
        """The report path under the cursor."""
        item = self.list_view.highlighted_child
        return item.path if isinstance(item, ReportRow) else None


#: Panel id -> class, in stacking order. The app composes straight from this.
PANEL_TYPES: tuple[type[SidePanel], ...] = (
    StatusPanel,
    ModulesPanel,
    OptionsPanel,
    FindingsPanel,
    ReportsPanel,
)
