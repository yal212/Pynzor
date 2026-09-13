"""The main panel: whatever the focused side panel is pointing at.

lazygit's right-hand pane never has its own idea of what to show -- it follows
the side panel's cursor, and pressing ``enter`` pushes focus into it for a
secondary context. This is that, for six recon modules.

Every sub-view is mounted once and toggled with ``display`` rather than rebuilt
on each switch. The module panes in particular have to survive being switched
away from: their tables are still being filled by a running worker, and
rebuilding one per cursor move would put table construction back on the hot
path the 15 fps flush exists to keep it off.
"""

import json
from pathlib import Path
from typing import Any

from textual.app import ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.widget import Widget
from textual.widgets import DataTable, Static

from pynzor.tui.preview import preview
from pynzor.tui.rows import detail_lines, headline, rows_from_result
from pynzor.tui.state import FindingRef, ModuleState, SessionState

#: Sub-tabs of the Modules main view, in ``[``/``]`` order.
SUB_VIEWS: tuple[str, ...] = ("findings", "report")

#: Shown when the module under the Modules cursor takes no options.
NO_OPTIONS = "No options for this module."


class TextView(VerticalScroll):
    """A scrollable block of text -- the main panel's read-only shape."""

    def __init__(self, view_id: str) -> None:
        super().__init__(id=view_id, classes="main-view")
        self._body = Static("", classes="main-body")
        # Static does not hand its source text back in a form that is stable
        # across Textual versions, so keep the copy we set.
        self._text = ""

    def compose(self) -> ComposeResult:
        """One Static, scrolled by its container."""
        yield self._body

    def set_text(self, text: str) -> None:
        """Replace the body and return to the top.

        Scrolling home on every switch is deliberate: this view is reused by
        several contexts, and inheriting the previous one's scroll offset makes
        a short body look blank.
        """
        self._text = text
        self._body.update(text)
        self.scroll_home(animate=False)

    @property
    def text(self) -> str:
        """The text last set, for tests and for the clipboard."""
        return self._text


class ModulePane(Vertical):
    """One module's results: a progress line, a verdict, and a findings table."""

    def __init__(self, module: ModuleState) -> None:
        super().__init__(id=f"pane-{module.spec.id}", classes="main-view")
        self.module = module
        # Static drops its source text, so keep the rendered line addressable.
        self.progress_text = ""

    def compose(self) -> ComposeResult:
        """Build the progress bar line, headline, and findings table."""
        yield Static("", classes="pane-progress", id=f"prog-{self.module.spec.id}")
        yield Static("", classes="pane-headline", id=f"head-{self.module.spec.id}")
        table: DataTable = DataTable(id=f"table-{self.module.spec.id}", cursor_type="row")
        table.add_columns(*self.module.spec.columns)
        yield table

    @property
    def table(self) -> DataTable:
        """The findings table for this module."""
        return self.query_one(DataTable)

    def refresh_progress(self) -> None:
        """Repaint the progress line from the module's counters."""
        module = self.module
        width = 28
        filled = int(width * module.percent / 100)
        head = "╸" if filled < width else ""
        track = "─" * max(0, width - filled - len(head))
        counts = f"{module.done}/{module.total}" if module.total else ""
        note = f"  {module.note}" if module.note else ""
        # Markup, not extra widgets: the rendered width is unchanged, so this
        # still repaints with `layout=False` and costs the budget nothing.
        # The track is $text-muted, not $panel-lighten-2: under the ansi theme
        # that token resolves to alpha-0 black, which as a *foreground* would
        # leave the unfilled half of the bar invisible.
        bar = f"[$success]{'━' * filled}{head}[/][$text-muted]{track}[/]"
        self.progress_text = f"{bar} {module.percent:5.1f}%  {counts}{note}"
        self.query_one(".pane-progress", Static).update(self.progress_text, layout=False)

    def refresh_headline(self) -> None:
        """Repaint the one-line verdict, or the error if the module failed."""
        module = self.module
        text = module.error if module.error else headline(module.spec.id, module.result)
        self.query_one(".pane-headline", Static).update(text or "", layout=False)

    def add_row(self, item: Any, row: tuple[str, ...]) -> None:
        """Append one finding, remembering the object behind it for drill-down."""
        self.module.rows.append(item)
        self.module.table_rows.append(row)
        self.table.add_row(*row)

    def rebuild(self) -> None:
        """Rebuild the table from the finished result, so it matches the report."""
        self.table.clear()
        self.module.rows = []
        self.module.table_rows = []
        # Drop anything still buffered: the result is authoritative, and
        # flushing those afterwards would append them a second time.
        self.module.pending_rows = []
        for item, row in rows_from_result(self.module.spec.id, self.module.result):
            self.add_row(item, row)


class MainPanel(Vertical):
    """The right-hand panel. Shows exactly one sub-view at a time."""

    def __init__(self, modules: dict[str, ModuleState]) -> None:
        super().__init__(id="main")
        self.modules = modules
        self._current: Widget | None = None

    def compose(self) -> ComposeResult:
        """Mount every sub-view once; `show` picks which one is displayed."""
        yield TextView("view-overview")
        for module in self.modules.values():
            yield ModulePane(module)
        yield TextView("view-modreport")
        yield TextView("view-option")
        yield TextView("view-detail")
        yield TextView("view-report")

    def on_mount(self) -> None:
        """Start with everything hidden; the app shows one on first focus."""
        for view in self.query(".main-view"):
            view.display = False

    # ------------------------------------------------------------------ views

    def pane(self, module_id: str) -> ModulePane:
        """The results pane for one module."""
        return self.query_one(f"#pane-{module_id}", ModulePane)

    def view(self, view_id: str) -> TextView:
        """One of the text sub-views."""
        return self.query_one(f"#{view_id}", TextView)

    def show(self, widget: Widget, title: str) -> None:
        """Display exactly one sub-view and title the border.

        `border_title` costs a layout pass, so this is only ever reached from a
        focus or cursor change -- never from the progress flush.
        """
        if self._current is widget:
            self.border_title = title
            return
        if self._current is not None:
            self._current.display = False
        widget.display = True
        self._current = widget
        self.border_title = title

    def show_module(self, module: ModuleState, sub_view: str) -> None:
        """Show one module's results, on whichever sub-tab is active.

        The tab strip is drawn into the border title the way lazygit draws
        ``Files``/``Worktrees`` -- it costs no rows, and the panel already has
        a border to hang it on.
        """
        title = self._tab_strip(module.spec.label, sub_view)
        if sub_view == "report":
            view = self.view("view-modreport")
            view.set_text(_render_envelope(module))
            self.show(view, title)
            return
        self.show(self.pane(module.spec.id), title)

    @staticmethod
    def _tab_strip(label: str, active: str) -> str:
        """``Findings`` / ``Report`` with the active tab lit."""
        cells = [
            f"[b]{name.capitalize()}[/b]"
            if name == active
            else f"[$text-muted]{name.capitalize()}[/]"
            for name in SUB_VIEWS
        ]
        return f"{label} — " + " [$text-muted]│[/] ".join(cells)

    def scrollable(self) -> Widget | None:
        """Whatever ``ctrl+d``/``ctrl+u`` should scroll right now.

        A module pane scrolls through its table rather than itself, which is
        the part with more rows than fit.
        """
        if isinstance(self._current, ModulePane):
            return self._current.table
        return self._current


def _render_envelope(module: ModuleState) -> str:
    """Pretty-print the report envelope ``e`` would write for one module.

    Shown rather than summarised: the point of this tab is to see the exact
    JSON before exporting it, so anything reformatted here would be a lie.
    """
    if module.report is None:
        return f"{module.spec.label} has not produced a report yet — press r to run."
    return json.dumps(module.report, indent=2, ensure_ascii=False, default=str)


# ------------------------------------------------------- sub-view text bodies

# Plain functions over session state rather than app methods: what the main
# panel says about a selection is worth reading, and testing, without a
# running app to hang it off.


def render_overview(state: SessionState, output_dir: Path) -> str:
    """The session at a glance, plus the command that reproduces it."""
    selected = state.selected_modules
    lines = [
        f"target    : {state.target or '(none set — press enter)'}",
        f"modules   : {len(selected)} of {len(state.modules)} selected",
        f"findings  : {state.total_findings}",
        f"reports   : {output_dir}",
        "",
        "[b]Equivalent command[/b]",
        f"[$success]$ {preview(state)}[/]",
        "",
        "[b]Selected[/b]",
    ]
    lines += [f"  {m.spec.label:<10} {m.spec.description}" for m in selected] or ["  (none)"]
    return "\n".join(lines)


def render_option(row: Any, default: Any) -> str:
    """What the option under the cursor does, and where its default lives."""
    spec = row.spec
    config_path = ".".join(spec.config_path) if spec.config_path else "(no config default)"
    lines = [
        f"[b]{spec.label}[/b]",
        "",
        f"flag      : {spec.flag}",
        f"kind      : {spec.kind}",
        f"value     : {row.value_text()}",
        f"default   : {default}",
        f"config    : {config_path}",
    ]
    if spec.empty_opts_out:
        # Three states, and only two of them are obvious from a text box.
        lines.append(f"empty     : clearing the field sends {spec.flag} '' -- <d> puts the")
        lines.append("            config default back")
    lines.extend(["", spec.help or ""])
    return "\n".join(lines)


def render_finding(ref: FindingRef | None) -> str:
    """The highlighted finding, expanded field by field."""
    if ref is None:
        return "No finding selected."
    pairs = detail_lines(ref.item)
    if not pairs:
        return "No detail."
    width = max(len(label) for label, _ in pairs)
    body = "\n".join(f"{label.rjust(width)} : {value}" for label, value in pairs)
    return f"[b]{ref.module_label} finding[/b]\n\n{body}"
