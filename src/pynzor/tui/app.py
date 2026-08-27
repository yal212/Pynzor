"""The Pynzor dashboard.

Runs each selected module in its own Textual worker awaiting the same
``pynzor.core.runner`` coroutine the CLI calls. Progress callbacks fire inside
those workers and do nothing but post a message, so widget mutation always
happens on the UI thread.
"""

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Any

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.message import Message
from textual.reactive import reactive
from textual.widgets import (
    Checkbox,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    Static,
    TabbedContent,
    TabPane,
)

from pynzor.core import runner
from pynzor.core.events import ProgressEvent
from pynzor.core.parsing import parse_int_list
from pynzor.output.reporter import Reporter
from pynzor.tui.preview import preview
from pynzor.tui.rows import detail_lines, headline, row_for, rows_from_result
from pynzor.tui.state import ModuleState, SessionState, Status

STYLES = Path(__file__).parent / "styles.tcss"


class ProgressUpdate(Message):
    """A progress event marshalled from a worker onto the UI thread."""

    def __init__(self, event: ProgressEvent) -> None:
        self.event = event
        super().__init__()


class ModuleRow(ListItem):
    """One module in the left rail: selection marker, glyph, label, summary."""

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


class ModulePane(Vertical):
    """One module's results: a progress line, a verdict, and a findings table."""

    def __init__(self, module: ModuleState) -> None:
        super().__init__(id=f"pane-{module.spec.id}")
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
        bar = "━" * filled + "╸" * (1 if filled < width else 0)
        bar += "─" * max(0, width - filled - 1)
        counts = f"{module.done}/{module.total}" if module.total else ""
        note = f"  {module.note}" if module.note else ""
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
        self.table.add_row(*row)

    def rebuild(self) -> None:
        """Rebuild the table from the finished result, so it matches the report."""
        self.table.clear()
        self.module.rows = []
        # Drop anything still buffered: the result is authoritative, and
        # flushing those afterwards would append them a second time.
        self.module.pending_rows = []
        for item, row in rows_from_result(self.module.spec.id, self.module.result):
            self.add_row(item, row)


class PynzorApp(App):
    """Full-screen recon dashboard."""

    CSS_PATH = STYLES
    TITLE = "Pynzor"

    BINDINGS = [
        Binding("r", "run", "Run"),
        Binding("s", "stop", "Stop"),
        Binding("space", "toggle_module", "Toggle"),
        Binding("o", "toggle_options", "Options"),
        Binding("e", "export", "Export"),
        Binding("b", "toggle_reports", "Reports"),
        Binding("c", "copy_command", "Copy cmd"),
        Binding("q", "quit", "Quit"),
    ]

    running = reactive(False)

    def __init__(self, config: dict, target: str | None = None) -> None:
        super().__init__()
        self.state = SessionState(config=config, target=target or "")
        self.reporter = Reporter()
        # Not `_workers`: that name is Textual's own WorkerManager slot.
        self._module_workers: list = []
        # Static drops its source text; keep the detail body addressable.
        self.detail_text = ""
        self._report_paths: dict[str, Path] = {}
        self._status = "Ready. Enter a target, pick modules, press r."

    # ------------------------------------------------------------------ layout

    def compose(self) -> ComposeResult:
        """Build the whole dashboard."""
        yield Header()
        yield Input(
            value=self.state.target,
            placeholder="Target — https://target.lab or target.lab",
            id="target",
        )
        with Horizontal(id="body"):
            with Vertical(id="rail"):
                yield Label("MODULES", classes="section")
                yield ListView(*(ModuleRow(m) for m in self.state.modules.values()), id="modules")
                yield Label("OPTIONS", classes="section", id="options-title")
                yield VerticalScroll(id="options")
            with Vertical(id="main"):
                with TabbedContent(id="tabs"):
                    for module in self.state.modules.values():
                        with TabPane(module.spec.label, id=f"tab-{module.spec.id}"):
                            yield ModulePane(module)
                    with TabPane("Detail", id="tab-detail"):
                        yield VerticalScroll(Static("", id="detail"), id="detail-scroll")
                    with TabPane("Reports", id="tab-reports"):
                        yield ListView(id="reports")
                # One container rather than two stacked docks: independently
                # docked siblings lose a row to the app-level Footer.
                yield Vertical(
                    Static("", id="status"),
                    Static("", id="preview"),
                    id="statusbar",
                )
        yield Footer()

    def on_mount(self) -> None:
        """Seed every widget from the initial session state."""
        self.query_one("#options-title").display = False
        self.query_one("#options").display = False
        self.refresh_all()
        # 15 fps is well under what a terminal can show and far under the rate
        # progress events arrive at, which is exactly the point.
        self.set_interval(1 / 15, self._flush_progress)
        if not self.state.target:
            self.query_one("#target", Input).focus()

    # ------------------------------------------------------------------ redraw

    def refresh_all(self) -> None:
        """Repaint the rail, every pane, the status line, and the preview."""
        for row in self.query(ModuleRow):
            row.refresh_row()
        for pane in self.query(ModulePane):
            pane.refresh_progress()
            pane.refresh_headline()
        self.refresh_status()

    def refresh_status(self) -> None:
        """Repaint the status and CLI-preview lines."""
        findings = self.state.total_findings
        selected = len(self.state.selected_modules)
        self.query_one("#status", Static).update(
            f"{self._status}   ·   {selected} module(s) selected   ·   {findings} finding(s)",
            layout=False,
        )
        self.query_one("#preview", Static).update(f"$ {preview(self.state)}", layout=False)

    def set_status(self, message: str) -> None:
        """Set the status line message and repaint."""
        self._status = message
        self.refresh_status()

    def pane(self, module_id: str) -> ModulePane:
        """Look up the results pane for a module."""
        return self.query_one(f"#pane-{module_id}", ModulePane)

    def row(self, module_id: str) -> ModuleRow:
        """Look up the rail row for a module."""
        return self.query_one(f"#row-{module_id}", ModuleRow)

    # ----------------------------------------------------------------- running

    def action_run(self) -> None:
        """Start every selected module, one worker each."""
        if self.running:
            self.set_status("Already running — press s to stop.")
            return

        self.state.target = self.query_one("#target", Input).value.strip()
        if not self.state.target:
            self.set_status("Enter a target first.")
            self.query_one("#target", Input).focus()
            return

        selected = self.state.selected_modules
        if not selected:
            self.set_status("No modules selected — press space on a module to enable it.")
            return

        self.state.reset_runs()
        for pane in self.query(ModulePane):
            pane.table.clear()
        self.refresh_all()

        self.running = True
        self._module_workers = []
        for module in selected:
            module.status = Status.QUEUED
            self._module_workers.append(self.run_module(module))
        self.set_status(f"Running {len(selected)} module(s) against {self.state.target}")
        self.refresh_all()

    @work(exclusive=False)
    async def run_module(self, module: ModuleState) -> None:
        """Run one module to completion, streaming progress back to the UI."""
        module.status = Status.RUNNING
        self.row(module.spec.id).refresh_row()

        def on_progress(event: ProgressEvent) -> None:
            """Hand a progress event to the message pump; never touch widgets here."""
            self.post_message(ProgressUpdate(event))

        try:
            result, report = await self._invoke(module, on_progress)
        except asyncio.CancelledError:
            module.status = Status.CANCELLED
            self._finish(module)
            raise
        except Exception as exc:  # a bad target must not kill the whole app
            module.status = Status.FAILED
            module.error = f"{type(exc).__name__}: {exc}"
        else:
            module.result = result
            module.report = report
            module.status = Status.DONE
            module.done = module.total = max(module.total, module.done, 1)
            # Drop the last in-flight phase label; the headline replaces it.
            module.note = None
            self.pane(module.spec.id).rebuild()
        self._finish(module)

    async def _invoke(self, module: ModuleState, on_progress) -> tuple[Any, dict]:
        """Call the runner for one module with its resolved options."""
        spec = module.spec
        target, config = self.state.target, self.state.config
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

    def _finish(self, module: ModuleState) -> None:
        """Repaint after a module ends and clear the running flag when all are done."""
        # Drain the buffer synchronously: callers (and tests) read the final
        # state right after the worker returns, before the next timer tick.
        module.dirty = True
        self._flush_progress()
        self.row(module.spec.id).refresh_row()
        pane = self.pane(module.spec.id)
        pane.refresh_progress()
        pane.refresh_headline()
        if any(m.status in (Status.RUNNING, Status.QUEUED) for m in self.state.selected_modules):
            self.refresh_status()
            return

        self.running = False
        self.set_status(self._run_summary())

    def _run_summary(self) -> str:
        """Describe how the finished run actually ended.

        A cancelled or failed run must not be reported as a clean finish, and
        the message the stop action already set must not be overwritten by a
        worker unwinding after it.
        """
        statuses = [m.status for m in self.state.selected_modules]
        cancelled = statuses.count(Status.CANCELLED)
        failed = statuses.count(Status.FAILED)
        if cancelled:
            return f"Stopped — {cancelled} module(s) cancelled."
        if failed:
            return f"Finished with {failed} failed module(s) — see the pane for details."
        return "Run finished — press e to export, b to browse reports."

    def action_stop(self) -> None:
        """Cancel every in-flight module worker."""
        if not self.running:
            self.set_status("Nothing running.")
            return
        for worker in self._module_workers:
            worker.cancel()
        for module in self.state.selected_modules:
            if module.status in (Status.RUNNING, Status.QUEUED):
                module.status = Status.CANCELLED
        self.running = False
        self.set_status("Stopped.")
        self.refresh_all()

    @on(ProgressUpdate)
    def handle_progress(self, message: ProgressUpdate) -> None:
        """Record one progress event. Deliberately touches no widgets.

        A default fuzz run emits ~2,900 of these. Painting on each one ties UI
        cost to wordlist size and thrashes layout; instead this buffers, and
        `_flush_progress` paints on a fixed cadence.
        """
        event = message.event
        module = self.state.modules.get(event.module)
        if module is None or module.status is not Status.RUNNING:
            return

        module.done, module.total, module.note = event.done, event.total, event.note
        row = row_for(event.module, event.item)
        if row is not None:
            module.pending_rows.append((event.item, row))
        module.dirty = True

    def _flush_progress(self) -> None:
        """Paint whatever changed since the last tick.

        Runs on a timer rather than per event, so UI work is capped at the
        repaint cadence no matter how fast a module produces results.
        """
        for module_id, module in self.state.modules.items():
            if not module.dirty:
                continue
            module.dirty = False

            pane = self.pane(module_id)
            if module.pending_rows:
                pending, module.pending_rows = module.pending_rows, []
                for item, row in pending:
                    pane.add_row(item, row)
            pane.refresh_progress()
            self.row(module_id).refresh_row()

    # ----------------------------------------------------------------- actions

    def action_toggle_module(self) -> None:
        """Include or exclude the highlighted module from the next run."""
        listview = self.query_one("#modules", ListView)
        item = listview.highlighted_child
        if not isinstance(item, ModuleRow):
            return
        item.module.selected = not item.module.selected
        item.refresh_row()
        self.refresh_status()

    def action_toggle_options(self) -> None:
        """Show or hide the options form for the highlighted module."""
        title, panel = self.query_one("#options-title"), self.query_one("#options")
        if panel.display:
            title.display = panel.display = False
            return
        item = self.query_one("#modules", ListView).highlighted_child
        if not isinstance(item, ModuleRow):
            return
        self.build_options(item.module)
        title.display = panel.display = True

    def build_options(self, module: ModuleState) -> None:
        """Render the options form for one module, seeded from its current values."""
        panel = self.query_one("#options", VerticalScroll)
        panel.remove_children()
        if not module.spec.options:
            panel.mount(Static(f"{module.spec.label} has no options."))
            return
        for spec in module.spec.options:
            value = module.options.get(spec.key)
            widget_id = f"opt-{module.spec.id}-{spec.key}"
            if spec.kind == "bool":
                panel.mount(Checkbox(spec.label, value=bool(value), id=widget_id))
            else:
                panel.mount(Label(spec.label, classes="opt-label"))
                panel.mount(Input(value=_as_text(value) or "", placeholder=spec.help, id=widget_id))

    @on(Input.Submitted, "#target")
    def target_submitted(self) -> None:
        """Enter in the target field starts a run.

        The Input consumes letter keys while focused, so the `r` binding is
        unreachable from there; Enter is the way out.
        """
        self.query_one("#modules", ListView).focus()
        self.action_run()

    @on(Input.Changed)
    def option_changed(self, message: Input.Changed) -> None:
        """Write a text option back into module state as it is typed."""
        self._store_option(message.input.id, message.value)

    @on(Checkbox.Changed)
    def checkbox_changed(self, message: Checkbox.Changed) -> None:
        """Write a boolean option back into module state."""
        self._store_option(message.checkbox.id, message.value)

    def _store_option(self, widget_id: str | None, value: Any) -> None:
        """Route an ``opt-<module>-<key>`` widget's value into module state."""
        if not widget_id or not widget_id.startswith("opt-"):
            if widget_id == "target":
                self.state.target = str(value).strip()
                self.refresh_status()
            return
        _, module_id, key = widget_id.split("-", 2)
        module = self.state.modules.get(module_id)
        if module is None:
            return
        module.options[key] = value
        self.refresh_status()

    @on(DataTable.RowHighlighted)
    def show_detail(self, message: DataTable.RowHighlighted) -> None:
        """Expand the highlighted finding in the Detail tab."""
        table_id = message.data_table.id or ""
        module = self.state.modules.get(table_id.removeprefix("table-"))
        if module is None or message.cursor_row >= len(module.rows):
            return
        item = module.rows[message.cursor_row]
        pairs = detail_lines(item)
        width = max((len(label) for label, _ in pairs), default=0)
        body = "\n".join(f"{label.rjust(width)} : {value}" for label, value in pairs)
        self.detail_text = f"{module.spec.label} finding\n\n{body}" if body else "No detail."
        self.query_one("#detail", Static).update(self.detail_text)

    async def action_export(self) -> None:
        """Write a JSON report for every module that produced one."""
        output_dir = Path(self.state.config.get("output", {}).get("directory", "./reports"))
        output_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        written = []
        for module in self.state.modules.values():
            if not module.report:
                continue
            path = output_dir / f"{module.spec.id}_{stamp}.json"
            self.reporter.save(module.report, path)
            written.append(path.name)

        if not written:
            self.set_status("Nothing to export yet — run a module first.")
            return
        self.set_status(f"Exported {len(written)} report(s) to {output_dir}: {', '.join(written)}")
        await self.load_reports()

    async def action_toggle_reports(self) -> None:
        """Open the report browser and refresh its listing."""
        await self.load_reports()
        self.query_one("#tabs", TabbedContent).active = "tab-reports"

    async def load_reports(self) -> None:
        """List saved JSON reports, newest first.

        ``ListView.clear`` is awaitable: appending before the removal settles
        raises DuplicateIds when the same report is listed twice.
        """
        listview = self.query_one("#reports", ListView)
        await listview.clear()
        self._report_paths = {}
        output_dir = Path(self.state.config.get("output", {}).get("directory", "./reports"))
        if not output_dir.is_dir():
            listview.append(ListItem(Label(f"No report directory at {output_dir}")))
            return
        files = sorted(output_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not files:
            listview.append(ListItem(Label(f"No reports in {output_dir}")))
            return
        for path in files[:50]:
            listview.append(ListItem(Label(path.name), id=f"report-{path.stem}"))
        self._report_paths = {f"report-{p.stem}": p for p in files[:50]}

    @on(ListView.Selected)
    def open_report(self, message: ListView.Selected) -> None:
        """Load the selected saved report."""
        if (message.list_view.id or "") != "reports":
            return
        path = self._report_paths.get(message.item.id or "")
        if path is not None:
            self.open_report_path(path)

    def open_report_path(self, path: Path) -> None:
        """Validate and render one saved report envelope.

        A malformed or future-schema file reports itself on the status line
        rather than rendering as if it were understood.
        """
        try:
            data = self.reporter.load(path)
        except (OSError, ValueError) as exc:
            self.set_status(f"Could not read {path.name}: {exc}")
            return
        if not isinstance(data, dict) or data.get("schema_version") != 1:
            version = data.get("schema_version") if isinstance(data, dict) else None
            self.set_status(f"{path.name} has schema_version {version}; expected 1.")
            return
        self.render_report(path, data)

    def render_report(self, path: Path, data: dict) -> None:
        """Render a loaded report envelope into the Detail tab."""
        findings = data.get("findings", [])
        width = max((len(k) for f in findings for k in f), default=0)
        blocks = []
        for index, finding in enumerate(findings, 1):
            body = "\n".join(f"{k.rjust(width)} : {v}" for k, v in finding.items())
            blocks.append(f"[{index}]\n{body}")
        summary = (
            f"{path.name}\n"
            f"module   : {data.get('module')}\n"
            f"target   : {data.get('target')}\n"
            f"severity : {data.get('severity')}\n"
            f"findings : {len(findings)}\n"
        )
        self.detail_text = summary + "\n" + ("\n\n".join(blocks) if blocks else "No findings.")
        self.query_one("#detail", Static).update(self.detail_text)
        self.query_one("#tabs", TabbedContent).active = "tab-detail"
        self.set_status(f"Loaded {path.name}")

    def action_copy_command(self) -> None:
        """Put the equivalent CLI command on the clipboard."""
        command = preview(self.state)
        self.copy_to_clipboard(command)
        self.set_status(f"Copied: {command}")


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


def run_tui(config: dict, target: str | None = None) -> int:
    """Launch the dashboard.

    Args:
        config: Parsed config dict, used for every option default.
        target: Optional target to pre-fill.

    Returns:
        A process exit code.
    """
    PynzorApp(config, target=target).run()
    return 0
