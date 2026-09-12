"""The Pynzor dashboard.

Laid out like lazygit: a column of stacked side panels jumped to by number, a
main panel that follows whichever of them has focus, a command log under it,
and a bottom bar showing the keys that work right here.

Runs each selected module in its own Textual worker awaiting the same
``pynzor.core.runner`` coroutine the CLI calls. Progress callbacks fire inside
those workers and do nothing but post a message, so widget mutation always
happens on the UI thread.
"""

import asyncio
from datetime import datetime
from pathlib import Path

from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, ScrollableContainer, Vertical
from textual.message import Message
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import DataTable, ListView

from pynzor.core.events import ProgressEvent
from pynzor.output.reporter import Reporter
from pynzor.tui.commandlog import CommandLog
from pynzor.tui.hintbar import HintBar
from pynzor.tui.invoke import invoke
from pynzor.tui.keymap import PANEL_ORDER, PANELS, PanelId, universal_bindings
from pynzor.tui.main_view import (
    NO_OPTIONS,
    SUB_VIEWS,
    MainPanel,
    ModulePane,
    render_finding,
    render_option,
    render_overview,
)
from pynzor.tui.panels import (
    PANEL_TYPES,
    FilterableRow,
    FindingsPanel,
    ModuleRow,
    ModulesPanel,
    OptionsPanel,
    ReportsPanel,
    SidePanel,
    StatusPanel,
)
from pynzor.tui.preview import command_for, preview
from pynzor.tui.rows import row_for
from pynzor.tui.screens import (
    ConfirmScreen,
    DashboardScreen,
    HelpScreen,
    MenuScreen,
    PromptScreen,
)
from pynzor.tui.state import ModuleState, SessionState, Status
from pynzor.tui.theme import PYNZOR_THEME

STYLES = Path(__file__).parent / "styles.tcss"

#: How long a transient status message holds the hint bar before the keys
#: come back. Long enough to read, short enough not to hide the bar.
STATUS_SECONDS = 5.0


class ProgressUpdate(Message):
    """A progress event marshalled from a worker onto the UI thread."""

    def __init__(self, event: ProgressEvent) -> None:
        self.event = event
        super().__init__()


class PynzorApp(App):
    """Full-screen recon dashboard."""

    CSS_PATH = STYLES
    TITLE = "Pynzor"

    # Generated, never hand-written: `keymap` is the one place a key is
    # described, and a test asserts nothing is bound outside it.
    BINDINGS = universal_bindings()

    running = reactive(False)

    def __init__(self, config: dict, target: str | None = None) -> None:
        super().__init__()
        self.state = SessionState(config=config, target=target or "")
        self.reporter = Reporter()
        # Not `_workers`: that name is Textual's own WorkerManager slot.
        self._module_workers: list = []
        self._status = "Press enter on Status to set a target, space to pick modules, r to run."
        self._status_timer = None

    # ------------------------------------------------------------------ layout

    def get_default_screen(self) -> DashboardScreen:
        """Use the screen that lets Tab mean 'next panel'."""
        return DashboardScreen()

    def compose(self) -> ComposeResult:
        """Side panels left, main panel and command log right, hints beneath."""
        with Horizontal(id="body"):
            with Vertical(id="side"):
                for panel_type in PANEL_TYPES:
                    yield panel_type(self.state)
            with Vertical(id="right"):
                yield MainPanel(self.state.modules)
                yield CommandLog()
        yield HintBar()

    def on_mount(self) -> None:
        """Seed every widget from the initial session state."""
        self.register_theme(PYNZOR_THEME)
        self.theme = "pynzor"
        self.apply_main_size()
        self.query_one(CommandLog).display = self.state.log_visible
        self.state.log(f"$ {preview(self.state)}")
        self.refresh_log()
        # 15 fps is well under what a terminal can show and far under the rate
        # progress events arrive at, which is exactly the point.
        self.set_interval(1 / 15, self._flush_progress)
        # Modules is the panel you want on open, the way lazygit opens on Files.
        self.action_focus_panel("modules")
        # Seed the list panels by hand: the Modules cursor starts on row 0
        # without ever moving, so no Highlighted message has fired to do it,
        # and the other two have nothing to react to at all. lazygit opens
        # with every panel already populated; an empty one reads as broken.
        self.call_later(self.options_panel.show_module, self.modules_panel.selected())
        self.call_later(self.findings_panel.rebuild)
        self.call_later(self.reports_panel.rebuild, self._output_dir())
        self.refresh_all()

    # -------------------------------------------------------------- panel plumbing

    def panel(self, panel_id: PanelId) -> SidePanel:
        """Look up one side panel."""
        return self.query_one(f"#panel-{panel_id}", SidePanel)

    @property
    def main(self) -> MainPanel:
        """The main panel."""
        return self.query_one(MainPanel)

    @property
    def hintbar(self) -> HintBar:
        """The bottom bar."""
        return self.query_one(HintBar)

    def current_panel(self) -> SidePanel:
        """The side panel that owns the keyboard.

        Walks up from whatever holds focus, so it stays right whether focus is
        on a panel itself or on the ListView inside it. When focus has been
        pushed into the main panel there is no ancestor panel to find, and the
        last one remains current -- which is what makes `escape` know where to
        go back to.
        """
        node: Widget | None = self.focused
        while node is not None:
            if isinstance(node, SidePanel):
                return node
            node = node.parent if isinstance(node.parent, Widget) else None
        return self.panel(self.state.focused_panel)

    @property
    def main_focused(self) -> bool:
        """True when focus has been pushed into the main panel."""
        node: Widget | None = self.focused
        while node is not None:
            if isinstance(node, MainPanel):
                return True
            node = node.parent if isinstance(node.parent, Widget) else None
        return False

    def action_focus_panel(self, panel_id: PanelId) -> None:
        """`1`-`5` — jump straight to a panel."""
        self.state.focused_panel = panel_id
        self.panel(panel_id).focus_target().focus()

    def action_next_panel(self) -> None:
        """`tab` — the next panel down, wrapping."""
        self._step_panel(1)

    def action_prev_panel(self) -> None:
        """`shift+tab` — the next panel up, wrapping."""
        self._step_panel(-1)

    def _step_panel(self, delta: int) -> None:
        """Move focus `delta` panels along the stacking order."""
        index = PANEL_ORDER.index(self.state.focused_panel)
        self.action_focus_panel(PANEL_ORDER[(index + delta) % len(PANEL_ORDER)])

    def on_descendant_focus(self) -> None:
        """Re-sync the chrome whenever focus lands somewhere new."""
        if not self.main_focused:
            self.state.focused_panel = self.current_panel().panel_id
        self.sync_context()

    def sync_context(self) -> None:
        """Point the main panel and the hint bar at the focused panel."""
        self.sync_main()
        self.refresh_hints()

    # ------------------------------------------------------------------ redraw

    def refresh_all(self) -> None:
        """Repaint every panel, the main view, and the bar."""
        for panel in self.query(SidePanel):
            panel.refresh_panel()
        for pane in self.query(ModulePane):
            pane.refresh_progress()
            pane.refresh_headline()
        self.sync_context()

    def refresh_hints(self) -> None:
        """Paint the keys for the focused panel."""
        self.hintbar.show_hints(self.state.focused_panel)

    def refresh_log(self) -> None:
        """Repaint the command log from session state."""
        self.query_one(CommandLog).render_lines_from(self.state.command_log)

    def set_status(self, message: str, level: str = "info") -> None:
        """Report something that just happened.

        It goes to the command log, which keeps it, and borrows the hint bar,
        which gives it back. lazygit reports the same way: a transient line
        where the keys are, never a row reserved for the occasional message.
        """
        self._status = message
        self.state.log(message)
        self.refresh_log()
        self.hintbar.show_status(message, level)
        if self._status_timer is not None:
            self._status_timer.stop()
        self._status_timer = self.set_timer(STATUS_SECONDS, self.refresh_hints)

    def sync_main(self) -> None:
        """Show whatever the focused panel's cursor is pointing at."""
        panel_id = self.state.focused_panel
        main = self.main

        if panel_id == "status":
            view = main.view("view-overview")
            view.set_text(render_overview(self.state, self._output_dir()))
            main.show(view, "Session")
            return

        if panel_id == "modules":
            module = self.modules_panel.selected()
            if module is None:
                return
            main.show_module(module, self.state.main_sub_view)
            return

        if panel_id == "options":
            row = self.options_panel.selected()
            view = main.view("view-option")
            view.set_text(
                render_option(row, self.options_panel.default_for(row)) if row else NO_OPTIONS
            )
            main.show(view, "Option")
            return

        if panel_id == "findings":
            view = main.view("view-detail")
            view.set_text(render_finding(self.findings_panel.selected()))
            main.show(view, "Finding")
            return

        view = main.view("view-report")
        main.show(view, "Report")

    def _output_dir(self) -> Path:
        """Where reports are written, per config.yaml."""
        return Path(self.state.config.get("output", {}).get("directory", "./reports"))

    # ---------------------------------------------------------- typed panel access

    @property
    def status_panel(self) -> StatusPanel:
        """The Status panel."""
        return self.query_one(StatusPanel)

    @property
    def modules_panel(self) -> ModulesPanel:
        """The Modules panel."""
        return self.query_one(ModulesPanel)

    @property
    def options_panel(self) -> OptionsPanel:
        """The Options panel."""
        return self.query_one(OptionsPanel)

    @property
    def findings_panel(self) -> FindingsPanel:
        """The Findings panel."""
        return self.query_one(FindingsPanel)

    @property
    def reports_panel(self) -> ReportsPanel:
        """The Reports panel."""
        return self.query_one(ReportsPanel)

    def pane(self, module_id: str) -> ModulePane:
        """Look up the results pane for a module."""
        return self.main.pane(module_id)

    def row(self, module_id: str) -> ModuleRow:
        """Look up the rail row for a module."""
        return self.query_one(f"#row-{module_id}", ModuleRow)

    # ----------------------------------------------------------------- cursors

    @on(ListView.Highlighted)
    async def cursor_moved(self, message: ListView.Highlighted) -> None:
        """Follow a side-panel cursor with the main view.

        The Modules cursor also drives the Options panel, which is what makes
        options a panel rather than a mode: it is always showing the options
        for the module you are looking at.
        """
        list_id = message.list_view.id or ""
        if list_id == "list-modules":
            await self.options_panel.show_module(self.modules_panel.selected())
        if list_id.removeprefix("list-") == self.state.focused_panel:
            self.sync_main()
        self.status_panel.refresh_panel()

    @on(ListView.Selected)
    async def list_selected(self, message: ListView.Selected) -> None:
        """Run the panel's `enter` action when a list row is chosen.

        `ListView` binds `enter` to its own `select_cursor`, and Textual
        resolves the focused widget's bindings before its ancestors' -- so a
        panel's `enter` binding can never fire on its own. Rather than fight
        that with a ListView subclass, this executes whatever the keymap says
        `enter` does here, which keeps the table the single source of truth.
        """
        panel_id = (message.list_view.id or "").removeprefix("list-")
        for key in PANELS.get(panel_id, ()):
            if "enter" in key.key_list:
                await self.run_action(key.action.removeprefix("app."))
                return

    # ----------------------------------------------------------------- running

    def action_run(self) -> None:
        """Start every selected module, one worker each."""
        if self.running:
            self.set_status("Already running — press s to stop.", "warn")
            return

        if not self.state.target:
            self.set_status("Enter a target first.", "warn")
            self.action_edit_target()
            return

        selected = self.state.selected_modules
        if not selected:
            self.set_status("No modules selected — press space on a module.", "warn")
            return

        self.state.reset_runs()
        for pane in self.query(ModulePane):
            pane.table.clear()
        self.refresh_all()

        self.running = True
        self._module_workers = []
        for module in selected:
            module.status = Status.QUEUED
            self.state.log(f"$ {command_for(module, self.state)}")
            self._module_workers.append(self.run_module(module))
        self.refresh_log()
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
            result, report = await invoke(module, self.state.target, self.state.config, on_progress)
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

    def _finish(self, module: ModuleState) -> None:
        """Repaint after a module ends and clear the running flag when all are done.

        Deliberately synchronous. This also runs on the cancellation path, and
        awaiting anything inside a task that is already being cancelled raises
        `CancelledError` straight back out -- which would skip the repaint and
        leave a cancelled module painted as if it were still running.
        """
        # Drain the buffer synchronously: callers (and tests) read the final
        # state right after the worker returns, before the next timer tick.
        module.dirty = True
        self._flush_progress()
        self.row(module.spec.id).refresh_row()
        pane = self.pane(module.spec.id)
        pane.refresh_progress()
        pane.refresh_headline()
        self.status_panel.refresh_panel()
        # The flat list is derived state: queued rather than awaited, so the
        # cancellation path above stays synchronous, and rebuilt once per module
        # rather than per event -- a run emits thousands of those.
        self.call_later(self._rebuild_findings)

        if any(m.status in (Status.RUNNING, Status.QUEUED) for m in self.state.selected_modules):
            return

        self.running = False
        self.set_status(self._run_summary(), self._run_level())

    async def _rebuild_findings(self) -> None:
        """Reflatten the Findings panel, and refresh the main view if it is showing."""
        await self.findings_panel.rebuild()
        if self.state.focused_panel == "findings":
            self.sync_main()

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
        return "Run finished — press e to export, 4 to browse findings."

    def _run_level(self) -> str:
        """Colour the closing status by how the run actually ended."""
        statuses = [m.status for m in self.state.selected_modules]
        if Status.FAILED in statuses:
            return "error"
        if Status.CANCELLED in statuses:
            return "warn"
        return "info"

    def action_stop(self) -> None:
        """Cancel every in-flight module worker."""
        if not self.running:
            self.set_status("Nothing running.", "warn")
            return
        for worker in self._module_workers:
            worker.cancel()
        for module in self.state.selected_modules:
            if module.status in (Status.RUNNING, Status.QUEUED):
                module.status = Status.CANCELLED
        self.running = False
        self.set_status("Stopped.", "warn")
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

    # -------------------------------------------------------------- navigation

    def action_nav(self, direction: str) -> None:
        """Move the cursor in whatever currently has focus.

        One app-level binding per direction rather than a `j`/`k` binding on
        every widget subclass: Textual's ListView and DataTable bind only the
        arrow keys, so there is nothing to fight, and the text views are plain
        scrollables that have no cursor at all.

        Directions: `up`, `down`, `home`, `end`, `pageup`, `pagedown`.
        """
        target = self.focused
        if isinstance(target, ListView):
            self._nav_list(target, direction)
        elif isinstance(target, DataTable):
            self._nav_table(target, direction)
        elif isinstance(target, ScrollableContainer):
            self._nav_scroll(target, direction)

    @staticmethod
    def _nav_list(listview: ListView, direction: str) -> None:
        """Move a ListView cursor; `index` is the only way to jump or page.

        ListView has no page action of its own, so `,`/`.` move the index by a
        visible page and clamp. Written as explicit branches rather than an
        `else` fallback: with six directions, a typo'd one silently jumping to
        the bottom of the list is worse than it doing nothing.
        """
        last = len(listview.children) - 1
        if last < 0:
            return
        if direction == "down":
            listview.action_cursor_down()
        elif direction == "up":
            listview.action_cursor_up()
        elif direction == "home":
            listview.index = 0
        elif direction == "end":
            listview.index = last
        elif direction in ("pagedown", "pageup"):
            page = max(1, listview.size.height)
            step = page if direction == "pagedown" else -page
            listview.index = max(0, min(last, (listview.index or 0) + step))

    @staticmethod
    def _nav_table(table: DataTable, direction: str) -> None:
        """Move a DataTable row cursor."""
        if direction == "down":
            table.action_cursor_down()
        elif direction == "up":
            table.action_cursor_up()
        elif direction == "home":
            table.action_scroll_top()
        elif direction == "end":
            table.action_scroll_bottom()
        elif direction == "pagedown":
            table.action_page_down()
        elif direction == "pageup":
            table.action_page_up()

    @staticmethod
    def _nav_scroll(container: ScrollableContainer, direction: str) -> None:
        """Scroll a cursorless pane. Never animate: `g`/`G` should land at once."""
        if direction == "down":
            container.scroll_down(animate=False)
        elif direction == "up":
            container.scroll_up(animate=False)
        elif direction == "home":
            container.scroll_home(animate=False)
        elif direction == "end":
            container.scroll_end(animate=False)
        elif direction == "pagedown":
            container.scroll_page_down(animate=False)
        elif direction == "pageup":
            container.scroll_page_up(animate=False)

    def action_scroll_main(self, direction: str) -> None:
        """`ctrl+d`/`ctrl+u` — scroll the main panel without leaving the side panel.

        The lazygit reflex: read a long result while the cursor stays where it
        is, so the next `j` still moves the list and not the text.
        """
        target = self.main.scrollable()
        if target is None:
            return
        page = max(1, target.size.height - 1)
        if direction == "down":
            target.scroll_relative(y=page, animate=False)
        else:
            target.scroll_relative(y=-page, animate=False)

    def action_focus_results(self) -> None:
        """`enter` — push focus into the main panel, lazygit's secondary context."""
        target = self.main.scrollable()
        if target is None or not target.focusable:
            return
        target.focus()
        self.refresh_hints()

    def action_next_block(self) -> None:
        """`l`/`right` — lazygit's nextBlock: side column to main panel.

        A no-op once focus is already in the main panel. lazygit has a third
        block (its own secondary view) to move on to; here there is nowhere
        further right, and wrapping back to the column would make `h` and `l`
        the same key.
        """
        if not self.main_focused:
            self.action_focus_results()

    def action_prev_block(self) -> None:
        """`h`/`left` — lazygit's prevBlock: main panel back to the side column."""
        self.action_leave_main()

    def action_focus_main(self) -> None:
        """`0` — lazygit's focusMainView, from wherever focus happens to be."""
        self.action_focus_results()

    def action_leave_main(self) -> None:
        """`escape` — pop back out of the main panel to the side panel.

        Not ``action_back``: Textual's App already defines that for screen
        navigation, and shadowing it with a different signature would break
        going back as well as fail the type check.
        """
        if self.main_focused:
            self.panel(self.state.focused_panel).focus_target().focus()

    def action_next_subtab(self) -> None:
        """`]` — the next sub-tab of the Modules main view."""
        self._step_subtab(1)

    def action_prev_subtab(self) -> None:
        """`[` — the previous sub-tab."""
        self._step_subtab(-1)

    def _step_subtab(self, delta: int) -> None:
        """Cycle the Modules main view between Findings and Report."""
        index = SUB_VIEWS.index(self.state.main_sub_view)
        self.state.main_sub_view = SUB_VIEWS[(index + delta) % len(SUB_VIEWS)]
        self.sync_main()

    # -------------------------------------------------------------- main sizing

    def action_grow_main(self) -> None:
        """`+` — give the main panel more room."""
        self.state.main_size = min(2, self.state.main_size + 1)
        self.apply_main_size()

    def action_shrink_main(self) -> None:
        """`_` — give it back."""
        self.state.main_size = max(0, self.state.main_size - 1)
        self.apply_main_size()

    def apply_main_size(self) -> None:
        """Paint the current size step as a class on the body.

        A class rather than inline styles so the three steps live in the
        stylesheet next to every other dimension.
        """
        body = self.query_one("#body")
        for step in range(3):
            body.set_class(step == self.state.main_size, f"main-{step}")

    def action_toggle_log(self) -> None:
        """`@` — show or hide the command log."""
        self.state.log_visible = not self.state.log_visible
        self.query_one(CommandLog).display = self.state.log_visible

    # ----------------------------------------------------------------- popups

    def action_help(self) -> None:
        """`?` — the keybinding cheatsheet."""
        self.push_screen(HelpScreen())

    def action_menu(self) -> None:
        """`x` — every action available here, pickable instead of remembered."""

        async def run_choice(action: str | None) -> None:
            """Run whatever the menu returned, in the app's namespace."""
            if action:
                await self.run_action(action.removeprefix("app."))

        self.push_screen(MenuScreen(self.state.focused_panel), run_choice)

    def action_edit_target(self) -> None:
        """`enter` on Status — set the target in a popup."""

        def store(value: str | None) -> None:
            """Adopt the typed target, unless the prompt was cancelled."""
            if value is None:
                return
            self.state.target = value
            self.status_panel.refresh_panel()
            self.sync_main()
            self.set_status(f"Target set to {value}" if value else "Target cleared.")

        self.push_screen(
            PromptScreen("Target", self.state.target, "https://target.lab or target.lab"), store
        )

    def action_edit_option(self) -> None:
        """`enter` on Options — toggle a switch, or type a new value."""
        row = self.options_panel.selected()
        if row is None:
            return
        if row.spec.kind == "bool":
            row.module.options[row.spec.key] = not row.module.options.get(row.spec.key)
            row.refresh_row()
            self.sync_main()
            return

        def store(value: str | None) -> None:
            """Write the typed value back into module state."""
            if value is None:
                return
            row.module.options[row.spec.key] = value
            row.refresh_row()
            self.sync_main()

        self.push_screen(PromptScreen(row.spec.label, row.value_text(), row.spec.help), store)

    def action_reset_option(self) -> None:
        """`d` on Options — put the config.yaml default back (AGENTS.md 11)."""
        row = self.options_panel.selected()
        if row is None:
            return
        row.module.options[row.spec.key] = self.options_panel.default_for(row)
        row.refresh_row()
        self.sync_main()
        self.set_status(f"{row.spec.label} reset to its config default.")

    async def action_quit(self) -> None:
        """`q` — quit, confirming first if that would abandon a running scan."""
        if not self.running:
            self.exit()
            return

        def maybe_exit(confirmed: bool | None) -> None:
            """Leave only on an explicit yes."""
            if confirmed:
                self.action_stop()
                self.exit()

        self.push_screen(
            ConfirmScreen("Quit", "A scan is still running. Stop it and quit?"), maybe_exit
        )

    def action_filter(self) -> None:
        """`/` — filter the focused list panel."""
        panel = self.panel(self.state.focused_panel)
        if not isinstance(panel, (ModulesPanel, FindingsPanel, ReportsPanel)):
            self.set_status("Nothing to filter in this panel.", "warn")
            return

        def apply(value: str | None) -> None:
            """Hide the rows that do not match."""
            if value is None:
                return
            self.state.filter_text = value
            self._apply_filter()

        self.push_screen(PromptScreen("Filter", self.state.filter_text, "substring"), apply)

    def _apply_filter(self) -> None:
        """Show only rows matching the current filter, across the list panels.

        Rows are hidden rather than removed: the Modules rows carry live
        progress state that a running worker is still repainting, and rebuilding
        them mid-run would drop it.
        """
        needle = self.state.filter_text.casefold()
        matched = 0
        for panel in self.query(SidePanel):
            if not isinstance(panel, (ModulesPanel, FindingsPanel, ReportsPanel)):
                continue
            for item in panel.list_view.children:
                if not isinstance(item, FilterableRow):
                    continue
                shown = not needle or needle in item.filter_text.casefold()
                item.display = shown
                matched += shown
        if not needle:
            self.set_status("Filter cleared.")
            return
        self.set_status(f"Filter {needle!r} — {matched} row(s) match.")

    # ---------------------------------------------------------------- reports

    async def action_export(self) -> None:
        """Write a JSON report for every module that produced one."""
        output_dir = self._output_dir()
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
            self.set_status("Nothing to export yet — run a module first.", "warn")
            return
        self.set_status(f"Exported {len(written)} report(s) to {output_dir}: {', '.join(written)}")
        await self.action_refresh_reports()

    async def action_refresh_reports(self) -> None:
        """Reload the saved-report listing from disk."""
        await self.reports_panel.rebuild(self._output_dir())

    def action_open_report(self) -> None:
        """`enter` on Reports — open whatever the cursor is on."""
        path = self.reports_panel.selected()
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
            self.set_status(f"Could not read {path.name}: {exc}", "error")
            return
        if not isinstance(data, dict) or data.get("schema_version") != 1:
            version = data.get("schema_version") if isinstance(data, dict) else None
            self.set_status(f"{path.name} has schema_version {version}; expected 1.", "error")
            return
        self.render_report(path, data)

    def render_report(self, path: Path, data: dict) -> None:
        """Render a loaded report envelope into the main panel."""
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
        view = self.main.view("view-report")
        view.set_text(summary + "\n" + ("\n\n".join(blocks) if blocks else "No findings."))
        self.main.show(view, f"Report — {path.name}")
        self.set_status(f"Loaded {path.name}")

    # ---------------------------------------------------------------- modules

    def action_toggle_module(self) -> None:
        """Include or exclude the highlighted module from the next run."""
        module = self.modules_panel.selected()
        if module is None:
            return
        module.selected = not module.selected
        self.modules_panel.refresh_panel()
        self.status_panel.refresh_panel()
        self.sync_main()

    def action_copy_command(self) -> None:
        """Put the equivalent CLI command on the clipboard."""
        command = preview(self.state)
        self.copy_to_clipboard(command)
        self.set_status(f"Copied: {command}")

    @on(DataTable.RowSelected)
    async def open_finding(self, message: DataTable.RowSelected) -> None:
        """`enter` on a results row — jump to that finding in the Findings panel.

        The drill-down lives in its own panel now, so this is a jump rather
        than a tab switch: the cursor lands on the same finding, in the flat
        cross-module list, with its detail already in the main panel.
        """
        table_id = message.data_table.id or ""
        module_id = table_id.removeprefix("table-")
        module = self.state.modules.get(module_id)
        if module is None:
            return
        await self.findings_panel.rebuild()
        offset = 0
        for other in self.state.modules.values():
            if other.spec.id == module_id:
                break
            offset += len(other.rows)
        self.action_focus_panel("findings")
        listview = self.findings_panel.list_view
        index = offset + message.cursor_row
        if index < len(listview.children):
            listview.index = index
        self.sync_main()


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
