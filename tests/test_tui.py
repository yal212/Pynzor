"""Pilot-driven tests for the dashboard.

Drives the real Textual app against the local HTTP fixture: no mocked runner,
so these cover the whole path from a keypress to an exported report envelope.
"""

import json
import pathlib

import pytest

from pynzor.cli.main import is_interactive
from pynzor.core.config import load_config
from pynzor.tui import keymap
from pynzor.tui.app import PynzorApp
from pynzor.tui.commandlog import CommandLog
from pynzor.tui.hintbar import HintBar
from pynzor.tui.panels import SidePanel
from pynzor.tui.preview import preview
from pynzor.tui.rows import detail_lines, headline, row_for
from pynzor.tui.screens import ConfirmScreen, HelpScreen, MenuScreen, PromptScreen
from pynzor.tui.state import SessionState, Status


@pytest.fixture
def tui_config(tmp_path, config):
    """A config whose report directory is a temp dir, so exports are isolated."""
    full = load_config()
    full["output"] = {"directory": str(tmp_path / "reports")}
    return full


def only(app: PynzorApp, *module_ids: str) -> None:
    """Select exactly the named modules for the next run."""
    for module_id, module in app.state.modules.items():
        module.selected = module_id in module_ids


async def focus(pilot, app: PynzorApp, panel: str = "modules") -> None:
    """Put focus on one side panel by its number key, the way a user would."""
    await pilot.press(str(keymap.PANEL_ORDER.index(panel) + 1))
    await pilot.pause()


async def run_and_wait(pilot, app: PynzorApp) -> None:
    """Press run, then wait for every module worker to finish."""
    await focus(pilot, app, "modules")
    await pilot.press("r")
    await app.workers.wait_for_complete()
    await pilot.pause()


def detail_text(app: PynzorApp) -> str:
    """Whatever the drill-down view is currently showing."""
    return app.main.view("view-detail").text


def report_text(app: PynzorApp) -> str:
    """Whatever the saved-report view is currently showing."""
    return app.main.view("view-report").text


# ----------------------------------------------------------------- behaviour


async def test_mounts_with_every_module(tui_config):
    """The Modules panel lists all six, idle and selected."""
    app = PynzorApp(tui_config)
    async with app.run_test() as pilot:
        await pilot.pause()
        assert len(app.state.modules) == 6
        assert all(m.status is Status.IDLE for m in app.state.modules.values())
        assert len(app.state.selected_modules) == 6


async def test_run_without_target_is_refused(tui_config):
    """Pressing run with an empty target explains itself instead of crashing."""
    app = PynzorApp(tui_config)
    async with app.run_test() as pilot:
        await focus(pilot, app)
        await pilot.press("r")
        await pilot.pause()
        assert "Enter a target" in app._status
        assert not app.running


async def test_headers_run_populates_table_and_report(http_fixture, tui_config):
    """A real run fills the pane's table and produces an exportable envelope."""
    app = PynzorApp(tui_config, target=http_fixture)
    async with app.run_test() as pilot:
        only(app, "headers")
        await run_and_wait(pilot, app)

        module = app.state.modules["headers"]
        assert module.status is Status.DONE, module.error
        assert module.report["module"] == "headers"
        assert module.report["schema_version"] == 1

        # The table is rebuilt from the result, so it must match the report.
        assert len(module.rows) == len(module.report["findings"])
        assert app.pane("headers").table.row_count == len(module.rows)
        assert not app.running


async def test_progress_events_reach_the_pane(http_fixture, tui_config, test_wordlist):
    """Progress from a worker is marshalled onto the UI and fills the bar."""
    app = PynzorApp(tui_config, target=http_fixture)
    async with app.run_test() as pilot:
        only(app, "fuzz")
        app.state.modules["fuzz"].options["wordlist"] = str(test_wordlist)
        await run_and_wait(pilot, app)

        module = app.state.modules["fuzz"]
        assert module.status is Status.DONE, module.error
        assert module.done > 0 and module.done >= module.total
        assert "100.0%" in app.pane("fuzz").progress_text
        # /admin is the fixture's only hit.
        assert any("/admin" in r.url for r in module.result.found)


async def test_stop_cancels_an_in_flight_run(tui_config, monkeypatch):
    """Pressing stop cancels the workers and marks the module cancelled.

    The runner is stubbed to hang so the run is guaranteed still in flight
    when stop is pressed -- against the local fixture a real module can finish
    first, which would make this pass for the wrong reason.
    """
    import asyncio

    from pynzor.core import runner

    started = asyncio.Event()

    async def never_finishes(*args, **kwargs):
        started.set()
        await asyncio.sleep(3600)

    # Patched on the runner module itself: `ModuleSpec.runner` resolves by name
    # at call time, so this reaches the dashboard whichever module imports it.
    monkeypatch.setattr(runner, "run_headers", never_finishes)

    app = PynzorApp(tui_config, target="https://demo.invalid")
    async with app.run_test() as pilot:
        only(app, "headers")
        await focus(pilot, app)
        await pilot.press("r")
        await asyncio.wait_for(started.wait(), timeout=5)
        assert app.running
        assert app.state.modules["headers"].status is Status.RUNNING

        await pilot.press("s")
        await pilot.pause()

        assert not app.running
        assert app.state.modules["headers"].status is Status.CANCELLED
        assert "Stopped" in app._status


async def test_cancelled_module_is_still_repainted(tui_config, monkeypatch):
    """A cancelled worker must leave the rail showing 'stopped', not 'running'.

    `_finish` also runs on the cancellation path, so it has to stay
    synchronous: awaiting anything inside a task that is already being
    cancelled raises straight back out and skips the repaint.
    """
    import asyncio

    from pynzor.core import runner

    started = asyncio.Event()

    async def never_finishes(*args, **kwargs):
        started.set()
        await asyncio.sleep(3600)

    # Patched on the runner module itself: `ModuleSpec.runner` resolves by name
    # at call time, so this reaches the dashboard whichever module imports it.
    monkeypatch.setattr(runner, "run_headers", never_finishes)

    app = PynzorApp(tui_config, target="https://demo.invalid")
    async with app.run_test() as pilot:
        only(app, "headers")
        await focus(pilot, app)
        await pilot.press("r")
        await asyncio.wait_for(started.wait(), timeout=5)
        await pilot.press("s")
        await pilot.pause()
        assert app.state.modules["headers"].summary == "stopped"


async def test_failure_is_reported_not_fatal(tui_config):
    """A module that blows up marks itself failed and leaves the app alive."""
    app = PynzorApp(tui_config, target="http://127.0.0.1:1")
    async with app.run_test() as pilot:
        only(app, "fuzz")
        app.state.modules["fuzz"].options["wordlist"] = "/nonexistent/wordlist.txt"
        await run_and_wait(pilot, app)

        module = app.state.modules["fuzz"]
        assert module.status is Status.FAILED
        assert module.error
        assert not app.running


async def test_export_writes_a_valid_envelope(http_fixture, tui_config, tmp_path):
    """Export writes the same schema the CLI writes, via the same Reporter."""
    app = PynzorApp(tui_config, target=http_fixture)
    async with app.run_test() as pilot:
        only(app, "headers")
        await run_and_wait(pilot, app)
        await pilot.press("e")
        await pilot.pause()

        files = list((tmp_path / "reports").glob("headers_*.json"))
        assert len(files) == 1
        data = json.loads(files[0].read_text())
        assert data["schema_version"] == 1
        assert data["module"] == "headers"
        assert data["target"] == http_fixture
        assert data == app.state.modules["headers"].report


async def test_export_with_nothing_to_export(tui_config):
    """Exporting before a run says so rather than writing an empty file."""
    app = PynzorApp(tui_config)
    async with app.run_test() as pilot:
        await focus(pilot, app)
        await pilot.press("e")
        await pilot.pause()
        assert "Nothing to export" in app._status


async def test_report_browser_loads_a_saved_report(http_fixture, tui_config, tmp_path):
    """A saved report can be reopened from the Reports panel into the main view."""
    app = PynzorApp(tui_config, target=http_fixture)
    async with app.run_test() as pilot:
        only(app, "headers")
        await run_and_wait(pilot, app)
        await pilot.press("e")
        await pilot.pause()

        # Export refreshes the listing, so the report is already there.
        await focus(pilot, app, "reports")
        await pilot.press("enter")
        await pilot.pause()

        saved = sorted((tmp_path / "reports").glob("headers_*.json"))[0]
        assert saved.name in report_text(app)
        assert "module   : headers" in report_text(app)


async def test_report_browser_rejects_a_bad_schema(tui_config, tmp_path):
    """An unknown schema_version is reported, not rendered as if it were fine."""
    reports = tmp_path / "reports"
    reports.mkdir(parents=True)
    bad = reports / "headers_20990101_000000.json"
    bad.write_text(json.dumps({"schema_version": 99, "module": "headers", "findings": []}))

    app = PynzorApp(tui_config)
    async with app.run_test() as pilot:
        await focus(pilot, app, "reports")
        await pilot.press("d")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        assert "schema_version 99" in app._status


async def test_toggle_deselects_a_module(tui_config):
    """Space toggles the highlighted module out of the next run."""
    app = PynzorApp(tui_config)
    async with app.run_test() as pilot:
        await focus(pilot, app)
        await pilot.press("space")
        await pilot.pause()
        assert len(app.state.selected_modules) == 5


# ------------------------------------------------------------ lazygit layout


async def test_number_keys_jump_to_every_panel(tui_config):
    """`1`-`5` select each side panel and put focus inside it."""
    app = PynzorApp(tui_config)
    async with app.run_test() as pilot:
        for index, panel_id in enumerate(keymap.PANEL_ORDER, start=1):
            await pilot.press(str(index))
            await pilot.pause()
            assert app.state.focused_panel == panel_id
            assert app.current_panel().panel_id == panel_id


async def test_tab_cycles_side_panels(tui_config):
    """Tab steps through the panels and wraps, rather than walking every widget.

    Textual's Screen binds Tab to `focus_next`; if that is not overridden, Tab
    wanders into the main panel and the panel order stops meaning anything.
    """
    app = PynzorApp(tui_config)
    async with app.run_test() as pilot:
        await focus(pilot, app, "status")
        for expected in keymap.PANEL_ORDER[1:] + keymap.PANEL_ORDER[:1]:
            await pilot.press("tab")
            await pilot.pause()
            assert app.state.focused_panel == expected

        await pilot.press("shift+tab")
        await pilot.pause()
        assert app.state.focused_panel == keymap.PANEL_ORDER[-1]


async def test_main_view_follows_the_focused_panel(tui_config):
    """The main panel shows the focused panel's context, lazygit-style."""
    app = PynzorApp(tui_config, target="https://demo.lab")
    async with app.run_test() as pilot:
        await focus(pilot, app, "status")
        assert "demo.lab" in app.main.view("view-overview").text

        await focus(pilot, app, "modules")
        assert app.main.border_title.startswith("Ports")

        await focus(pilot, app, "options")
        assert "flag" in app.main.view("view-option").text

        await focus(pilot, app, "findings")
        assert app.main.border_title == "Finding"


async def test_module_cursor_drives_the_main_view_and_options(tui_config):
    """Moving the Modules cursor retitles the main panel and reloads Options."""
    app = PynzorApp(tui_config)
    async with app.run_test() as pilot:
        await focus(pilot, app, "modules")
        assert app.main.border_title.startswith("Ports")

        await pilot.press("j")
        await pilot.pause()
        assert app.main.border_title.startswith("Fuzz")
        assert app.options_panel.module is not None
        assert app.options_panel.module.spec.id == "fuzz"


async def test_brackets_switch_the_module_subtabs(tui_config):
    """`[`/`]` cycle the Modules main view between Findings and Report."""
    app = PynzorApp(tui_config)
    async with app.run_test() as pilot:
        await focus(pilot, app, "modules")
        assert app.state.main_sub_view == "findings"

        await pilot.press("]")
        await pilot.pause()
        assert app.state.main_sub_view == "report"
        assert "has not produced a report yet" in app.main.view("view-modreport").text

        await pilot.press("[")
        await pilot.pause()
        assert app.state.main_sub_view == "findings"


async def test_enter_pushes_focus_into_main_and_escape_pops_back(http_fixture, tui_config):
    """lazygit's secondary context: `enter` goes in, `esc` comes back."""
    app = PynzorApp(tui_config, target=http_fixture)
    async with app.run_test() as pilot:
        only(app, "headers")
        await run_and_wait(pilot, app)
        await focus(pilot, app, "modules")
        # Land on the module that actually has rows.
        while app.modules_panel.selected().spec.id != "headers":
            await pilot.press("j")
            await pilot.pause()

        await pilot.press("enter")
        await pilot.pause()
        assert app.main_focused

        await pilot.press("escape")
        await pilot.pause()
        assert not app.main_focused
        assert app.state.focused_panel == "modules"


async def test_ctrl_d_scrolls_main_without_moving_the_side_cursor(http_fixture, tui_config):
    """The main panel scrolls while the side panel keeps the cursor."""
    app = PynzorApp(tui_config, target=http_fixture)
    async with app.run_test(size=(120, 30)) as pilot:
        await focus(pilot, app, "status")
        before = app.focused

        await pilot.press("ctrl+d")
        await pilot.pause()
        assert app.focused is before
        assert app.state.focused_panel == "status"


async def test_panel_sizing_cycles(tui_config):
    """`+` grows the main panel through three steps and `_` gives them back."""
    app = PynzorApp(tui_config)
    async with app.run_test() as pilot:
        await pilot.pause()
        body = app.query_one("#body")
        assert body.has_class("main-0")

        await pilot.press("+")
        await pilot.pause()
        assert body.has_class("main-1")

        await pilot.press("+", "+")
        await pilot.pause()
        assert body.has_class("main-2")
        assert not app.query_one("#side").display

        await pilot.press("_", "_")
        await pilot.pause()
        assert body.has_class("main-0")


async def test_command_log_records_each_module_command(http_fixture, tui_config):
    """The log shows the CLI command each module corresponds to."""
    app = PynzorApp(tui_config, target=http_fixture)
    async with app.run_test() as pilot:
        only(app, "headers")
        await run_and_wait(pilot, app)
        text = app.query_one(CommandLog).text
        assert f"$ Pynzor headers -t {http_fixture}" in text
        assert "Run finished" in text


async def test_command_log_toggles(tui_config):
    """`@` hides and shows the command log."""
    app = PynzorApp(tui_config)
    async with app.run_test() as pilot:
        await focus(pilot, app)
        log = app.query_one(CommandLog)
        assert log.display

        await pilot.press("@")
        await pilot.pause()
        assert not log.display

        await pilot.press("@")
        await pilot.pause()
        assert log.display


async def test_findings_panel_flattens_across_modules(http_fixture, tui_config):
    """Every finding lands in one cross-module list, tagged with its module."""
    app = PynzorApp(tui_config, target=http_fixture)
    async with app.run_test() as pilot:
        only(app, "headers")
        await run_and_wait(pilot, app)
        await focus(pilot, app, "findings")

        refs = app.state.findings
        assert refs
        assert all(ref.module_id == "headers" for ref in refs)
        assert app.findings_panel.selected() is not None
        assert "Headers finding" in detail_text(app)


async def test_enter_on_a_result_row_jumps_to_that_finding(http_fixture, tui_config):
    """Drilling in from the results table lands on the same finding in panel 4."""
    app = PynzorApp(tui_config, target=http_fixture)
    async with app.run_test() as pilot:
        only(app, "headers")
        await run_and_wait(pilot, app)

        table = app.pane("headers").table
        assert table.row_count
        table.focus()
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()

        assert app.state.focused_panel == "findings"
        assert app.findings_panel.selected() is not None
        assert detail_text(app).startswith("[b]Headers finding")


# --------------------------------------------------------------- hint bar


async def test_hints_are_context_sensitive(tui_config):
    """The bar shows the focused panel's keys, not one global set."""
    app = PynzorApp(tui_config)
    async with app.run_test() as pilot:
        bar = app.query_one(HintBar)

        await focus(pilot, app, "modules")
        modules_hints = bar.text
        assert "Toggle module" in modules_hints

        await focus(pilot, app, "reports")
        assert bar.text != modules_hints
        assert "Open report" in bar.text
        assert "Toggle module" not in bar.text


async def test_hints_always_offer_the_way_out(tui_config):
    """Every panel advertises the menu and the cheatsheet, as lazygit does."""
    app = PynzorApp(tui_config)
    async with app.run_test() as pilot:
        bar = app.query_one(HintBar)
        for panel_id in keymap.PANEL_ORDER:
            await focus(pilot, app, panel_id)
            assert "Menu" in bar.text
            assert "Keybindings" in bar.text


async def test_status_messages_borrow_the_hint_bar(tui_config):
    """A status message takes the bar, then the keys come back."""
    app = PynzorApp(tui_config)
    async with app.run_test() as pilot:
        await focus(pilot, app)
        bar = app.query_one(HintBar)
        app.set_status("something happened")
        await pilot.pause()
        assert "something happened" in bar.text

        app.refresh_hints()
        await pilot.pause()
        assert "Toggle module" in bar.text


# ----------------------------------------------------------------- popups


async def test_help_overlay_opens_and_closes(tui_config):
    """`?` shows the cheatsheet and Esc dismisses it."""
    app = PynzorApp(tui_config)
    async with app.run_test() as pilot:
        await focus(pilot, app)

        await pilot.press("?")
        await pilot.pause()
        assert isinstance(app.screen, HelpScreen)

        await pilot.press("escape")
        await pilot.pause()
        assert not isinstance(app.screen, HelpScreen)


async def test_menu_lists_the_focused_panels_actions_and_runs_one(tui_config):
    """`x` offers what is available here, and picking a row performs it."""
    app = PynzorApp(tui_config)
    async with app.run_test() as pilot:
        await focus(pilot, app, "modules")
        selected_before = len(app.state.selected_modules)

        await pilot.press("x")
        await pilot.pause()
        assert isinstance(app.screen, MenuScreen)
        # The panel's own keys come first, so the cursor starts on one.
        assert keymap.menu_for("modules")[0][1] == "Toggle module"

        await pilot.press("enter")
        await pilot.pause()
        assert not isinstance(app.screen, MenuScreen)
        assert len(app.state.selected_modules) == selected_before - 1


async def test_target_prompt_sets_the_target(tui_config):
    """`enter` on Status opens a prompt, and what you type becomes the target."""
    app = PynzorApp(tui_config)
    async with app.run_test() as pilot:
        await focus(pilot, app, "status")
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, PromptScreen)

        await pilot.press(*"https://demo.lab")
        await pilot.press("enter")
        await pilot.pause()
        assert app.state.target == "https://demo.lab"


async def test_target_prompt_can_be_cancelled(tui_config):
    """Escaping the prompt leaves the previous target alone."""
    app = PynzorApp(tui_config, target="https://keep.me")
    async with app.run_test() as pilot:
        await focus(pilot, app, "status")
        await pilot.press("enter")
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
        assert app.state.target == "https://keep.me"


async def test_quit_while_running_asks_first(tui_config, monkeypatch):
    """`q` mid-scan confirms rather than dropping the run on the floor."""
    import asyncio

    from pynzor.core import runner

    started = asyncio.Event()

    async def never_finishes(*args, **kwargs):
        started.set()
        await asyncio.sleep(3600)

    # Patched on the runner module itself: `ModuleSpec.runner` resolves by name
    # at call time, so this reaches the dashboard whichever module imports it.
    monkeypatch.setattr(runner, "run_headers", never_finishes)

    app = PynzorApp(tui_config, target="https://demo.invalid")
    async with app.run_test() as pilot:
        only(app, "headers")
        await focus(pilot, app)
        await pilot.press("r")
        await asyncio.wait_for(started.wait(), timeout=5)

        await pilot.press("q")
        await pilot.pause()
        assert isinstance(app.screen, ConfirmScreen)

        await pilot.press("escape")
        await pilot.pause()
        assert app.is_running
        assert app.running

        await pilot.press("s")
        await pilot.pause()


async def test_option_editing_toggles_and_resets(tui_config):
    """Options are a panel: `enter` flips a switch, `d` restores the default."""
    app = PynzorApp(tui_config)
    async with app.run_test() as pilot:
        await focus(pilot, app, "modules")
        await focus(pilot, app, "options")
        # Ports' third option is the service-detection switch.
        await pilot.press("j", "j")
        await pilot.pause()
        row = app.options_panel.selected()
        assert row is not None and row.spec.kind == "bool"

        before = bool(row.module.options[row.spec.key])
        await pilot.press("enter")
        await pilot.pause()
        assert bool(row.module.options[row.spec.key]) is not before

        await pilot.press("d")
        await pilot.pause()
        assert row.module.options[row.spec.key] == app.options_panel.default_for(row)


async def test_options_seed_from_config(tui_config):
    """The form is seeded from config.yaml, not from hardcoded values."""
    app = PynzorApp(tui_config)
    async with app.run_test() as pilot:
        await pilot.pause()
        await app.options_panel.show_module(app.state.modules["subdomain"])
        await pilot.pause()
        values = {row.spec.key: row.value_text() for row in app.options_panel.query("OptionRow")}
        assert values["threads"] == str(tui_config["subdomain"]["threads"])


async def test_filter_hides_non_matching_rows(tui_config):
    """`/` narrows a list panel without destroying its rows."""
    app = PynzorApp(tui_config)
    async with app.run_test() as pilot:
        await focus(pilot, app, "modules")
        await pilot.press("/")
        await pilot.pause()
        await pilot.press(*"fuzz")
        await pilot.press("enter")
        await pilot.pause()

        rows = app.modules_panel.list_view.children
        shown = [row for row in rows if row.display]
        assert len(shown) == 1
        # Hidden, not removed: a running module still repaints into its row.
        assert len(rows) == 6


# -------------------------------------------------------------- keymap drift


def test_every_binding_comes_from_the_keymap():
    """Nothing may be bound outside the one table that documents the keys.

    This replaces the old help-vs-bindings drift guard. There is nothing left
    to drift: the bindings, the hint bar, the menu, and the cheatsheet are all
    generated from `keymap`, and this asserts nobody has hand-written a
    `Binding` around it.
    """
    documented = keymap.documented_actions()

    for binding in PynzorApp.BINDINGS:
        assert not isinstance(binding, tuple)
        assert binding.action.removeprefix("app.") in documented, binding.action

    for panel_type in keymap.PANEL_ORDER:
        for binding in keymap.bindings_for(panel_type):
            assert binding.action.removeprefix("app.") in documented, binding.action


def test_every_bound_action_exists_on_the_app():
    """A key that names an action the app does not have is a silent no-op."""
    for key in keymap.all_keys():
        name = key.action.removeprefix("app.").split("(")[0]
        assert hasattr(PynzorApp, f"action_{name}"), f"{key.keys} -> action_{name} is missing"


def test_every_panel_is_described_by_the_keymap():
    """A panel without a keymap entry has no title and no contextual keys."""
    from pynzor.tui.panels import PANEL_TYPES

    assert tuple(p.panel_id for p in PANEL_TYPES) == keymap.PANEL_ORDER
    for panel_id in keymap.PANEL_ORDER:
        assert panel_id in keymap.PANEL_TITLES


def test_docs_table_matches_the_keymap():
    """The docs' key table is the third copy, and the one nothing watched.

    It is generated from `keymap` now, so this asserts it was regenerated --
    a key added without touching `docs/dashboard.md` fails here rather than
    silently documenting the wrong thing.

    The README carries a short subset of the same table for the front page.
    That one is only asserted to be a subset: it is allowed to list fewer keys
    than the keymap, but never a key the keymap does not bind, and never a
    stale label for one it does.
    """
    import re

    root = pathlib.Path(__file__).resolve().parents[1]
    pattern = r"^\| `(.+?)` \| (.+?) \| (.+?) \|$"
    expected = {(shown, group, label) for group, rows in keymap.sections() for shown, label in rows}

    reference = (root / "docs" / "dashboard.md").read_text()
    documented = set(re.findall(pattern, reference, re.MULTILINE))
    assert documented == expected

    readme = (root / "README.md").read_text()
    highlighted = set(re.findall(pattern, readme, re.MULTILINE))
    assert highlighted, "the README lists no keys at all"
    assert highlighted <= expected


def test_readme_screenshot_is_committed_and_linked():
    """The README's dashboard image must exist in the repo and be referenced.

    The README is also the PyPI long description (`pyproject.toml` sets
    `readme`), and PyPI does not resolve relative paths against the repo -- so
    the image is referenced by absolute raw URL. That makes the link
    unverifiable offline in both directions: a rename would leave a broken
    image on the project's front page, and nothing local would notice. This
    pins the two ends together.
    """
    root = pathlib.Path(__file__).resolve().parents[1]
    relative = "docs/images/dashboard.svg"

    assert (root / relative).is_file(), f"{relative} is missing"
    assert (root / "docs/images/make_screenshot.py").is_file(), "generator is missing"

    readme = (root / "README.md").read_text()
    assert relative in readme, "README does not reference the screenshot"
    # Absolute, not relative: a relative path renders broken on PyPI.
    assert f"https://raw.githubusercontent.com/yal212/Pynzor/main/{relative}" in readme

    svg = (root / relative).read_text()
    assert svg.lstrip().startswith("<svg"), "screenshot is not an SVG"
    # Generated from a real run against a local fixture, so it must not carry
    # anything from the machine that produced it.
    for leak in ("/Users/", "/home/", "/var/folders", "C:\\"):
        assert leak not in svg, f"screenshot leaks a local path: {leak}"


def test_cheatsheet_covers_every_key():
    """Every key in the table reaches the `?` card."""
    listed = {cell for _, rows in keymap.sections() for cell, _ in rows}
    assert listed == {key.shown for key in keymap.all_keys()}


# ------------------------------------------------------------------ geometry


async def test_layout_fits_eighty_by_twentyfour(tui_config):
    """Every panel stays visible and usable at the smallest terminal we target.

    lazygit keeps all five panels open and lets them share the height
    (expandFocusedSidePanel: false), so what has to hold here is that the
    share each one gets is still readable -- not that the focused one is
    bigger, which it deliberately no longer is. `size` is Textual's content
    box, so the outer box is what has to add up to the screen.

    At 80x24: 23 body rows, 4 of them Status, the remaining 19 split four ways.
    """
    app = PynzorApp(tui_config)
    async with app.run_test(size=(80, 24)) as pilot:
        await focus(pilot, app, "modules")

        panels = list(app.query(SidePanel))
        assert len(panels) == len(keymap.PANEL_ORDER)
        for panel in panels:
            # Border plus at least one body row: a panel you cannot read is
            # the same as a panel that is not there.
            assert panel.outer_size.height >= 3, f"{panel.panel_id} collapsed away"
            assert panel.size.height >= 1
            assert panel.size.width > 0

        # Focus changes the border, not the geometry. Tabbing between panels
        # must not reflow the column -- that jump is the thing the accordion
        # traded away readability for.
        heights = {p.panel_id: p.outer_size.height for p in panels}
        await focus(pilot, app, "reports")
        assert {p.panel_id: p.outer_size.height for p in app.query(SidePanel)} == heights

        # The column has to exactly fill the body, with nothing clipped.
        assert sum(p.outer_size.height for p in panels) == app.query_one("#body").size.height

        assert app.query_one(HintBar).size.height == 1
        assert app.query_one(CommandLog).outer_size.height == 5
        assert app.main.size.height > 0
        # Two lines of Status survive at the smallest size: target and counts.
        assert app.panel("status").size.height == 2


async def test_nothing_paints_over_the_terminal_background(tui_config):
    """The dashboard is see-through: no cell carries an opaque background.

    This is the one that guards the look. Textual's trap is that
    `background: transparent` is alpha-0 black and paints over the terminal,
    so the only thing that actually shows through is an ANSI colour -- and a
    single hex value anywhere in theme.py or styles.tcss silently takes the
    transparency away again with nothing else failing.

    Every segment must be either unstyled or ANSI: `ColorType.DEFAULT` for the
    terminal's own background, or a `STANDARD` ANSI index for a deliberate
    highlight like the selected row.
    """
    from rich.color import ColorType

    app = PynzorApp(tui_config)
    async with app.run_test(size=(80, 24)) as pilot:
        await focus(pilot, app, "modules")

        assert app.native_ansi_color, "theme must keep ansi=True"
        assert "ansi" in app.get_pseudo_classes()
        assert app.screen.styles.background.ansi == -1

        allowed = {ColorType.DEFAULT, ColorType.STANDARD}
        offenders = set()
        for strip in app.screen._compositor.render_strips():
            for segment in strip:
                style = segment.style
                if style is None:
                    continue
                for colour in (style.bgcolor, style.color):
                    if colour is not None and colour.type not in allowed:
                        offenders.add(str(colour))
        assert not offenders, f"opaque colours painted over the terminal: {offenders}"


async def test_focus_is_marked_the_way_lazygit_marks_it(tui_config):
    """Green border and a blue cursor row on the focused panel; neither elsewhere.

    lazygit's activeBorderColor is green, selectedLineBgColor blue, and
    inactiveViewSelectedLineBgColor is `bold` -- an unfocused panel marks its
    cursor with weight and no fill, so five panels cannot all look focused.

    The cursor class is Textual's `-highlight`, one dash. A stylesheet that
    spells it with two matches nothing and the rules here silently do nothing,
    which is how it was broken before.
    """
    from textual.widgets import ListItem, ListView

    green, blue, default = 2, 4, -1
    app = PynzorApp(tui_config)
    async with app.run_test(size=(80, 24)) as pilot:
        # modules and options, because both always have rows: the module list
        # is fixed and the option form follows the module cursor. Findings and
        # Reports are empty until something has run.
        for focused in ("modules", "options"):
            await focus(pilot, app, focused)
            for panel_id in ("modules", "options"):
                panel = app.panel(panel_id)
                cursors = [
                    item
                    for item in app.query_one(f"#list-{panel_id}", ListView).query(ListItem)
                    if "-highlight" in item.classes
                ]
                assert cursors, f"{panel_id} has no cursor row"
                border = panel.styles.border_top[1]
                background = cursors[0].styles.background
                if panel_id == focused:
                    assert border.ansi == green
                    assert background.ansi == blue
                else:
                    assert border.ansi == default
                    assert background.ansi == default
                    assert "bold" in str(cursors[0].styles.text_style)


async def test_panel_borders_carry_their_jump_number(tui_config):
    """showPanelJumps: the digit that focuses a panel is drawn in its border."""
    app = PynzorApp(tui_config)
    async with app.run_test() as pilot:
        await pilot.pause()
        for index, panel_id in enumerate(keymap.PANEL_ORDER, start=1):
            title = str(app.panel(panel_id).border_title)
            assert title.startswith(f"{index} "), title
            assert keymap.PANEL_TITLES[panel_id] in title

        # A panel that re-titles itself as its context changes keeps the number.
        await focus(pilot, app, "options")
        assert str(app.panel("options").border_title).startswith("3 Options")


async def test_hint_bar_and_brand_share_the_bottom_row(tui_config):
    """Both halves of the bar get painted; one docked over the other loses one."""
    app = PynzorApp(tui_config)
    async with app.run_test(size=(100, 34)) as pilot:
        await pilot.pause()
        assert app.query_one("#hints").size.height == 1
        assert app.query_one("#brand").size.width > 0


async def test_headline_row_has_height(http_fixture, tui_config):
    """The verdict line needs a content row; padding once collapsed it to zero."""
    app = PynzorApp(tui_config, target=http_fixture)
    async with app.run_test(size=(100, 34)) as pilot:
        only(app, "headers")
        await run_and_wait(pilot, app)
        # Only the displayed pane is laid out, so bring the one under test up.
        app.main.show_module(app.state.modules["headers"], "findings")
        await pilot.pause()
        assert app.pane("headers").query_one(".pane-headline").size.height >= 1
        assert headline("headers", app.state.modules["headers"].result)


async def test_streamed_rows_are_not_duplicated_by_the_rebuild(
    http_fixture, tui_config, test_wordlist
):
    """Rows buffered mid-run must not be re-appended after the rebuild."""
    app = PynzorApp(tui_config, target=http_fixture)
    async with app.run_test() as pilot:
        only(app, "fuzz")
        app.state.modules["fuzz"].options["wordlist"] = str(test_wordlist)
        await run_and_wait(pilot, app)

        module = app.state.modules["fuzz"]
        assert not module.pending_rows
        assert len(module.rows) == len(module.report["findings"])
        assert len(module.table_rows) == len(module.rows)
        assert app.pane("fuzz").table.row_count == len(module.rows)


# --------------------------------------------------------------- pure helpers


def test_preview_collapses_to_a_single_scan(tui_config):
    """All modules at their defaults is just `Pynzor scan`."""
    state = SessionState(config=tui_config, target="https://demo.lab")
    assert preview(state) == "Pynzor scan -t https://demo.lab -f both"


def test_preview_shows_only_changed_flags(tui_config):
    """A non-default option appears; everything left at its default does not."""
    state = SessionState(config=tui_config, target="https://demo.lab")
    for module_id in ("fuzz", "headers", "sqli", "xss", "subdomain"):
        state.modules[module_id].selected = False
    state.modules["ports"].options["service_detection"] = True

    line = preview(state)
    assert line == "Pynzor ports -t https://demo.lab -sV"
    assert "--threads" not in line


def test_preview_without_a_target_is_still_readable(tui_config):
    """An empty target renders a placeholder rather than a broken command."""
    assert "<target>" in preview(SessionState(config=tui_config))


def test_row_for_skips_non_findings():
    """Closed ports and empty probe units never become table rows."""

    class Port:
        port, status, service, product, version = 80, "closed", "http", None, None

    assert row_for("ports", Port()) is None
    assert row_for("sqli", None) is None
    assert row_for("nonexistent", object()) is None


def test_detail_lines_expand_a_finding():
    """The drill-down shows fields the summary table clips, and skips blanks."""
    from pynzor.modules.sqli import SQLiVulnerability

    pairs = dict(
        detail_lines(
            SQLiVulnerability(
                url="http://x/?id=1", payload="' OR 1=1--", type="error-based", evidence=""
            )
        )
    )
    assert pairs["payload"] == "' OR 1=1--"
    assert "evidence" not in pairs  # empty fields are omitted


def test_headline_summarises_each_module():
    """Each module gets a one-line verdict above its table."""
    from datetime import datetime

    from pynzor.modules.headers import HeaderResult

    now = datetime.now()
    result = HeaderResult(target="x", start_time=now, end_time=now, score=40, grade="F")
    assert headline("headers", result) == "score 40/100 — grade F"
    assert headline("headers", None) == ""


def test_finding_ref_summary_names_its_module():
    """A flat cross-module row has to say which module it came from."""
    from pynzor.tui.state import FindingRef

    ref = FindingRef("ports", "Ports", 0, object(), ("80", "open", "http", "-"))
    assert ref.summary.startswith("Ports")
    assert "80" in ref.summary


def test_finding_ref_summary_drops_uninformative_cells():
    """A yes/no column identifies nothing and only eats width in the panel."""
    from pynzor.tui.state import FindingRef

    ref = FindingRef("headers", "Headers", 0, object(), ("X-Frame-Options", "no", "high", "DENY"))
    assert ref.summary == "Headers  X-Frame-Options"


def test_session_log_is_bounded():
    """A long session must not grow the command log without limit."""
    state = SessionState(config={})
    for index in range(500):
        state.log(str(index))
    assert len(state.command_log) == 200
    assert state.command_log[-1] == "499"


def test_is_interactive_is_false_under_pytest():
    """Captured stdio must never be mistaken for a terminal."""
    assert is_interactive() is False


# ------------------------------------------------------------- layout budget


@pytest.fixture
def layout_counter(monkeypatch):
    """Count full-screen layout passes, the thing that made the UI lag.

    `Static.update()` defaults to `layout=True`, so a single careless update
    in the progress path triggers a whole-screen relayout per event.
    """
    from textual.screen import Screen

    calls = {"n": 0}
    original = Screen._refresh_layout

    def counting(self, *args, **kwargs):
        calls["n"] += 1
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Screen, "_refresh_layout", counting)
    return calls


async def test_a_run_does_not_thrash_layout(http_fixture, tui_config, tmp_path, layout_counter):
    """A full fuzz run must not force a layout pass per progress event.

    Measured before the fix: 535 passes for a default run. After: 5. The
    wordlist has to be big enough to actually emit events -- a handful of
    words stays under the threshold even with the bug present.
    """
    wordlist = tmp_path / "many.txt"
    wordlist.write_text("\n".join(f"w{i}" for i in range(150)))

    app = PynzorApp(tui_config, target=http_fixture)
    async with app.run_test() as pilot:
        only(app, "fuzz")
        fuzz = app.state.modules["fuzz"]
        fuzz.options["wordlist"] = str(wordlist)
        fuzz.options["threads"] = 40
        await pilot.pause()
        layout_counter["n"] = 0
        await run_and_wait(pilot, app)
        # The config's extensions multiply the wordlist, so this is well over
        # a thousand progress events -- enough for the bug to show.
        assert fuzz.done == fuzz.total > 1000

    assert app.state.modules["fuzz"].status is Status.DONE
    assert layout_counter["n"] < 50, (
        f"{layout_counter['n']} layout passes for one run — a Static.update() "
        "in the progress path is missing layout=False"
    )


async def test_ui_cost_does_not_scale_with_event_count(
    http_fixture, tui_config, tmp_path, layout_counter
):
    """Painting is on a timer, so a 20x bigger wordlist must not cost 20x."""

    async def layout_passes_for(words: int) -> int:
        wordlist = tmp_path / f"wl{words}.txt"
        wordlist.write_text("\n".join(f"w{i}" for i in range(words)))
        app = PynzorApp(tui_config, target=http_fixture)
        async with app.run_test() as pilot:
            only(app, "fuzz")
            fuzz = app.state.modules["fuzz"]
            fuzz.options["wordlist"] = str(wordlist)
            fuzz.options["threads"] = 40
            await pilot.pause()
            layout_counter["n"] = 0
            await run_and_wait(pilot, app)
            assert fuzz.done == fuzz.total
            return layout_counter["n"]

    small = await layout_passes_for(10)
    large = await layout_passes_for(200)

    # 20x the events must not mean anything like 20x the layout work.
    assert large <= small + 20, f"{small} -> {large} layout passes for 20x the events"
