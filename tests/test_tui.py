"""Pilot-driven tests for the dashboard.

Drives the real Textual app against the local HTTP fixture: no mocked runner,
so these cover the whole path from a keypress to an exported report envelope.
"""

import json

import pytest
from textual.widgets import Input, ListView, TabbedContent

from pynzor.cli.main import is_interactive
from pynzor.core.config import load_config
from pynzor.tui.app import PynzorApp
from pynzor.tui.keymap import HelpScreen, keymap_keys
from pynzor.tui.preview import preview
from pynzor.tui.rows import detail_lines, headline, row_for
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


async def focus_rail(pilot, app: PynzorApp) -> None:
    """Put focus on the module rail.

    A no-op since the app mounts in normal mode, but kept so each test stays
    explicit about needing single-key bindings to be reachable.
    """
    app.query_one("#modules").focus()
    await pilot.pause()


async def run_and_wait(pilot, app: PynzorApp) -> None:
    """Press run, then wait for every module worker to finish."""
    await focus_rail(pilot, app)
    await pilot.press("r")
    await app.workers.wait_for_complete()
    await pilot.pause()


async def test_mounts_with_every_module(tui_config):
    """The rail lists all six modules, idle and selected."""
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
        await focus_rail(pilot, app)
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

    from pynzor.tui import app as app_module

    started = asyncio.Event()

    async def never_finishes(*args, **kwargs):
        started.set()
        await asyncio.sleep(3600)

    monkeypatch.setattr(app_module.runner, "run_headers", never_finishes)

    app = PynzorApp(tui_config, target="https://demo.invalid")
    async with app.run_test() as pilot:
        only(app, "headers")
        await focus_rail(pilot, app)
        await pilot.press("r")
        await asyncio.wait_for(started.wait(), timeout=5)
        assert app.running
        assert app.state.modules["headers"].status is Status.RUNNING

        await pilot.press("s")
        await pilot.pause()

        assert not app.running
        assert app.state.modules["headers"].status is Status.CANCELLED
        assert "Stopped" in app._status


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
        await focus_rail(pilot, app)
        await pilot.press("e")
        await pilot.pause()
        assert "Nothing to export" in app._status


async def test_report_browser_loads_a_saved_report(http_fixture, tui_config, tmp_path):
    """A saved report can be reopened from the browser into the detail pane."""
    app = PynzorApp(tui_config, target=http_fixture)
    async with app.run_test() as pilot:
        only(app, "headers")
        await run_and_wait(pilot, app)
        await pilot.press("e")
        await pilot.pause()

        await pilot.press("b")
        await pilot.pause()

        saved = sorted((tmp_path / "reports").glob("headers_*.json"))[0]
        app.open_report_path(saved)
        await pilot.pause()

        detail = app.detail_text
        assert saved.name in detail
        assert "module   : headers" in detail


async def test_report_browser_rejects_a_bad_schema(tui_config, tmp_path):
    """An unknown schema_version is reported, not rendered as if it were fine."""
    reports = tmp_path / "reports"
    reports.mkdir(parents=True)
    bad = reports / "headers_20990101_000000.json"
    bad.write_text(json.dumps({"schema_version": 99, "module": "headers", "findings": []}))

    app = PynzorApp(tui_config)
    async with app.run_test() as pilot:
        await pilot.press("b")
        await pilot.pause()
        app.open_report_path(bad)
        await pilot.pause()
        assert "schema_version 99" in app._status


async def test_toggle_deselects_a_module(tui_config):
    """Space toggles the highlighted module out of the next run."""
    app = PynzorApp(tui_config)
    async with app.run_test() as pilot:
        await focus_rail(pilot, app)
        await pilot.press("space")
        await pilot.pause()
        assert len(app.state.selected_modules) == 5


async def test_starts_in_normal_mode(tui_config):
    """Letters must be commands on mount, not text.

    The target Input used to grab focus and swallow every printable key, so
    `r`, `space`, and `o` silently did nothing until focus moved.
    """
    app = PynzorApp(tui_config)
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app.focused is app.query_one("#modules")
        assert app.mode == "NORMAL"

        await pilot.press("i")
        await pilot.pause()
        assert app.focused is app.query_one("#target", Input)
        assert app.mode == "INSERT"

        await pilot.press("escape")
        await pilot.pause()
        assert app.focused is app.query_one("#modules")
        assert app.mode == "NORMAL"


async def test_jk_and_gG_move_the_rail_cursor(tui_config):
    """hjkl navigation drives the rail without touching the arrow keys."""
    app = PynzorApp(tui_config)
    async with app.run_test() as pilot:
        await focus_rail(pilot, app)
        rail = app.query_one("#modules", ListView)

        await pilot.press("j", "j", "k")
        await pilot.pause()
        assert rail.index == 1

        await pilot.press("G")
        await pilot.pause()
        assert rail.index == len(app.state.modules) - 1

        await pilot.press("g")
        await pilot.pause()
        assert rail.index == 0


async def test_hl_switches_panels(tui_config):
    """`l` moves into the results panel and `h` comes back to the rail."""
    app = PynzorApp(tui_config)
    async with app.run_test() as pilot:
        await focus_rail(pilot, app)

        await pilot.press("l")
        await pilot.pause()
        focused = app.focused
        assert focused is not None
        assert app.query_one("#main") in focused.ancestors

        await pilot.press("h")
        await pilot.pause()
        assert app.focused is app.query_one("#modules")


async def test_brackets_switch_tabs(tui_config):
    """`[` and `]` cycle result tabs, so the mouse is never required."""
    app = PynzorApp(tui_config)
    async with app.run_test() as pilot:
        await focus_rail(pilot, app)
        tabs = app.query_one("#tabs", TabbedContent)
        first = tabs.active

        await pilot.press("]")
        await pilot.pause()
        assert tabs.active != first

        await pilot.press("[")
        await pilot.pause()
        assert tabs.active == first


async def test_help_overlay_opens_and_closes(tui_config):
    """`?` shows the cheatsheet and Esc dismisses it."""
    app = PynzorApp(tui_config)
    async with app.run_test() as pilot:
        await focus_rail(pilot, app)

        await pilot.press("?")
        await pilot.pause()
        assert isinstance(app.screen, HelpScreen)

        await pilot.press("escape")
        await pilot.pause()
        assert not isinstance(app.screen, HelpScreen)


def test_help_documents_every_binding():
    """Guard against help text drifting away from the bindings it describes.

    Arrow and shifted aliases are excluded: they exist so muscle memory works,
    not because they are worth a line in the cheatsheet.
    """
    aliases = {"down", "up", "tab", "H", "L"}
    documented = keymap_keys()
    for binding in PynzorApp.BINDINGS:
        assert not isinstance(binding, tuple)
        for key in binding.key.split(","):
            key = key.strip()
            if key in aliases:
                continue
            assert key in documented, f"{key} is bound but missing from KEYMAP"


async def test_enter_on_a_finding_opens_detail(http_fixture, tui_config):
    """Drilling in has to be visible: Detail sits behind the module tabs."""
    app = PynzorApp(tui_config, target=http_fixture)
    async with app.run_test() as pilot:
        only(app, "headers")
        await run_and_wait(pilot, app)

        table = app.pane("headers").table
        assert table.row_count
        table.focus()
        await pilot.press("enter")
        await pilot.pause()
        assert app.query_one("#tabs", TabbedContent).active == "tab-detail"
        assert app.detail_text


async def test_options_panel_seeds_from_config(tui_config):
    """Opening options renders a field per option, seeded from config.yaml."""
    app = PynzorApp(tui_config)
    async with app.run_test() as pilot:
        await pilot.pause()
        app.build_options(app.state.modules["subdomain"])
        await pilot.pause()
        threads = app.query_one("#opt-subdomain-threads")
        assert threads.value == str(tui_config["subdomain"]["threads"])


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
    from pynzor.modules.headers import HeaderResult
    from datetime import datetime

    now = datetime.now()
    result = HeaderResult(target="x", start_time=now, end_time=now, score=40, grade="F")
    assert headline("headers", result) == "score 40/100 — grade F"
    assert headline("headers", None) == ""


def test_is_interactive_is_false_under_pytest():
    """Captured stdio must never be mistaken for a terminal."""
    assert is_interactive() is False


async def test_status_and_preview_lines_are_visible(http_fixture, tui_config):
    """Both footer lines get a row: docking them separately silently drops one."""
    app = PynzorApp(tui_config, target=http_fixture)
    async with app.run_test(size=(100, 34)) as pilot:
        await pilot.pause()
        assert app.query_one("#status").size.height == 1
        assert app.query_one("#preview").size.height == 1


async def test_headline_row_has_height(http_fixture, tui_config):
    """The verdict line needs a content row; padding once collapsed it to zero."""
    app = PynzorApp(tui_config, target=http_fixture)
    async with app.run_test(size=(100, 34)) as pilot:
        only(app, "headers")
        await run_and_wait(pilot, app)
        # Only the active tab is laid out, so switch to the one under test.
        app.query_one("#tabs", TabbedContent).active = "tab-headers"
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
        assert app.pane("fuzz").table.row_count == len(module.rows)


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
