#!/usr/bin/env python3
"""Generate the dashboard screenshot used in README.md.

Runs the real dashboard headlessly against a local HTTP fixture on
``127.0.0.1`` -- no external network is touched and no public target is
scanned -- lets a scan finish so the panels have real content in them, and
exports what Textual actually rendered as an SVG.

Usage::

    uv run python docs/images/make_screenshot.py

This writes ``docs/images/dashboard.svg`` next to this script. Regenerate it
whenever the dashboard's layout or palette changes, so the README shows the
program rather than a drawing of it.

The fixture routes mirror ``tests/conftest.py``, the same way
``docs/demo/record_demo.py`` does, so the screenshot stays in sync with what
the integration tests scan.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

from rich.terminal_theme import TerminalTheme
from textual.containers import VerticalScroll

# Run against the working tree, not whatever happens to be installed, so the
# screenshot always shows the code sitting next to it.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from pynzor.core.config import load_config  # noqa: E402
from pynzor.tui.app import PynzorApp  # noqa: E402

SVG_PATH = Path(__file__).resolve().parent / "dashboard.svg"

#: Comfortably larger than the 80x24 minimum the layout is designed to survive.
#: At 80x24 the Modules panel is down to two visible rows, which is honest but
#: reads as cramped at README scale.
TERM_WIDTH = 100
TERM_HEIGHT = 30

#: The modules to run. Headers and fuzz between them fill every panel the
#: screenshot is meant to show: a progress bar, a findings table with real
#: rows, the flattened findings list, and a populated command log.
MODULES = ("headers", "fuzz")

#: Preferred fixture port. Fixed rather than ephemeral so the target URL in the
#: image -- and therefore the committed file -- does not change on every run.
#: Falls back to an ephemeral port if this one is busy, which only costs a
#: noisier diff.
PREFERRED_PORT = 8771

#: A small wordlist, written into the run's temp directory and referenced by a
#: bare relative name. Two reasons, both visible in the screenshot: the bundled
#: wordlist's absolute path would render the author's home directory into the
#: Options panel, and 3000 requests against a canned fixture takes far longer
#: than the handful needed to produce a findings table.
#: `admin`, `sqli` and `xss` are the three paths the fixture above actually
#: serves, so the results table has rows in it; the rest are realistic misses.
#: Chosen to suit the fixture rather than extending the fixture to suit the
#: screenshot, which would drift from ``tests/conftest.py``.
WORDLIST = (
    "admin",
    "sqli",
    "login",
    "xss",
    "backup",
    "config",
    "api",
    ".git",
    "robots.txt",
    "private",
)

#: The palette the screenshot is rendered in.
#:
#: The dashboard has no colours of its own -- theme.py sets every surface to
#: `ansi_default` so the terminal supplies them -- and an SVG has no terminal to
#: inherit from, so something has to decide. Left alone, Rich's SVG export theme
#: decides, and picks a washed-out grey. Textual's own default (MONOKAI) renders
#: ANSI blue as violet, which contradicts the "blue marks the selected row" the
#: README describes. So the choice is made here, explicitly: a dark terminal with
#: an honest blue and green.
SCREENSHOT_THEME = TerminalTheme(
    (13, 17, 23),  # background
    (201, 209, 217),  # foreground
    [
        (48, 54, 61),  # black
        (248, 81, 73),  # red
        (86, 211, 100),  # green   -- focused panel border
        (210, 153, 34),  # yellow  -- module running
        (47, 108, 196),  # blue    -- selected row
        (188, 140, 255),  # magenta
        (57, 197, 207),  # cyan
        (201, 209, 217),  # white
    ],
    [
        (110, 118, 129),  # bright black -- muted text
        (255, 123, 114),  # bright red
        (126, 231, 135),  # bright green
        (227, 179, 65),  # bright yellow
        (84, 174, 255),  # bright blue
        (210, 168, 255),  # bright magenta
        (118, 224, 233),  # bright cyan
        (240, 246, 252),  # bright white
    ],
)


class _FixtureHandler(BaseHTTPRequestHandler):
    """Deterministic canned responses mirroring ``tests/conftest.py``."""

    def log_message(self, format, *args):  # silence per-request logging
        pass

    def _send(self, code: int, body: str, extra_headers: dict | None = None) -> None:
        payload = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):  # noqa: N802 - required BaseHTTPRequestHandler name
        parts = urlsplit(self.path)
        path, query = parts.path, unquote(parts.query)
        if path == "/sqli":
            self._send(200, "<html>You have an error in your SQL syntax near '1'</html>")
        elif path == "/xss":
            self._send(200, f"<html><body>Results for {query}</body></html>")
        elif path == "/admin":
            self._send(200, "<html>admin panel</html>")
        elif path == "/":
            self._send(
                200,
                "<html><body>home</body></html>",
                {"Content-Security-Policy": "default-src 'self'"},
            )
        else:
            self._send(404, "<html>not found</html>")


def start_fixture() -> tuple[ThreadingHTTPServer, threading.Thread, str, int]:
    """Start the local fixture server and return (server, thread, host, port)."""
    try:
        server = ThreadingHTTPServer(("127.0.0.1", PREFERRED_PORT), _FixtureHandler)
    except OSError:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = str(server.server_address[0]), server.server_address[1]
    return server, thread, host, port


async def capture(target: str, workdir: Path) -> str:
    """Run a scan in the real dashboard and return an SVG of the result.

    Drives the app the way ``tests/test_tui.py`` does -- ``run_test`` plus
    ``workers.wait_for_complete`` -- rather than screenshotting an idle screen,
    because an empty dashboard says very little about what the tool does.

    Everything the panels display is real output from that run. The only things
    arranged for the camera are which modules run, where the cursor is left,
    and the palette.
    """
    config = load_config()
    # Relative paths, resolved against `workdir`: an absolute one would render
    # a temp directory and the author's home directory into the screenshot.
    config["output"] = {"directory": "reports"}
    config["fuzzer"]["wordlist"] = "wordlist.txt"

    app = PynzorApp(config, target=target)
    async with app.run_test(size=(TERM_WIDTH, TERM_HEIGHT)) as pilot:
        for module_id, module in app.state.modules.items():
            module.selected = module_id in MODULES

        await pilot.press("2")  # Modules panel
        await pilot.pause()
        await pilot.press("r")  # run
        await app.workers.wait_for_complete()
        await pilot.pause()

        # Export, then reload the listing, so the Reports panel shows real
        # saved files instead of "no report directory".
        await app.run_action("export")
        await app.run_action("refresh_reports")
        await pilot.pause()

        # Back to Modules, cursor on a module that found something, so the main
        # panel shows a populated results table rather than the overview.
        await pilot.press("2")
        await pilot.press("j")
        await pilot.pause()

        # Exporting leaves a transient confirmation in the bottom row. Put the
        # contextual keybindings back -- they are the more useful thing for a
        # reader to see, and the row's whole point.
        app.refresh_hints()
        await pilot.pause()

        # The command log auto-scrolls to its newest line, which by now is the
        # export confirmation. Scroll back to the top so the `$ Pynzor ...`
        # lines are the ones on show -- that the dashboard tells you the exact
        # command to reproduce what it just did is the panel's whole point.
        app.query_one("#cmdlog-scroll", VerticalScroll).scroll_home(animate=False)
        await pilot.pause()

        # See SCREENSHOT_THEME. Setting `ansi_color = False` re-enables
        # Textual's ANSIToTruecolor filter, which is what resolves the
        # dashboard's ANSI colours through the theme below instead of leaving
        # them for Rich's export theme to flatten.
        app.ansi_theme_dark = SCREENSHOT_THEME
        app.ansi_color = False
        await pilot.pause()

        return app.export_screenshot(title="Pynzor")


def main() -> int:
    server, thread, host, port = start_fixture()
    original_cwd = Path.cwd()
    try:
        target = f"http://{host}:{port}"
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            (workdir / "wordlist.txt").write_text("\n".join(WORDLIST) + "\n")
            # The app resolves its relative config paths against the process
            # cwd, so run from the temp directory and put it back afterwards.
            os.chdir(workdir)
            try:
                svg = asyncio.run(capture(target, workdir))
            finally:
                os.chdir(original_cwd)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        with contextlib.suppress(OSError):
            os.chdir(original_cwd)

    SVG_PATH.write_text(svg, encoding="utf-8")
    print(f"Wrote {SVG_PATH} ({len(svg):,} bytes)")
    if port != PREFERRED_PORT:
        print(f"note: port {PREFERRED_PORT} was busy, so the image shows :{port}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
