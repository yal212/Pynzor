#!/usr/bin/env python3
"""Generate the Pynzor terminal demo as an asciinema v2 cast.

The demo runs the real CLI against a local HTTP fixture on ``127.0.0.1`` — no
external network is touched and no public target is scanned. Each command's
actual output is captured and written into a replayable ``.cast`` file.

Usage::

    uv run python docs/demo/record_demo.py

This writes ``docs/demo/pynzor-demo.cast`` next to this script. Replay it with
the asciinema player (``asciinema play docs/demo/pynzor-demo.cast``) or upload
it to https://asciinema.org. The cast is synthesized from captured output, so
the ``asciinema`` binary is not required to *generate* it.

The fixture routes below mirror ``tests/conftest.py`` so the demo stays in sync
with the integration-test target.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

CAST_PATH = Path(__file__).resolve().parent / "pynzor-demo.cast"
TERM_WIDTH = 100
TERM_HEIGHT = 32
PROMPT = "$ "

# Timing (seconds) used to lay out the synthesized cast.
TYPE_DELAY = 0.04  # per-character "typing" of a command
PAUSE_AFTER_CMD = 0.4  # beat before output appears
PAUSE_BETWEEN = 1.2  # beat before the next prompt


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
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = str(server.server_address[0]), server.server_address[1]
    return server, thread, host, port


def run(argv: list[str]) -> str:
    """Run ``python -m pynzor`` with ``argv`` and return combined output."""
    result = subprocess.run(
        [sys.executable, "-m", "pynzor", *argv],
        capture_output=True,
        text=True,
    )
    return result.stdout + result.stderr


class CastWriter:
    """Accumulate asciinema v2 output events with monotonically rising time."""

    def __init__(self) -> None:
        self.events: list[list] = []
        self.t = 0.0

    def _emit(self, text: str) -> None:
        self.events.append([round(self.t, 3), "o", text])

    def wait(self, seconds: float) -> None:
        self.t += seconds

    def type_command(self, command: str) -> None:
        """Render the prompt, then the command 'typed' one character at a time."""
        self._emit(PROMPT)
        self.wait(0.3)
        for char in command:
            self._emit(char)
            self.wait(TYPE_DELAY)
        self._emit("\r\n")
        self.wait(PAUSE_AFTER_CMD)

    def output(self, text: str) -> None:
        if not text:
            return
        self._emit(text if text.endswith("\n") else text + "\n")
        self.wait(PAUSE_BETWEEN)

    def write(self, path: Path) -> None:
        header = {
            "version": 2,
            "width": TERM_WIDTH,
            "height": TERM_HEIGHT,
            "timestamp": int(time.time()),
            "title": "Pynzor recon demo",
            "env": {"TERM": "xterm-256color", "SHELL": "/bin/bash"},
        }
        lines = [json.dumps(header)]
        lines.extend(json.dumps(event) for event in self.events)
        path.write_text("\n".join(lines) + "\n")


def build_cast(base_url: str, port: int, workdir: Path) -> CastWriter:
    """Drive the CLI against the fixture and record the session."""
    reports = workdir / "reports"
    cast = CastWriter()

    # 1. Install / help
    cast.type_command("pynzor --version")
    cast.output(run(["--version"]))

    # 2. Security headers
    cast.type_command(f"pynzor headers -t {base_url} -o reports")
    cast.output(run(["headers", "-t", base_url, "-o", str(reports), "--no-color"]))

    # 3. Port scan (the fixture's own port is open)
    cast.type_command(f"pynzor ports -t 127.0.0.1 -p {port} -o reports")
    cast.output(run(["ports", "-t", "127.0.0.1", "-p", str(port), "-o", str(reports), "--no-color"]))

    # 4. Directory fuzzing against a small wordlist (/admin is served)
    wordlist = workdir / "demo-wordlist.txt"
    wordlist.write_text("admin\nlogin\ndashboard\n")
    cast.type_command(f"pynzor fuzz -t {base_url} -w demo-wordlist.txt --threads 5 -o reports")
    cast.output(
        run(["fuzz", "-t", base_url, "-w", str(wordlist), "--threads", "5", "-o", str(reports), "--no-color"])
    )

    # 5. Report review — print the headers JSON report that was just written
    header_reports = sorted(reports.glob("headers_*.json"))
    if header_reports:
        rel = header_reports[-1].name
        cast.type_command(f"pynzor report reports/{rel}")
        cast.output(run(["report", str(header_reports[-1])]))

    return cast


def main() -> int:
    server, thread, host, port = start_fixture()
    base_url = f"http://{host}:{port}"
    try:
        with tempfile.TemporaryDirectory() as tmp:
            cast = build_cast(base_url, port, Path(tmp))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    cast.write(CAST_PATH)
    print(f"Wrote {CAST_PATH} ({len(cast.events)} events)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
