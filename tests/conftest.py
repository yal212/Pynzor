import pytest
import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit


class _FixtureHandler(BaseHTTPRequestHandler):
    """Deterministic canned responses for command-level integration tests.

    No external network is touched: every route returns a fixed body so the
    security modules produce predictable findings.
    """

    def log_message(self, format, *args):  # silence per-request stderr logging
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
            # Error-based SQLi signature the module matches on.
            self._send(200, "<html>You have an error in your SQL syntax near '1'</html>")
        elif path == "/xss":
            # Reflect the raw query so injected payloads appear verbatim.
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
            # Unknown paths (incl. fuzzer baseline probes) 404 so they aren't
            # treated as catch-all hits.
            self._send(404, "<html>not found</html>")


@pytest.fixture
def http_fixture():
    """Run a local HTTP server on 127.0.0.1 and yield its base URL."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[0], server.server_address[1]
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture
def event_loop():
    """Provide a fresh asyncio event loop for async tests and close it after."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def test_wordlist(tmp_path):
    """Write a small temp wordlist file and return its path."""
    wordlist = tmp_path / "test-wordlist.txt"
    wordlist.write_text("/admin\n/login\n/test\n")
    return wordlist


@pytest.fixture
def config():
    """Return a representative config dict for tests."""
    return {
        "http": {
            "timeout": 10,
            "max_retries": 3,
            "rate_limit": 0.1,
            "user_agent": "TestAgent/1.0",
            "follow_redirects": True,
            "verify_ssl": False,
            "max_redirects": 5,
        },
        "scanner": {
            "common_ports": [80, 443],
            "timeout": 3,
            "concurrent": 50,
        },
        "fuzzer": {
            "threads": 5,
            "status_codes": [200, 403],
            "extensions": [".php", ".html"],
            "wordlist": "wordlists/common-dirs.txt",
        },
    }
