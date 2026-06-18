import pytest
from modules import scanner


@pytest.mark.asyncio
async def test_port_scanner_localhost():
    """Scanning localhost with explicit ports returns results for that target."""
    result = await scanner.scan("127.0.0.1", ports=[80, 443], timeout=2.0)
    assert result.target == "127.0.0.1"
    assert len(result.ports) > 0


@pytest.mark.asyncio
async def test_port_scanner_no_target():
    """Scanning with default ports returns a non-None port list."""
    result = await scanner.scan("127.0.0.1")
    assert result.target == "127.0.0.1"
    assert result.ports is not None


def test_parse_ports_single_and_list():
    """parse_ports handles a single port and a comma-separated list (sorted)."""
    assert scanner.parse_ports("80") == [80]
    assert scanner.parse_ports("80,443,22") == [22, 80, 443]


def test_parse_ports_range():
    """parse_ports expands hyphenated ranges, alone and mixed with single ports."""
    assert scanner.parse_ports("78-81") == [78, 79, 80, 81]
    assert scanner.parse_ports("80,443,8000-8002") == [80, 443, 8000, 8001, 8002]


def test_parse_ports_dedup_and_clamp():
    """parse_ports deduplicates, clamps out-of-range ports, and tolerates reversed ranges."""
    assert scanner.parse_ports("80,80,443") == [80, 443]
    assert scanner.parse_ports("0,80,70000") == [80]
    assert scanner.parse_ports("85-83") == [83, 84, 85]  # reversed range tolerated


def test_parse_ports_clamps_huge_range():
    """An out-of-bounds range is clamped to 1-65535 instead of hanging the process."""
    result = scanner.parse_ports("1-100000000")
    assert result[0] == 1
    assert result[-1] == 65535
    assert len(result) == 65535
    # An open-ended-feeling upper bound still clamps to the max valid port.
    assert scanner.parse_ports("80-100000")[-1] == 65535


def test_parse_service_banner_ssh():
    """parse_service_banner extracts product and version from an OpenSSH banner."""
    product, version = scanner.parse_service_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu")
    assert product == "OpenSSH"
    assert version == "8.9p1"


def test_parse_service_banner_http_nginx():
    """parse_service_banner extracts product and version from an nginx Server header."""
    banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n"
    product, version = scanner.parse_service_banner(banner)
    assert product == "nginx"
    assert version == "1.18.0"


def test_parse_service_banner_ftp():
    """parse_service_banner extracts product and version from a ProFTPD banner."""
    product, version = scanner.parse_service_banner("220 ProFTPD 1.3.5 Server ready")
    assert product == "ProFTPD"
    assert version == "1.3.5"


def test_parse_service_banner_none():
    """parse_service_banner returns (None, None) for None or empty input."""
    assert scanner.parse_service_banner(None) == (None, None)
    assert scanner.parse_service_banner("") == (None, None)


class _FakeReader:
    def __init__(self, data: bytes):
        self._data = data

    async def read(self, n: int) -> bytes:
        return self._data


class _FakeWriter:
    def write(self, data):  # noqa: D401 - test stub
        pass

    async def drain(self):
        pass

    def close(self):
        pass

    async def wait_closed(self):
        pass


@pytest.mark.asyncio
async def test_grab_banner_reads_service_banner(monkeypatch):
    """grab_banner returns the banner text read from a connected socket."""
    async def fake_open_connection(host, port, ssl=None):
        return _FakeReader(b"SSH-2.0-OpenSSH_8.9p1\r\n"), _FakeWriter()

    monkeypatch.setattr(scanner.asyncio, "open_connection", fake_open_connection)
    banner = await scanner.grab_banner("host", 22, timeout=1.0)
    assert banner is not None
    assert "OpenSSH" in banner


@pytest.mark.asyncio
async def test_grab_banner_connection_failure_returns_none(monkeypatch):
    """grab_banner returns None when the connection cannot be established."""
    async def fake_open_connection(host, port, ssl=None):
        raise OSError("connection refused")

    monkeypatch.setattr(scanner.asyncio, "open_connection", fake_open_connection)
    assert await scanner.grab_banner("host", 22, timeout=1.0) is None


@pytest.mark.asyncio
async def test_grab_banner_read_error_returns_none(monkeypatch):
    """A read/reset failure after connecting returns None (port is not dropped)."""
    class _RaisingReader:
        async def read(self, n: int) -> bytes:
            raise ConnectionResetError("connection reset by peer")

    async def fake_open_connection(host, port, ssl=None):
        return _RaisingReader(), _FakeWriter()

    monkeypatch.setattr(scanner.asyncio, "open_connection", fake_open_connection)
    assert await scanner.grab_banner("host", 22, timeout=1.0) is None


@pytest.mark.asyncio
async def test_scan_service_detection_populates_version(monkeypatch):
    """scan with service_detection populates product/version from the grabbed banner."""
    async def fake_scan_port(host, port, timeout=3.0):
        return scanner.PortResult(port=port, status="open", service="SSH", latency=0.01)

    async def fake_open_connection(host, port, ssl=None):
        return _FakeReader(b"SSH-2.0-OpenSSH_9.6p1\r\n"), _FakeWriter()

    monkeypatch.setattr(scanner, "scan_port", fake_scan_port)
    monkeypatch.setattr(scanner.asyncio, "open_connection", fake_open_connection)

    result = await scanner.scan("host", ports=[22], service_detection=True)
    assert result.ports[0].product == "OpenSSH"
    assert result.ports[0].version == "9.6p1"


def test_format_nmap_text_layout():
    """format_nmap_text renders port, version, and open-count lines."""
    from datetime import datetime

    result = scanner.ScanResult(
        target="example.com",
        start_time=datetime(2026, 5, 29, 12, 0, 0),
        end_time=datetime(2026, 5, 29, 12, 0, 1),
        ports=[
            scanner.PortResult(
                port=22, status="open", service="SSH", latency=0.01,
                product="OpenSSH", version="9.6p1",
            )
        ],
    )
    text = scanner.format_nmap_text(result)
    assert "22/tcp" in text
    assert "OpenSSH 9.6p1" in text
    assert "1 open port(s)" in text


def test_format_nmap_text_hides_closed_ports():
    """format_nmap_text omits closed ports and reports the not-shown count."""
    from datetime import datetime

    result = scanner.ScanResult(
        target="example.com",
        start_time=datetime(2026, 5, 29, 12, 0, 0),
        end_time=datetime(2026, 5, 29, 12, 0, 1),
        ports=[
            scanner.PortResult(port=22, status="open", service="SSH", latency=0.01),
            scanner.PortResult(port=23, status="closed", service="Telnet", latency=0.0),
            scanner.PortResult(port=25, status="closed", service="SMTP", latency=0.0),
        ],
    )
    text = scanner.format_nmap_text(result)
    assert "22/tcp" in text
    assert "23/tcp" not in text
    assert "Not shown: 2 closed port(s)" in text
    assert "1 open port(s) of 3 scanned" in text
