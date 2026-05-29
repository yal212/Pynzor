import asyncio
import re
import ssl
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

HTTP_PORTS = {80, 8080, 8000, 8888}
TLS_PORTS = {443, 8443}


@dataclass
class PortResult:
    port: int
    status: str
    service: Optional[str]
    latency: float
    banner: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None


@dataclass
class ScanResult:
    target: str
    start_time: datetime
    end_time: datetime
    ports: list[PortResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


async def scan_port(host: str, port: int, timeout: float = 3.0) -> PortResult:
    start = datetime.now()
    service = COMMON_PORTS.get(port, "Unknown")

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        latency = (datetime.now() - start).total_seconds()

        return PortResult(
            port=port,
            status="open",
            service=service,
            latency=latency,
        )
    except asyncio.TimeoutError:
        latency = (datetime.now() - start).total_seconds()
        return PortResult(
            port=port,
            status="filtered",
            service=service,
            latency=latency,
        )
    except ConnectionRefusedError:
        latency = (datetime.now() - start).total_seconds()
        return PortResult(
            port=port,
            status="closed",
            service=service,
            latency=latency,
        )
    except OSError as e:
        latency = (datetime.now() - start).total_seconds()
        return PortResult(
            port=port,
            status="filtered",
            service=service,
            latency=latency,
        )


def parse_ports(spec: str) -> list[int]:
    """Parse an nmap-style port spec: '80,443', '1-1000', '22,80,8000-8100'."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, _, hi_s = part.partition("-")
            try:
                lo, hi = int(lo_s), int(hi_s)
            except ValueError:
                raise ValueError(f"Invalid port range: {part!r} (expected 'lo-hi')")
            if lo > hi:
                lo, hi = hi, lo
            for p in range(lo, hi + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            try:
                p = int(part)
            except ValueError:
                raise ValueError(f"Invalid port: {part!r}")
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)


# Ordered (pattern, product, version-group) heuristics for common banners.
_BANNER_PATTERNS = [
    (re.compile(r"SSH-[\d.]+-OpenSSH[_-]([\w.]+)", re.I), "OpenSSH", 1),
    (re.compile(r"SSH-[\d.]+-([\w.+-]+)", re.I), "SSH", 1),
    (re.compile(r"ProFTPD\s+([\d.]+)", re.I), "ProFTPD", 1),
    (re.compile(r"\bvsFTPd\s+([\d.]+)", re.I), "vsftpd", 1),
    (re.compile(r"\b(?:Server:\s*)?nginx/([\d.]+)", re.I), "nginx", 1),
    (re.compile(r"\b(?:Server:\s*)?Apache/([\d.]+)", re.I), "Apache", 1),
    (re.compile(r"\bServer:\s*([^\r\n]+)", re.I), None, 1),
    (re.compile(r"220[ -]([^\r\n]+)", re.I), None, 1),
]


def parse_service_banner(banner: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Extract (product, version) from a raw banner. Best-effort heuristics."""
    if not banner:
        return None, None
    for pattern, product, group in _BANNER_PATTERNS:
        m = pattern.search(banner)
        if m:
            captured = m.group(group).strip()
            if product is None:
                # Generic match: the capture is the whole product string.
                return captured, None
            return product, captured
    return None, None


async def grab_banner(host: str, port: int, timeout: float = 2.0) -> Optional[str]:
    """Connect to an open port and read a banner. For HTTP(S) ports we send a
    minimal request to elicit the Server header; other services usually emit a
    banner on connect. Returns the raw text (truncated) or None."""
    use_tls = port in TLS_PORTS
    ssl_ctx = None
    if use_tls:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_ctx), timeout=timeout
        )
    except (asyncio.TimeoutError, OSError, ssl.SSLError):
        return None

    try:
        if port in HTTP_PORTS or use_tls:
            request = (
                f"GET / HTTP/1.0\r\nHost: {host}\r\n"
                "User-Agent: Pynzor\r\nConnection: close\r\n\r\n"
            )
            writer.write(request.encode())
            await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        except asyncio.TimeoutError:
            data = b""
        text = data.decode("utf-8", errors="replace").strip()
        return text or None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ssl.SSLError):
            pass


async def scan(
    target: str,
    ports: Optional[list[int]] = None,
    timeout: float = 3.0,
    concurrent: int = 50,
    service_detection: bool = False,
    banner_timeout: float = 2.0,
) -> ScanResult:
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    start_time = datetime.now()
    result = ScanResult(target=target, start_time=start_time, end_time=start_time)

    semaphore = asyncio.Semaphore(concurrent)

    async def scan_with_semaphore(port: int) -> PortResult:
        async with semaphore:
            port_result = await scan_port(target, port, timeout)
            if service_detection and port_result.status == "open":
                banner = await grab_banner(target, port, banner_timeout)
                if banner:
                    product, version = parse_service_banner(banner)
                    port_result.banner = banner[:200]
                    port_result.product = product
                    port_result.version = version
            return port_result

    tasks = [scan_with_semaphore(p) for p in ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if isinstance(r, Exception):
            result.errors.append(str(r))
        elif isinstance(r, PortResult):
            result.ports.append(r)

    result.ports.sort(key=lambda x: x.port)
    result.end_time = datetime.now()

    return result


def format_nmap_text(result: ScanResult) -> str:
    """Render an nmap-style plain-text report (for -oN)."""
    lines = [
        f"Pynzor scan report for {result.target}",
        f"Scanned at {result.start_time.isoformat(timespec='seconds')}",
        "",
        f"{'PORT':<10}{'STATE':<10}{'SERVICE':<14}VERSION",
    ]
    for p in result.ports:
        version = " ".join(x for x in (p.product, p.version) if x)
        lines.append(
            f"{str(p.port) + '/tcp':<10}{p.status:<10}{(p.service or ''):<14}{version}"
        )
    open_count = len([p for p in result.ports if p.status == "open"])
    lines.append("")
    lines.append(f"{open_count} open port(s) of {len(result.ports)} scanned")
    return "\n".join(lines) + "\n"
