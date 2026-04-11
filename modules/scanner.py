import asyncio
import socket
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


@dataclass
class PortResult:
    port: int
    status: str
    service: Optional[str]
    latency: float


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


async def scan(
    target: str,
    ports: Optional[list[int]] = None,
    timeout: float = 3.0,
    concurrent: int = 50,
) -> ScanResult:
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    start_time = datetime.now()
    result = ScanResult(target=target, start_time=start_time, end_time=start_time)

    semaphore = asyncio.Semaphore(concurrent)

    async def scan_with_semaphore(port: int) -> PortResult:
        async with semaphore:
            return await scan_port(target, port, timeout)

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
