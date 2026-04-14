import asyncio
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime
from pathlib import Path
from utils.http_client import HTTPClient, ClientConfig, Response


@dataclass
class FuzzResult:
    url: str
    status_code: int
    discovered: bool
    content_length: int
    redirect: Optional[str]


@dataclass
class FuzzScanResult:
    target: str
    start_time: datetime
    end_time: datetime
    found: list[FuzzResult] = field(default_factory=list)
    scanned: int = 0
    errors: int = 0


async def fuzz_directory(
    target: str,
    wordlist: list[str],
    threads: int = 20,
    status_codes: Optional[list[int]] = None,
) -> FuzzScanResult:
    if status_codes is None:
        status_codes = [200, 201, 204, 301, 302, 307, 401, 403]

    start_time = datetime.now()
    result = FuzzScanResult(target=target, start_time=start_time, end_time=start_time)

    config = ClientConfig(rate_limit=0.1)
    client = HTTPClient(config)

    semaphore = asyncio.Semaphore(threads)
    found = []
    errors = 0
    scanned = 0

    async def fuzz_path(path: str) -> Optional[FuzzResult]:
        nonlocal errors, scanned
        url = target.rstrip("/") + "/" + path.lstrip("/")

        async with semaphore:
            response = await client.get(url)

        scanned += 1

        if response.error:
            errors += 1
            return None

        if response.status_code in status_codes:
            return FuzzResult(
                url=response.url,
                status_code=response.status_code,
                discovered=True,
                content_length=len(response.body or ""),
                redirect=response.headers.get("Location"),
            )

        return None

    async with client:
        tasks = [fuzz_path(path) for path in wordlist]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, FuzzResult) and r:
                found.append(r)
            elif isinstance(r, Exception):
                errors += 1

    result.found = found
    result.scanned = scanned
    result.errors = errors
    result.end_time = datetime.now()

    return result


def load_wordlist(path: str) -> list[str]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Wordlist not found: {path}")
    if not p.is_file():
        raise ValueError(f"Wordlist path is not a file: {path}")
    with open(p, "r") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]
