import asyncio
import hashlib
import uuid
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
class BaselineSignature:
    status_code: int
    content_length: int
    body_hash: str
    probe_path: str

    def matches(self, response: Response) -> bool:
        if response.status_code != self.status_code:
            return False
        body = response.body or ""
        if _hash_body(body) == self.body_hash:
            return True
        # For short bodies the hash is the only reliable signal. For larger
        # bodies we also accept a small length drift (dynamic tokens, CSRF,
        # timestamps) as a match.
        if self.content_length < 500:
            return False
        length = len(body)
        tolerance = max(20, int(self.content_length * 0.03))
        return abs(length - self.content_length) <= tolerance


@dataclass
class FuzzScanResult:
    target: str
    start_time: datetime
    end_time: datetime
    found: list[FuzzResult] = field(default_factory=list)
    scanned: int = 0
    errors: int = 0
    baseline_detected: bool = False
    baseline_status: Optional[int] = None
    baseline_note: Optional[str] = None
    baseline_filtered: int = 0


def _hash_body(body: str) -> str:
    normalized = " ".join((body or "").split())
    return hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest()


async def _probe_baseline(
    client: HTTPClient, target: str, semaphore: asyncio.Semaphore
) -> Optional[BaselineSignature]:
    probe_paths = [f"pynzor-baseline-{uuid.uuid4().hex[:16]}" for _ in range(2)]

    async def fetch(path: str) -> Optional[Response]:
        url = target.rstrip("/") + "/" + path
        async with semaphore:
            resp = await client.get(url)
        return None if resp.error else resp

    responses = await asyncio.gather(*(fetch(p) for p in probe_paths))
    valid = [r for r in responses if r is not None]
    if len(valid) < 2:
        return None

    first, second = valid[0], valid[1]
    if first.status_code != second.status_code:
        return None

    # Random paths should normally 404. If two random UUIDs return a "success"
    # code AND near-identical bodies, the server is a catch-all (SPA/proxy).
    catchall_codes = {200, 201, 202, 204, 301, 302, 307, 308, 401, 403}
    if first.status_code not in catchall_codes:
        return None

    first_hash = _hash_body(first.body or "")
    second_hash = _hash_body(second.body or "")
    first_len = len(first.body or "")
    second_len = len(second.body or "")

    # Accept baseline if bodies are identical (hash match) or, for larger
    # bodies, differ by only a few percent (dynamic content).
    length_ok = first_len >= 500 and abs(first_len - second_len) <= max(
        20, int(first_len * 0.03)
    )
    if first_hash == second_hash or length_ok:
        return BaselineSignature(
            status_code=first.status_code,
            content_length=first_len,
            body_hash=first_hash,
            probe_path=probe_paths[0],
        )
    return None


async def fuzz_directory(
    target: str,
    wordlist: list[str],
    threads: int = 20,
    status_codes: Optional[list[int]] = None,
    use_baseline: bool = True,
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
    baseline_filtered = 0
    baseline: Optional[BaselineSignature] = None

    async def fuzz_path(path: str) -> Optional[FuzzResult]:
        nonlocal errors, scanned, baseline_filtered
        url = target.rstrip("/") + "/" + path.lstrip("/")

        async with semaphore:
            response = await client.get(url)

        scanned += 1

        if response.error:
            errors += 1
            return None

        if response.status_code not in status_codes:
            return None

        if baseline is not None and baseline.matches(response):
            baseline_filtered += 1
            return None

        return FuzzResult(
            url=response.url,
            status_code=response.status_code,
            discovered=True,
            content_length=len(response.body or ""),
            redirect=response.headers.get("Location"),
        )

    async with client:
        if use_baseline:
            baseline = await _probe_baseline(client, target, semaphore)
            if baseline is not None:
                result.baseline_detected = True
                result.baseline_status = baseline.status_code
                result.baseline_note = (
                    f"SPA/catch-all detected (probe '/{baseline.probe_path}' "
                    f"returned {baseline.status_code}, {baseline.content_length} bytes). "
                    "Filtering matches."
                )

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
    result.baseline_filtered = baseline_filtered
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
