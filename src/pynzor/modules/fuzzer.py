import asyncio
import hashlib
import uuid
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime
from pathlib import Path
from pynzor.utils.http_client import HTTPClient, ClientConfig, Response
from pynzor.utils.validators import extract_domain


FUZZ_KEYWORD = "FUZZ"

# ffuf's default matcher set.
DEFAULT_MATCH_CODES = [200, 204, 301, 302, 307, 401, 403, 405, 500]


def is_request_mode(
    target: str,
    headers: Optional[dict[str, str]] = None,
    data: Optional[str] = None,
    method: str = "GET",
) -> bool:
    """ffuf-style request fuzzing applies when a FUZZ keyword appears in the
    target, header names, or header values, a non-GET method is used, or a
    non-empty request body is supplied. Otherwise we run gobuster-style
    directory fuzzing."""
    header_text = " ".join(f"{k} {v}" for k, v in (headers or {}).items())
    return (
        FUZZ_KEYWORD in target
        or FUZZ_KEYWORD in header_text
        or method.upper() != "GET"
        or bool(data)
    )


@dataclass
class FuzzResult:
    """A single discovered path/word and its response metrics."""

    url: str
    status_code: int
    discovered: bool
    content_length: int
    redirect: Optional[str]
    word: Optional[str] = None
    words: int = 0
    lines: int = 0


@dataclass
class BaselineSignature:
    """Fingerprint of a catch-all (SPA/proxy) response used to filter false hits."""

    status_code: int
    content_length: int
    body_hash: str
    probe_path: str

    def matches(self, response: Response) -> bool:
        """Check whether a response looks like the recorded catch-all baseline.

        Length acts as a fast-path gate: a body whose size differs from the
        baseline by more than a few percent is rejected without hashing. Within
        that tolerance an identical normalized-body hash confirms the match, so
        two similarly sized but genuinely different pages are not conflated. For
        very large pages a small length drift (dynamic tokens, CSRF, timestamps)
        is treated as a baseline match even when the hash differs.

        Args:
            response: The response to compare against this baseline.

        Returns:
            True if the response should be treated as a baseline (non-)hit.
        """
        if response.status_code != self.status_code:
            return False
        body = response.body or ""
        length = len(body)
        tolerance = max(20, int(self.content_length * 0.03))
        # For short bodies the hash is the only reliable signal, so allow a
        # wider gate (up to 100 bytes) before hashing — otherwise length drift
        # could skip a true catch-all whose normalized body still hashes equal.
        gate = max(tolerance, 100) if self.content_length < 500 else tolerance
        # Fast path: a clearly different size is not the baseline, and we avoid
        # hashing the body entirely.
        if abs(length - self.content_length) > gate:
            return False
        # Within tolerance, an identical normalized-body hash is the reliable
        # signal that this is the catch-all page.
        if _hash_body(body) == self.body_hash:
            return True
        # For very large pages, a few-percent length drift alone is enough to
        # treat the response as the baseline even without a hash match.
        return self.content_length >= 5000


@dataclass
class FuzzScanResult:
    """Aggregated results of a directory or request fuzzing run."""

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
    mode: str = "directory"


def _hash_body(body: str) -> str:
    """Return a SHA-256 hash of a whitespace-normalized response body.

    Args:
        body: Raw response body text.

    Returns:
        Hex digest of the normalized body, used for baseline comparison.
    """
    normalized = " ".join((body or "").split())
    return hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest()


async def _probe_baseline(
    client: HTTPClient, target: str, semaphore: asyncio.Semaphore
) -> Optional[BaselineSignature]:
    """Probe random paths to detect a catch-all (SPA/proxy) response.

    Requests two random UUID paths; if both return the same "success" status
    with identical (or near-identical, for large bodies) content, the server is
    treated as a catch-all and a baseline signature is returned.

    Args:
        client: HTTP client to issue probes with.
        target: Base URL to probe under.
        semaphore: Concurrency limiter shared with the fuzz run.

    Returns:
        A :class:`BaselineSignature` if a catch-all is detected, else None.
    """
    probe_paths = [f"pynzor-baseline-{uuid.uuid4().hex[:16]}" for _ in range(2)]

    async def fetch(path: str) -> Optional[Response]:
        """Fetch one probe path under the semaphore; None on request error."""
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
    length_ok = first_len >= 500 and abs(first_len - second_len) <= max(20, int(first_len * 0.03))
    if first_hash == second_hash or length_ok:
        return BaselineSignature(
            status_code=first.status_code,
            content_length=first_len,
            body_hash=first_hash,
            probe_path=probe_paths[0],
        )
    return None


def _normalize_extensions(extensions: Optional[list[str]]) -> list[str]:
    """Turn user-supplied extensions (``php``, ``.php``) into dotted form."""
    norm = []
    for ext in extensions or []:
        ext = ext.strip()
        if not ext:
            continue
        if not ext.startswith("."):
            ext = "." + ext
        if ext not in norm:
            norm.append(ext)
    return norm


def expand_candidates(wordlist: list[str], extensions: Optional[list[str]]) -> list[str]:
    """Expand each word into the bare word plus ``word+ext`` for each extension
    (gobuster ``-x`` behavior). The bare word is always probed."""
    exts = _normalize_extensions(extensions)
    candidates: list[str] = []
    for word in wordlist:
        candidates.append(word)
        for ext in exts:
            if not word.endswith(ext):
                candidates.append(word + ext)
    return candidates


def _is_directory_hit(result: FuzzResult) -> bool:
    """A hit worth recursing into: a success/redirect/forbidden status on a path
    whose last segment has no file extension."""
    if result.status_code not in (200, 301, 302, 307, 308, 403):
        return False
    last = result.url.rstrip("/").rsplit("/", 1)[-1]
    return "." not in last


async def fuzz_directory(
    target: str,
    wordlist: list[str],
    threads: int = 20,
    status_codes: Optional[list[int]] = None,
    use_baseline: bool = True,
    extensions: Optional[list[str]] = None,
    recursive: bool = False,
    depth: int = 1,
    max_candidates: int = 20000,
) -> FuzzScanResult:
    """Run gobuster-style directory fuzzing against a base URL.

    Expands the wordlist with extensions, optionally detects a catch-all
    baseline to filter false positives, and (when recursive) descends into
    discovered directories up to ``depth`` via breadth-first search.

    Args:
        target: Base URL to fuzz.
        wordlist: Words/paths to try.
        threads: Maximum concurrent requests.
        status_codes: Status codes treated as hits; defaults to a common set.
        use_baseline: Whether to probe for and filter a catch-all baseline.
        extensions: Extensions to append to each word (gobuster ``-x``).
        recursive: Whether to recurse into discovered directories.
        depth: Maximum recursion depth when ``recursive`` is set.
        max_candidates: Cap on total candidates/requests to bound fan-out.

    Returns:
        A :class:`FuzzScanResult` with discovered paths and run statistics.
    """
    if status_codes is None:
        status_codes = [200, 201, 204, 301, 302, 307, 401, 403]

    candidates = expand_candidates(wordlist, extensions)
    # Bound per-base fan-out: extensions can multiply a wordlist into 100k+
    # candidates, and each base schedules every candidate at once.
    if len(candidates) > max_candidates:
        candidates = candidates[:max_candidates]

    start_time = datetime.now()
    result = FuzzScanResult(target=target, start_time=start_time, end_time=start_time)

    config = ClientConfig(rate_limit=0.1)
    client = HTTPClient(config)
    semaphore = asyncio.Semaphore(threads)

    totals = {"scanned": 0, "errors": 0, "baseline_filtered": 0}
    found: list[FuzzResult] = []

    async def fuzz_base(base: str) -> tuple[list[FuzzResult], Optional[BaselineSignature]]:
        """Fuzz every candidate under one base URL, returning hits and its baseline."""
        baseline = await _probe_baseline(client, base, semaphore) if use_baseline else None

        async def fuzz_path(path: str) -> Optional[FuzzResult]:
            """Request a single candidate path; return a hit or None (miss/baseline/error)."""
            url = base.rstrip("/") + "/" + path.lstrip("/")
            async with semaphore:
                response = await client.get(url)
            totals["scanned"] += 1
            if response.error:
                totals["errors"] += 1
                return None
            if response.status_code not in status_codes:
                return None
            if baseline is not None and baseline.matches(response):
                totals["baseline_filtered"] += 1
                return None
            return FuzzResult(
                url=response.url,
                status_code=response.status_code,
                discovered=True,
                content_length=len(response.body or ""),
                redirect=response.headers.get("Location"),
            )

        # Honor the global budget across recursive bases: the BFS loop only
        # checks the cap between bases, so slice each base to what remains.
        remaining = max_candidates - totals["scanned"]
        if remaining <= 0:
            return [], baseline
        results = await asyncio.gather(
            *(fuzz_path(p) for p in candidates[:remaining]), return_exceptions=True
        )
        base_found = []
        for r in results:
            if isinstance(r, FuzzResult):
                base_found.append(r)
            elif isinstance(r, Exception):
                totals["errors"] += 1
        return base_found, baseline

    async with client:
        # BFS over discovered directories up to `depth` (only when recursive).
        queue: list[tuple[str, int]] = [(target, 0)]
        seen_bases = {target.rstrip("/")}
        top_level = True
        while queue:
            base, level = queue.pop(0)
            if totals["scanned"] >= max_candidates:
                break
            base_found, baseline = await fuzz_base(base)
            if top_level and baseline is not None:
                result.baseline_detected = True
                result.baseline_status = baseline.status_code
                result.baseline_note = (
                    f"SPA/catch-all detected (probe '/{baseline.probe_path}' "
                    f"returned {baseline.status_code}, {baseline.content_length} bytes). "
                    "Filtering matches."
                )
            top_level = False
            found.extend(base_found)
            if recursive and level < depth:
                target_domain = extract_domain(target)
                for fr in base_found:
                    child = fr.url.rstrip("/")
                    # Redirects can point off-host; only recurse in-scope.
                    if (
                        _is_directory_hit(fr)
                        and child not in seen_bases
                        and extract_domain(child) == target_domain
                    ):
                        seen_bases.add(child)
                        queue.append((child, level + 1))

    result.found = found
    result.scanned = totals["scanned"]
    result.errors = totals["errors"]
    result.baseline_filtered = totals["baseline_filtered"]
    result.end_time = datetime.now()

    return result


async def fuzz_request(
    target: str,
    wordlist: list[str],
    method: str = "GET",
    headers: Optional[dict[str, str]] = None,
    data: Optional[str] = None,
    threads: int = 20,
    match_codes: Optional[list[int]] = None,
    filter_codes: Optional[list[int]] = None,
    filter_size: Optional[int] = None,
    filter_words: Optional[int] = None,
    filter_lines: Optional[int] = None,
    max_candidates: int = 20000,
) -> FuzzScanResult:
    """ffuf-style fuzzing: substitute the ``FUZZ`` keyword into the URL, header
    values, and/or raw body, then match/filter responses."""
    method = method.upper()
    headers = headers or {}
    if match_codes is None:
        match_codes = list(DEFAULT_MATCH_CODES)

    # Bound fan-out: every word schedules a request up front, so an oversized
    # wordlist is capped the same way directory mode caps expanded candidates.
    if len(wordlist) > max_candidates:
        wordlist = wordlist[:max_candidates]

    start_time = datetime.now()
    result = FuzzScanResult(
        target=target, start_time=start_time, end_time=start_time, mode="request"
    )

    # Don't follow redirects: ffuf treats 3xx as terminal so -mc 301,302,307
    # (and the default matcher) can actually match instead of resolving to 200.
    config = ClientConfig(rate_limit=0.1, follow_redirects=False)
    client = HTTPClient(config)
    semaphore = asyncio.Semaphore(threads)

    totals = {"scanned": 0, "errors": 0}

    def _passes_filters(status: int, size: int, words: int, lines: int) -> bool:
        """Return True if a response matches ``match_codes`` and survives all filters."""
        if status not in match_codes:
            return False
        if filter_codes and status in filter_codes:
            return False
        if filter_size is not None and size == filter_size:
            return False
        if filter_words is not None and words == filter_words:
            return False
        if filter_lines is not None and lines == filter_lines:
            return False
        return True

    async def fuzz_word(word: str) -> Optional[FuzzResult]:
        """Substitute one word into the request and return a hit or None."""
        url = target.replace(FUZZ_KEYWORD, word)
        req_headers = {
            k.replace(FUZZ_KEYWORD, word): v.replace(FUZZ_KEYWORD, word) for k, v in headers.items()
        }
        body = data.replace(FUZZ_KEYWORD, word) if data is not None else None

        async with semaphore:
            response = await client.request(method, url, headers=req_headers or None, content=body)
        totals["scanned"] += 1

        if response.error:
            totals["errors"] += 1
            return None

        text = response.body or ""
        size = len(text)
        words = len(text.split())
        lines = len(text.splitlines())

        if not _passes_filters(response.status_code, size, words, lines):
            return None

        return FuzzResult(
            url=response.url,
            status_code=response.status_code,
            discovered=True,
            content_length=size,
            redirect=response.headers.get("Location"),
            word=word,
            words=words,
            lines=lines,
        )

    async with client:
        results = await asyncio.gather(*(fuzz_word(w) for w in wordlist), return_exceptions=True)

    found = []
    for r in results:
        if isinstance(r, FuzzResult):
            found.append(r)
        elif isinstance(r, Exception):
            totals["errors"] += 1

    result.found = found
    result.scanned = totals["scanned"]
    result.errors = totals["errors"]
    result.end_time = datetime.now()

    return result


def load_wordlist(path: str) -> list[str]:
    """Load a wordlist file, skipping blank lines and ``#`` comments.

    Args:
        path: Filesystem path to the wordlist.

    Returns:
        List of stripped, non-comment words.

    Raises:
        FileNotFoundError: If the path does not exist.
        ValueError: If the path exists but is not a regular file.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Wordlist not found: {path}")
    if not p.is_file():
        raise ValueError(f"Wordlist path is not a file: {path}")
    with open(p, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]
