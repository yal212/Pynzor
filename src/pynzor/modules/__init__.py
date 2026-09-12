from . import scanner as _scanner
from . import fuzzer as _fuzzer
from . import headers as _headers
from . import sqli as _sqli
from . import xss as _xss
from . import subdomain as _subdomain
from .fuzzer import is_request_mode
from pynzor.core.events import ProgressCallback
from pynzor.utils.http_client import ClientConfig, HTTPClient


async def scan(
    target: str,
    ports: list[int] | None = None,
    timeout: float = 3.0,
    concurrent: int = 50,
    service_detection: bool = False,
    banner_timeout: float = 2.0,
    on_progress: ProgressCallback | None = None,
):
    """Public facade for the port scanner.

    Delegates to :func:`modules.scanner.scan`; see it for argument details.

    Returns:
        The scanner's ``ScanResult``.
    """
    return await _scanner.scan(
        target,
        ports,
        timeout,
        concurrent,
        service_detection=service_detection,
        banner_timeout=banner_timeout,
        on_progress=on_progress,
    )


async def fuzz(
    target: str,
    wordlist_path: str,
    threads: int = 20,
    use_baseline: bool = True,
    extensions: list[str] | None = None,
    recursive: bool = False,
    depth: int = 1,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: str | None = None,
    match_codes: list[int] | None = None,
    filter_codes: list[int] | None = None,
    filter_size: int | None = None,
    filter_words: int | None = None,
    filter_lines: int | None = None,
    on_progress: ProgressCallback | None = None,
    client_config: ClientConfig | None = None,
):
    """Public facade for the fuzzer.

    Loads the wordlist, then dispatches to request-mode fuzzing
    (:func:`modules.fuzzer.fuzz_request`) when a FUZZ keyword/body/method is
    present, otherwise directory fuzzing (:func:`modules.fuzzer.fuzz_directory`).

    Returns:
        A ``FuzzScanResult``.
    """
    wordlist = _fuzzer.load_wordlist(wordlist_path)

    if is_request_mode(target, headers=headers, data=data, method=method):
        return await _fuzzer.fuzz_request(
            target,
            wordlist,
            method=method,
            headers=headers,
            data=data,
            threads=threads,
            match_codes=match_codes,
            filter_codes=filter_codes,
            filter_size=filter_size,
            filter_words=filter_words,
            filter_lines=filter_lines,
            on_progress=on_progress,
            client_config=client_config,
        )

    return await _fuzzer.fuzz_directory(
        target,
        wordlist,
        threads,
        use_baseline=use_baseline,
        extensions=extensions,
        recursive=recursive,
        depth=depth,
        on_progress=on_progress,
        client_config=client_config,
    )


async def analyze(
    target: str,
    http_client: HTTPClient | None = None,
    on_progress: ProgressCallback | None = None,
):
    """Public facade for security-header analysis.

    Delegates to :func:`modules.headers.analyze_headers`.

    Returns:
        A ``HeaderResult``.
    """
    return await _headers.analyze_headers(target, http_client, on_progress=on_progress)


async def probe(
    target: str,
    on_progress: ProgressCallback | None = None,
    client_config: ClientConfig | None = None,
):
    """Public facade for SQL injection probing.

    Delegates to :func:`modules.sqli.probe_sqli`, which manages its own HTTP
    client (a deliberately gentler probe with its own rate limit).

    Returns:
        A ``SQLiResult``.
    """
    return await _sqli.probe_sqli(target, on_progress=on_progress, client_config=client_config)


async def detect(
    target: str,
    on_progress: ProgressCallback | None = None,
    client_config: ClientConfig | None = None,
):
    """Public facade for XSS detection.

    Delegates to :func:`modules.xss.detect_xss`, which manages its own HTTP
    client (a deliberately gentler probe with its own rate limit).

    Returns:
        An ``XSSResult``.
    """
    return await _xss.detect_xss(target, on_progress=on_progress, client_config=client_config)


async def enumerate(
    target: str,
    wordlist_path: str,
    threads: int = 20,
    include_wildcard: bool = False,
    on_progress: ProgressCallback | None = None,
    client_config: ClientConfig | None = None,
):
    """Public facade for subdomain enumeration.

    Loads the wordlist and delegates to
    :func:`modules.subdomain.enumerate_subdomains`.

    Returns:
        A ``SubdomainScanResult``.
    """
    wordlist = _fuzzer.load_wordlist(wordlist_path)
    return await _subdomain.enumerate_subdomains(
        target,
        wordlist,
        threads,
        include_wildcard=include_wildcard,
        on_progress=on_progress,
        client_config=client_config,
    )
