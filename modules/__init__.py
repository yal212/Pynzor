import asyncio

from . import scanner as _scanner
from . import fuzzer as _fuzzer
from . import headers as _headers
from . import sqli as _sqli
from . import xss as _xss
from . import subdomain as _subdomain
from .fuzzer import is_request_mode
from utils.http_client import HTTPClient


async def scan(
    target: str,
    ports: list[int] | None = None,
    timeout: float = 3.0,
    concurrent: int = 50,
    service_detection: bool = False,
    banner_timeout: float = 2.0,
):
    return await _scanner.scan(
        target,
        ports,
        timeout,
        concurrent,
        service_detection=service_detection,
        banner_timeout=banner_timeout,
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
):
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
        )

    return await _fuzzer.fuzz_directory(
        target,
        wordlist,
        threads,
        use_baseline=use_baseline,
        extensions=extensions,
        recursive=recursive,
        depth=depth,
    )


async def analyze(target: str, http_client: HTTPClient | None = None):
    return await _headers.analyze_headers(target, http_client)


async def probe(target: str, http_client: HTTPClient | None = None):
    return await _sqli.probe_sqli(target)


async def detect(target: str, http_client: HTTPClient | None = None):
    return await _xss.detect_xss(target)


async def enumerate(
    target: str,
    wordlist_path: str,
    threads: int = 20,
    include_wildcard: bool = False,
):
    wordlist = _fuzzer.load_wordlist(wordlist_path)
    return await _subdomain.enumerate_subdomains(
        target, wordlist, threads, include_wildcard=include_wildcard
    )
