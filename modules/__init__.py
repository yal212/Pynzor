import asyncio

from . import scanner as _scanner
from . import fuzzer as _fuzzer
from . import headers as _headers
from . import sqli as _sqli
from . import xss as _xss
from . import subdomain as _subdomain
from utils.http_client import HTTPClient


async def scan(
    target: str,
    ports: list[int] | None = None,
    timeout: float = 3.0,
    concurrent: int = 50,
):
    return await _scanner.scan(target, ports, timeout, concurrent)


async def fuzz(
    target: str,
    wordlist_path: str,
    threads: int = 20,
    use_baseline: bool = True,
):
    wordlist = _fuzzer.load_wordlist(wordlist_path)
    return await _fuzzer.fuzz_directory(
        target, wordlist, threads, use_baseline=use_baseline
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
