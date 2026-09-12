"""Run one recon module and build its report envelope.

Each ``run_*`` coroutine owns the option resolution and envelope construction
that used to be duplicated inside every Typer command body. They never call
``asyncio.run``, never print, and never touch a console, so the CLI (which
wraps them in ``asyncio.run``) and the TUI (which awaits them on its own loop)
produce byte-identical reports.
"""

from dataclasses import dataclass, field, replace
from typing import Any, Optional

import pynzor.modules as modules
from pynzor.core.events import ProgressCallback
from pynzor.core.parsing import parse_int_list, parse_str_list
from pynzor.output.reporter import build_report, highest_severity, severity_from_grade
from pynzor.utils.http_client import ClientConfig, HTTPClient
from pynzor.utils.validators import extract_domain, normalize_url

RunResult = tuple[Any, dict]


# Per-module fallbacks, used only when neither the module's own config section
# nor the http section supplies a value. These are the values the modules used
# to hardcode, so behaviour is unchanged for a config that says nothing.
_MODULE_RATE_LIMITS = {"fuzz": 0.1, "sqli": 0.2, "xss": 0.2, "subdomain": 0.1}

# Module id -> config.yaml section name, where they differ.
_CONFIG_SECTIONS = {"fuzz": "fuzzer", "ports": "scanner"}


def client_config_from(config: dict) -> ClientConfig:
    """Build an HTTP client config from the ``http`` section of the config."""
    http_cfg = config.get("http", {})
    return ClientConfig(
        timeout=http_cfg.get("timeout", 10),
        max_retries=http_cfg.get("max_retries", 3),
        rate_limit=http_cfg.get("rate_limit", 0.1),
        user_agent=http_cfg.get("user_agent"),
        follow_redirects=http_cfg.get("follow_redirects", True),
        verify_ssl=http_cfg.get("verify_ssl", True),
    )


def client_config_for(config: dict, module_id: str) -> ClientConfig:
    """Build a module's HTTP client config, honouring its per-module overrides.

    Resolution order for ``rate_limit`` and ``timeout``: the module's own
    section in config.yaml, then the ``http`` section, then the value that
    module used to hardcode. This is what makes keys like ``sqli.rate_limit``
    -- which have always been in the shipped config -- actually take effect
    (AGENTS.md 11: no hardcoded timeouts or rate limits).

    Args:
        config: Parsed config dict.
        module_id: Module id, e.g. "fuzz" or "sqli".

    Returns:
        A :class:`ClientConfig` for that module.
    """
    base = client_config_from(config)
    section = config.get(_CONFIG_SECTIONS.get(module_id, module_id), {}) or {}

    rate_limit = section.get("rate_limit")
    if rate_limit is None:
        rate_limit = _MODULE_RATE_LIMITS.get(module_id, base.rate_limit)

    return replace(
        base,
        rate_limit=float(rate_limit),
        timeout=float(section.get("timeout", base.timeout)),
    )


async def run_ports(
    target: str,
    config: dict,
    *,
    ports: list[int] | None = None,
    service_detection: bool = False,
    threads: int | None = None,
    on_progress: Optional[ProgressCallback] = None,
) -> RunResult:
    """Scan TCP ports and build the ``ports`` report envelope.

    Args:
        target: Host or URL; normalized to a bare host.
        config: Parsed config dict.
        ports: Explicit port list; defaults to the config's common ports.
        service_detection: Grab and parse banners on open ports.
        threads: Concurrency override; defaults to the config's value.
        on_progress: Fired once per port probed.

    Returns:
        ``(ScanResult, report_dict)``.
    """
    host = extract_domain(normalize_url(target))
    scanner_cfg = config.get("scanner", {})
    port_list = ports if ports is not None else scanner_cfg.get("common_ports")
    concurrent = threads if threads is not None else scanner_cfg.get("concurrent", 50)

    result = await modules.scan(
        host,
        ports=port_list,
        timeout=scanner_cfg.get("timeout", 3),
        concurrent=concurrent,
        service_detection=service_detection,
        banner_timeout=scanner_cfg.get("banner_timeout", 2),
        on_progress=on_progress,
    )

    report = build_report(
        module="ports",
        target=host,
        findings=[
            {
                "port": p.port,
                "status": p.status,
                "service": p.service,
                "product": p.product,
                "version": p.version,
                "banner": p.banner,
            }
            for p in result.ports
            if p.status != "closed"
        ],
        metadata={"open_count": len([p for p in result.ports if p.status == "open"])},
    )
    return result, report


@dataclass
class FuzzOptions:
    """Fully resolved fuzzer options, independent of how they were entered."""

    target: str
    wordlist_path: str
    threads: int
    request_mode: bool
    use_baseline: bool = True
    extensions: list[str] | None = None
    recursive: bool = False
    depth: int = 1
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    data: str | None = None
    match_codes: list[int] | None = None
    filter_codes: list[int] | None = None
    filter_size: int | None = None
    filter_words: int | None = None
    filter_lines: int | None = None
    ignored_flags: list[str] = field(default_factory=list)
    config: dict = field(default_factory=dict)
    """The config these options were resolved from; carries the HTTP settings
    down to ``run_fuzz``, which otherwise only receives this object."""


def resolve_fuzz_options(
    target: str,
    config: dict,
    *,
    wordlist: str | None = None,
    threads: int = 20,
    no_baseline: bool = False,
    extensions: str | None = None,
    recursive: bool = False,
    depth: int | None = None,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: str | None = None,
    match_codes: str | None = None,
    filter_codes: str | None = None,
    filter_size: int | None = None,
    filter_words: int | None = None,
    filter_lines: int | None = None,
) -> FuzzOptions:
    """Resolve raw fuzzer input into a ``FuzzOptions``, applying config defaults.

    Detects request mode (FUZZ keyword / -X / -d) and collects the names of any
    flags that do not apply to the detected mode into ``ignored_flags`` so the
    frontend can warn about them.

    Raises:
        ValueError: If a comma-separated code list is malformed.
    """
    fuzzer_cfg = config.get("fuzzer", {})
    headers = headers or {}
    request_mode = modules.is_request_mode(target, headers=headers, data=data, method=method)

    # FUZZ-mode keeps the keyword-bearing target intact (only ensuring a
    # scheme so requests resolve); directory-mode normalizes to a clean base URL.
    if request_mode:
        normalized = target.strip()
        if not normalized.startswith(("http://", "https://")):
            normalized = f"https://{normalized}"
    else:
        normalized = normalize_url(target)

    # Extensions: -x omitted -> config default (directory mode only);
    # -x "" -> explicit opt-out (bare words only); -x "php,html" -> those.
    if extensions is None:
        ext_list = None if request_mode else fuzzer_cfg.get("extensions")
    else:
        ext_list = parse_str_list(extensions)

    match_list = parse_int_list(match_codes, "--match-codes")
    if match_list is None and request_mode:
        match_list = fuzzer_cfg.get("match_codes")

    if request_mode:
        ignored = [
            name
            for name, given in (
                ("--extensions", extensions is not None),
                ("--recursive", recursive),
                ("--depth", depth is not None),
            )
            if given
        ]
    else:
        ignored = [
            name
            for name, given in (
                ("--match-codes", bool(match_codes)),
                ("--filter-codes", bool(filter_codes)),
                ("--filter-size", filter_size is not None),
                ("--filter-words", filter_words is not None),
                ("--filter-lines", filter_lines is not None),
            )
            if given
        ]

    return FuzzOptions(
        target=normalized,
        wordlist_path=str(wordlist) if wordlist else fuzzer_cfg["wordlist"],
        threads=threads,
        request_mode=request_mode,
        use_baseline=not no_baseline,
        extensions=ext_list,
        recursive=recursive,
        depth=depth if depth is not None else fuzzer_cfg.get("recursion_depth", 1),
        method=method,
        headers=headers,
        data=data,
        match_codes=match_list,
        filter_codes=parse_int_list(filter_codes, "--filter-codes"),
        filter_size=filter_size,
        filter_words=filter_words,
        filter_lines=filter_lines,
        ignored_flags=ignored,
        config=config,
    )


async def run_fuzz(
    opts: FuzzOptions,
    *,
    on_progress: Optional[ProgressCallback] = None,
) -> RunResult:
    """Run the fuzzer with resolved options and build the ``fuzz`` envelope.

    Returns:
        ``(FuzzScanResult, report_dict)``.
    """
    result = await modules.fuzz(
        opts.target,
        opts.wordlist_path,
        opts.threads,
        use_baseline=opts.use_baseline,
        extensions=opts.extensions,
        recursive=opts.recursive,
        depth=opts.depth,
        method=opts.method,
        headers=opts.headers or None,
        data=opts.data,
        match_codes=opts.match_codes,
        filter_codes=opts.filter_codes,
        filter_size=opts.filter_size,
        filter_words=opts.filter_words,
        filter_lines=opts.filter_lines,
        on_progress=on_progress,
        client_config=client_config_for(opts.config, "fuzz"),
    )

    report = build_report(
        module="fuzz",
        target=opts.target,
        findings=[
            {
                "url": r.url,
                "status": r.status_code,
                "length": r.content_length,
                "word": r.word,
            }
            for r in result.found
        ],
        metadata={
            "mode": result.mode,
            "found_count": len(result.found),
            "scanned": result.scanned,
        },
    )
    return result, report


async def run_headers(
    target: str,
    config: dict,
    *,
    http_client: HTTPClient | None = None,
    on_progress: Optional[ProgressCallback] = None,
) -> RunResult:
    """Score security headers and build the ``headers`` report envelope.

    Returns:
        ``(HeaderResult, report_dict)``.
    """
    normalized = normalize_url(target)
    result = await modules.analyze(normalized, http_client, on_progress=on_progress)

    report = build_report(
        module="headers",
        target=normalized,
        findings=[
            {
                "header": a.header,
                "present": a.present,
                "risk": a.risk,
                "recommendation": a.recommendation,
            }
            for a in result.analysis
            if not a.present
        ],
        severity=severity_from_grade(result.grade),
        metadata={"score": result.score, "grade": result.grade},
    )
    return result, report


def _vuln_report(module: str, target: str, result: Any) -> dict:
    """Build the shared envelope used by the sqli and xss probes."""
    return build_report(
        module=module,
        target=target,
        findings=[
            {
                "url": v.url,
                "payload": v.payload,
                "type": v.type,
                "evidence": v.evidence,
            }
            for v in result.vulnerabilities
        ],
        severity="high" if result.vulnerable else "info",
        metadata={
            "vulnerable": result.vulnerable,
            "payload": result.payload,
            "tested": result.tested,
        },
    )


async def run_sqli(
    target: str,
    config: dict,
    *,
    on_progress: Optional[ProgressCallback] = None,
) -> RunResult:
    """Probe URL parameters for SQL injection and build the ``sqli`` envelope."""
    normalized = normalize_url(target)
    result = await modules.probe(
        normalized,
        on_progress=on_progress,
        client_config=client_config_for(config, "sqli"),
    )
    return result, _vuln_report("sqli", normalized, result)


async def run_xss(
    target: str,
    config: dict,
    *,
    on_progress: Optional[ProgressCallback] = None,
) -> RunResult:
    """Probe for reflected XSS and build the ``xss`` envelope."""
    normalized = normalize_url(target)
    result = await modules.detect(
        normalized,
        on_progress=on_progress,
        client_config=client_config_for(config, "xss"),
    )
    return result, _vuln_report("xss", normalized, result)


async def run_subdomain(
    target: str,
    config: dict,
    *,
    threads: int | None = None,
    include_wildcard: bool = False,
    on_progress: Optional[ProgressCallback] = None,
) -> RunResult:
    """Enumerate subdomains and build the ``subdomain`` report envelope.

    Returns:
        ``(SubdomainScanResult, report_dict)``.
    """
    domain = extract_domain(target)
    sub_cfg = config.get("subdomain", {})
    concurrency = threads if threads is not None else sub_cfg.get("threads", 20)

    result = await modules.enumerate(
        domain,
        sub_cfg["wordlist"],
        concurrency,
        include_wildcard=include_wildcard,
        on_progress=on_progress,
        client_config=client_config_for(config, "subdomain"),
    )

    report = build_report(
        module="subdomain",
        target=domain,
        findings=[
            {
                "subdomain": s.subdomain,
                "record_type": s.record_type,
                "value": s.value,
                "verified": s.verified,
            }
            for s in result.subdomains
        ],
        metadata={"found_count": len(result.subdomains), "scanned": result.scanned},
    )
    return result, report


# Order matters: the full scan runs these sequentially and the CLI prints each
# section as it completes.
SCAN_SEQUENCE = ("ports", "fuzz", "headers", "sqli", "xss", "subdomain")


async def run_full_scan(
    target: str,
    config: dict,
    *,
    on_module_start: Optional[Any] = None,
    on_module_done: Optional[Any] = None,
    on_progress: Optional[ProgressCallback] = None,
) -> RunResult:
    """Run every module in sequence and build the aggregate ``scan`` envelope.

    Args:
        target: Host or URL to scan.
        config: Parsed config dict.
        on_module_start: Called with the module id before it runs, so a
            frontend can print a section header or start a spinner.
        on_module_done: Called with ``(module_id, result)`` as each finishes,
            so a frontend can render that section's results immediately.
        on_progress: Forwarded to every module for live progress.

    Returns:
        ``(dict of per-module results, report_dict)``.
    """
    from datetime import datetime

    normalized = normalize_url(target)
    domain = extract_domain(normalized)
    scan_start = datetime.now().isoformat()

    modules_out: dict = {}
    findings: list = []
    severities: list[str] = []
    results: dict[str, Any] = {}

    def start(name: str) -> None:
        if on_module_start:
            on_module_start(name)

    def done(name: str, result: Any) -> None:
        results[name] = result
        if on_module_done:
            on_module_done(name, result)

    http = HTTPClient(client_config_from(config))
    try:
        start("ports")
        scanner_result = await modules.scan(
            domain, ports=config["scanner"]["common_ports"], on_progress=on_progress
        )
        open_ports = [p for p in scanner_result.ports if p.status == "open"]
        modules_out["scanner"] = {
            "ports": [
                {"port": p.port, "status": p.status, "service": p.service}
                for p in scanner_result.ports
            ],
            "open_count": len(open_ports),
        }
        findings.extend(
            {"module": "ports", "port": p.port, "service": p.service} for p in open_ports
        )
        done("ports", scanner_result)

        start("fuzz")
        fuzzer_result = await modules.fuzz(
            normalized,
            config["fuzzer"]["wordlist"],
            config["fuzzer"]["threads"],
            on_progress=on_progress,
        )
        modules_out["fuzzer"] = {
            "found": len(fuzzer_result.found),
            "paths": [r.url for r in fuzzer_result.found[:20]],
            "scanned": fuzzer_result.scanned,
        }
        findings.extend(
            {"module": "fuzz", "url": r.url, "status": r.status_code}
            for r in fuzzer_result.found[:20]
        )
        done("fuzz", fuzzer_result)

        start("headers")
        headers_result = await modules.analyze(normalized, http, on_progress=on_progress)
        modules_out["headers"] = {
            "score": headers_result.score,
            "grade": headers_result.grade,
            "missing": headers_result.missing_headers,
        }
        findings.extend(
            {"module": "headers", "header": h, "present": False}
            for h in headers_result.missing_headers
        )
        severities.append(severity_from_grade(headers_result.grade))
        done("headers", headers_result)

        start("sqli")
        sqli_result = await modules.probe(normalized, on_progress=on_progress)
        modules_out["sqli"] = {
            "vulnerable": sqli_result.vulnerable,
            "payload": sqli_result.payload,
        }
        if sqli_result.vulnerable:
            findings.append({"module": "sqli", "payload": sqli_result.payload, "vulnerable": True})
            severities.append("high")
        done("sqli", sqli_result)

        start("xss")
        xss_result = await modules.detect(normalized, on_progress=on_progress)
        modules_out["xss"] = {
            "vulnerable": xss_result.vulnerable,
            "payload": xss_result.payload,
        }
        if xss_result.vulnerable:
            findings.append({"module": "xss", "payload": xss_result.payload, "vulnerable": True})
            severities.append("high")
        done("xss", xss_result)

        start("subdomain")
        subdomain_result = await modules.enumerate(
            domain,
            config["subdomain"]["wordlist"],
            config["subdomain"]["threads"],
            on_progress=on_progress,
        )
        modules_out["subdomain"] = {
            "found": len(subdomain_result.subdomains),
            "subdomains": [
                {
                    "subdomain": s.subdomain,
                    "record_type": s.record_type,
                    "value": s.value,
                    "verified": s.verified,
                }
                for s in subdomain_result.subdomains[:20]
            ],
            "scanned": subdomain_result.scanned,
        }
        findings.extend(
            {"module": "subdomain", "subdomain": s.subdomain, "value": s.value}
            for s in subdomain_result.subdomains[:20]
        )
        done("subdomain", subdomain_result)
    finally:
        # Close the shared client even when a module raises or the caller
        # cancels mid-scan, so sockets never leak into the frontend's loop.
        await http.close()

    report = build_report(
        module="scan",
        target=normalized,
        findings=findings,
        severity=highest_severity(severities),
        metadata={"scan_time": scan_start, "modules": modules_out},
        timestamp=scan_start,
    )
    return results, report
