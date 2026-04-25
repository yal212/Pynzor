import asyncio
import uuid
import dns.resolver
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime
from utils.http_client import HTTPClient, ClientConfig
from utils.validators import extract_domain, extract_root_domain


DNS_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]


@dataclass
class SubdomainResult:
    subdomain: str
    record_type: str
    value: str
    verified: bool


@dataclass
class SubdomainScanResult:
    target: str
    start_time: datetime
    end_time: datetime
    subdomains: list[SubdomainResult] = field(default_factory=list)
    scanned: int = 0
    errors: int = 0
    wildcard_detected: bool = False
    wildcard_ips: list[str] = field(default_factory=list)
    wildcard_filtered: int = 0


def _build_resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 3.0
    return resolver


async def detect_wildcard(
    resolver: dns.resolver.Resolver, root_domain: str
) -> Optional[set[str]]:
    """Probe for wildcard DNS by resolving two random subdomains.

    Returns the set of IPs the wildcard resolves to, or None if no wildcard.
    """
    probes = [f"pynzor-wildcard-{uuid.uuid4().hex[:16]}.{root_domain}" for _ in range(2)]

    def resolve(name: str) -> Optional[set[str]]:
        try:
            answers = resolver.resolve(name, "A")
            return {str(r) for r in answers}
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            return None
        except Exception:
            return None

    loop = asyncio.get_event_loop()
    first, second = await asyncio.gather(
        loop.run_in_executor(None, resolve, probes[0]),
        loop.run_in_executor(None, resolve, probes[1]),
    )

    if not first or not second:
        return None

    if first & second:
        return first | second
    return None


async def enumerate_subdomains(
    target: str,
    wordlist: list[str],
    threads: int = 20,
    check_http: bool = True,
    include_wildcard: bool = False,
) -> SubdomainScanResult:
    start_time = datetime.now()
    result = SubdomainScanResult(
        target=target, start_time=start_time, end_time=start_time
    )

    root_domain = extract_root_domain(extract_domain(target))

    config = ClientConfig(rate_limit=0.1)
    http_client = HTTPClient(config)

    subdomains = []
    errors = 0
    scanned = 0
    wildcard_filtered = 0
    counter_lock = asyncio.Lock()

    resolver = _build_resolver()
    wildcard_ips = await detect_wildcard(resolver, root_domain)
    if wildcard_ips:
        result.wildcard_detected = True
        result.wildcard_ips = sorted(wildcard_ips)

    async def check_subdomain(sub: str) -> Optional[SubdomainResult]:
        nonlocal errors, scanned, wildcard_filtered
        full_domain = f"{sub}.{root_domain}"
        async with counter_lock:
            scanned += 1

        try:
            try:
                answers = resolver.resolve(full_domain, "A")
                values = {str(rdata) for rdata in answers}

                if wildcard_ips and values.issubset(wildcard_ips):
                    async with counter_lock:
                        wildcard_filtered += 1
                    if not include_wildcard:
                        return None
                    return SubdomainResult(
                        subdomain=full_domain,
                        record_type="WILDCARD",
                        value=", ".join(sorted(values)),
                        verified=False,
                    )

                return SubdomainResult(
                    subdomain=full_domain,
                    record_type="A",
                    value=", ".join(sorted(values)),
                    verified=True,
                )
            except dns.resolver.NXDOMAIN:
                pass
            except dns.resolver.NoAnswer:
                pass
            except Exception:
                async with counter_lock:
                    errors += 1

            try:
                answers = resolver.resolve(full_domain, "CNAME")
                values = [str(rdata.target) for rdata in answers]
                return SubdomainResult(
                    subdomain=full_domain,
                    record_type="CNAME",
                    value=", ".join(values),
                    verified=True,
                )
            except dns.resolver.NXDOMAIN:
                pass
            except dns.resolver.NoAnswer:
                pass
            except Exception:
                async with counter_lock:
                    errors += 1

            # Skip HTTP-only verification when a wildcard is present: the
            # wildcard would make every HTTP check pass and reintroduce the
            # false positives the DNS filter just removed.
            if check_http and not wildcard_ips:
                try:
                    http_url = f"https://{full_domain}"
                    response = await http_client.get(http_url)

                    if not response.error and response.status_code < 500:
                        return SubdomainResult(
                            subdomain=full_domain,
                            record_type="HTTP",
                            value=f"HTTP {response.status_code}",
                            verified=False,
                        )
                except Exception:
                    async with counter_lock:
                        errors += 1

        except Exception:
            async with counter_lock:
                errors += 1

        return None

    semaphore = asyncio.Semaphore(threads)

    async def limited_check(sub: str) -> Optional[SubdomainResult]:
        async with semaphore:
            return await check_subdomain(sub)

    async with http_client:
        tasks = [limited_check(sub) for sub in wordlist]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, SubdomainResult):
                subdomains.append(r)
            elif isinstance(r, Exception):
                errors += 1

    result.subdomains = subdomains
    result.scanned = scanned
    result.errors = errors
    result.wildcard_filtered = wildcard_filtered
    result.end_time = datetime.now()

    return result
