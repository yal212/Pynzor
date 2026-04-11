import asyncio
import dns.resolver
import dns.reversename
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime
from utils.http_client import HTTPClient, ClientConfig
from utils.validators import extract_domain, extract_root_domain
import socket


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


async def enumerate_subdomains(
    target: str,
    wordlist: list[str],
    threads: int = 20,
    check_http: bool = True,
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

    async def check_subdomain(sub: str) -> Optional[SubdomainResult]:
        nonlocal errors, scanned
        full_domain = f"{sub}.{root_domain}"
        scanned += 1

        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3.0
            resolver.lifetime = 3.0

            try:
                answers = resolver.resolve(full_domain, "A")
                values = [str(rdata) for rdata in answers]
                return SubdomainResult(
                    subdomain=full_domain,
                    record_type="A",
                    value=", ".join(values),
                    verified=True,
                )
            except dns.resolver.NXDOMAIN:
                pass
            except dns.resolver.NoAnswer:
                pass
            except Exception:
                pass

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
                pass

            if check_http:
                try:
                    http_url = f"https://{full_domain}"
                    async with http_client:
                        response = await http_client.get(http_url)

                    if not response.error and response.status_code < 500:
                        return SubdomainResult(
                            subdomain=full_domain,
                            record_type="HTTP",
                            value=f"HTTP {response.status_code}",
                            verified=False,
                        )
                except Exception:
                    pass

        except Exception as e:
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
    result.end_time = datetime.now()

    return result
