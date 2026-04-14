import pytest
import respx
import httpx
from modules.sqli import _test_payload, probe_sqli, SQLiVulnerability
from utils.http_client import HTTPClient, ClientConfig


@pytest.mark.asyncio
async def test_test_payload_error_signature_detected():
    config = ClientConfig(rate_limit=0)
    client = HTTPClient(config)
    payload = "' OR '1'='1"
    url = f"http://example.com/?id={payload}"
    with respx.mock:
        respx.get(url).mock(
            return_value=httpx.Response(200, text="You have an error in SQL syntax near line 1")
        )
        async with client:
            result = await _test_payload(client, "http://example.com/", "id", payload)
    assert isinstance(result, SQLiVulnerability)
    assert result.type == "error-based"


@pytest.mark.asyncio
async def test_test_payload_clean_response_returns_none():
    config = ClientConfig(rate_limit=0)
    client = HTTPClient(config)
    payload = "' OR '1'='1"
    url = f"http://example.com/?id={payload}"
    with respx.mock:
        respx.get(url).mock(
            return_value=httpx.Response(200, text="<html><body>Welcome</body></html>")
        )
        async with client:
            result = await _test_payload(client, "http://example.com/", "id", payload)
    assert result is None


@pytest.mark.asyncio
async def test_probe_sqli_no_params_returns_empty():
    result = await probe_sqli("http://example.com/search")
    assert result.tested == 0
    assert result.vulnerabilities == []
    assert not result.vulnerable


@pytest.mark.asyncio
async def test_probe_sqli_finds_vulnerability():
    with respx.mock:
        respx.get(url__regex=r"http://example\.com/\?id=.*").mock(
            return_value=httpx.Response(200, text="mysql_fetch_array() error occurred")
        )
        result = await probe_sqli("http://example.com/?id=1", max_payloads=2, threads=2)
    assert result.vulnerable
    assert len(result.vulnerabilities) > 0
