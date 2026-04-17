import pytest
import respx
import httpx
from modules.sqli import (
    _test_payload,
    _test_time_based,
    _test_boolean_blind,
    _test_payload_post,
    _extract_forms,
    probe_sqli,
    SQLiVulnerability,
    TIME_BASED_THRESHOLD,
)
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
    with respx.mock:
        respx.get("http://example.com/search").mock(
            return_value=httpx.Response(200, text="<html><body>nothing</body></html>")
        )
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


# --- New error signature tests ---

@pytest.mark.asyncio
async def test_mssql_error_signature_detected():
    config = ClientConfig(rate_limit=0)
    client = HTTPClient(config)
    payload = "' OR '1'='1"
    url = f"http://example.com/?id={payload}"
    with respx.mock:
        respx.get(url).mock(
            return_value=httpx.Response(200, text="Microsoft SQL Native Error in query")
        )
        async with client:
            result = await _test_payload(client, "http://example.com/", "id", payload)
    assert isinstance(result, SQLiVulnerability)
    assert result.type == "error-based"


@pytest.mark.asyncio
async def test_sqlite_error_signature_detected():
    config = ClientConfig(rate_limit=0)
    client = HTTPClient(config)
    payload = "' OR '1'='1"
    url = f"http://example.com/?id={payload}"
    with respx.mock:
        respx.get(url).mock(
            return_value=httpx.Response(200, text="sqlite3.OperationalError: near '1': syntax error")
        )
        async with client:
            result = await _test_payload(client, "http://example.com/", "id", payload)
    assert isinstance(result, SQLiVulnerability)
    assert result.type == "error-based"


# --- Time-based blind SQLi tests ---

@pytest.mark.asyncio
async def test_time_based_blind_detected():
    config = ClientConfig(rate_limit=0)
    client = HTTPClient(config)
    with respx.mock:
        # All time-based payloads return with simulated high latency
        respx.get(url__regex=r"http://example\.com/\?id=.*SLEEP.*").mock(
            return_value=httpx.Response(200, text="<html>ok</html>")
        )
        respx.get(url__regex=r"http://example\.com/\?id=.*WAITFOR.*").mock(
            return_value=httpx.Response(200, text="<html>ok</html>")
        )
        respx.get(url__regex=r"http://example\.com/\?id=.*BENCHMARK.*").mock(
            return_value=httpx.Response(200, text="<html>ok</html>")
        )
        respx.get(url__regex=r"http://example\.com/\?id=.*pg_sleep.*").mock(
            return_value=httpx.Response(200, text="<html>ok</html>")
        )
        respx.get(url__regex=r"http://example\.com/\?id=.*SELECT.*").mock(
            return_value=httpx.Response(200, text="<html>ok</html>")
        )
        async with client:
            # Patch latency directly on the first response
            from unittest.mock import patch, AsyncMock
            from utils.http_client import Response as HttpResponse

            async def fake_get(url):
                return HttpResponse(
                    url=url,
                    status_code=200,
                    headers={},
                    body="<html>ok</html>",
                    latency=5.0,
                )

            with patch.object(client, "get", side_effect=fake_get):
                result = await _test_time_based(client, "http://example.com/", "id")
    assert isinstance(result, SQLiVulnerability)
    assert result.type == "blind-time"
    assert "5.0s" in result.evidence


@pytest.mark.asyncio
async def test_time_based_blind_not_triggered_fast_response():
    config = ClientConfig(rate_limit=0)
    client = HTTPClient(config)
    async with client:
        from unittest.mock import patch
        from utils.http_client import Response as HttpResponse

        async def fast_get(url):
            return HttpResponse(
                url=url, status_code=200, headers={}, body="ok", latency=0.1
            )

        with patch.object(client, "get", side_effect=fast_get):
            result = await _test_time_based(client, "http://example.com/", "id")
    assert result is None


# --- Boolean-based blind SQLi tests ---

@pytest.mark.asyncio
async def test_boolean_blind_detected():
    config = ClientConfig(rate_limit=0)
    client = HTTPClient(config)
    async with client:
        from unittest.mock import patch
        from utils.http_client import Response as HttpResponse

        # True condition returns longer body than false condition
        call_count = 0

        async def toggling_get(url):
            nonlocal call_count
            call_count += 1
            if "1=1" in url:
                body = "<html><body>Welcome back, admin! You have 5 messages.</body></html>"
            else:
                body = "<html><body>No results.</body></html>"
            return HttpResponse(
                url=url, status_code=200, headers={}, body=body, latency=0.1
            )

        with patch.object(client, "get", side_effect=toggling_get):
            result = await _test_boolean_blind(client, "http://example.com/", "id")
    assert isinstance(result, SQLiVulnerability)
    assert result.type == "blind-boolean"
    assert "differ" in result.evidence


@pytest.mark.asyncio
async def test_boolean_blind_not_triggered_identical_responses():
    config = ClientConfig(rate_limit=0)
    client = HTTPClient(config)
    async with client:
        from unittest.mock import patch
        from utils.http_client import Response as HttpResponse

        async def same_get(url):
            return HttpResponse(
                url=url, status_code=200, headers={}, body="<html>same</html>", latency=0.1
            )

        with patch.object(client, "get", side_effect=same_get):
            result = await _test_boolean_blind(client, "http://example.com/", "id")
    assert result is None


# --- POST form scanning tests ---

def test_extract_forms_basic():
    html = """
    <html><body>
      <form action="/login" method="post">
        <input name="username" type="text">
        <input name="password" type="password">
      </form>
    </body></html>
    """
    forms = _extract_forms(html, "http://example.com")
    assert len(forms) == 1
    assert forms[0]["action"] == "http://example.com/login"
    assert forms[0]["method"] == "post"
    assert "username" in forms[0]["fields"]
    assert "password" in forms[0]["fields"]


def test_extract_forms_no_forms():
    html = "<html><body><p>No forms</p></body></html>"
    assert _extract_forms(html, "http://example.com") == []


@pytest.mark.asyncio
async def test_post_form_sqli_detected():
    payload = "' OR '1'='1"
    config = ClientConfig(rate_limit=0)
    client = HTTPClient(config)
    with respx.mock:
        respx.post("http://example.com/login").mock(
            return_value=httpx.Response(
                200, text="Warning: mysql_fetch_array() expects parameter 1"
            )
        )
        async with client:
            result = await _test_payload_post(
                client,
                "http://example.com/login",
                ["username", "password"],
                payload,
            )
    assert isinstance(result, SQLiVulnerability)
    assert result.type == "error-based"
    assert "POST" in result.evidence


@pytest.mark.asyncio
async def test_probe_sqli_scans_post_form():
    with respx.mock:
        # Page fetch returns a login form
        respx.get("http://example.com/login").mock(
            return_value=httpx.Response(
                200,
                text='<html><body><form action="/login" method="post"><input name="user"><input name="pass"></form></body></html>',
            )
        )
        # POST triggers SQL error
        respx.post("http://example.com/login").mock(
            return_value=httpx.Response(
                200, text="mysql_fetch_array() error"
            )
        )
        result = await probe_sqli("http://example.com/login", max_payloads=2, threads=2)
    assert result.vulnerable
    assert any(v.type == "error-based" for v in result.vulnerabilities)
