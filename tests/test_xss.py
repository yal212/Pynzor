import pytest
import respx
import httpx
from modules.xss import _check_reflected, _test_payload, detect_xss, XSSVulnerability
from utils.http_client import HTTPClient, ClientConfig


def test_check_reflected_exact():
    assert _check_reflected("<script>alert(1)</script>", "<script>alert(1)</script>")


def test_check_reflected_encoded():
    payload = "<script>alert(1)</script>"
    encoded_html = "&lt;script&gt;alert(1)&lt;/script&gt;"
    assert _check_reflected(encoded_html, payload)


def test_check_reflected_not_present():
    assert not _check_reflected("<html><body>hello</body></html>", "<script>alert(1)</script>")


@pytest.mark.asyncio
async def test_test_payload_no_reflection():
    config = ClientConfig(rate_limit=0)
    client = HTTPClient(config)
    with respx.mock:
        respx.get("http://example.com/?x=<script>alert(1)</script>").mock(
            return_value=httpx.Response(200, text="<html><body>clean</body></html>")
        )
        async with client:
            result = await _test_payload(client, "http://example.com/?x=<script>alert(1)</script>", "<script>alert(1)</script>")
    assert result is None


@pytest.mark.asyncio
async def test_test_payload_reflected_in_script_context():
    payload = "<script>alert(1)</script>"
    config = ClientConfig(rate_limit=0)
    client = HTTPClient(config)
    with respx.mock:
        respx.get(f"http://example.com/?x={payload}").mock(
            return_value=httpx.Response(
                200,
                text=f"<html><body><script>{payload}</script></body></html>",
            )
        )
        async with client:
            result = await _test_payload(client, f"http://example.com/?x={payload}", payload)
    assert isinstance(result, XSSVulnerability)
    assert result.type == "stored"


@pytest.mark.asyncio
async def test_test_payload_only_html_encoded_reflection_returns_none():
    payload = "<script>alert(1)</script>"
    encoded = "&lt;script&gt;alert(1)&lt;/script&gt;"
    config = ClientConfig(rate_limit=0)
    client = HTTPClient(config)
    with respx.mock:
        respx.get(f"http://example.com/?x={payload}").mock(
            return_value=httpx.Response(200, text=f"<html><body>{encoded}</body></html>")
        )
        async with client:
            result = await _test_payload(client, f"http://example.com/?x={payload}", payload)
    # HTML-encoded means no executable context — should be None after Fix 1
    assert result is None


@pytest.mark.asyncio
async def test_detect_xss_no_params_returns_empty():
    result = await detect_xss("http://example.com/path")
    assert result.tested == 0
    assert result.vulnerabilities == []
    assert not result.vulnerable
