import pytest
import respx
import httpx
from modules.xss import (
    _check_reflected,
    _is_raw_reflected,
    _is_encoded_reflected,
    _test_payload,
    _extract_forms,
    detect_xss,
    XSSVulnerability,
)
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
    with respx.mock:
        respx.get("http://example.com/path").mock(
            return_value=httpx.Response(200, text="<html><body>nothing</body></html>")
        )
        result = await detect_xss("http://example.com/path")
    assert result.tested == 0
    assert result.vulnerabilities == []
    assert not result.vulnerable


def test_is_raw_reflected_true():
    assert _is_raw_reflected("<img src=x onerror=alert(1)>", "<img src=x onerror=alert(1)>")


def test_is_raw_reflected_false():
    assert not _is_raw_reflected("<html>safe</html>", "<img src=x onerror=alert(1)>")


def test_is_encoded_reflected_true():
    payload = "<script>alert(1)</script>"
    assert _is_encoded_reflected("&lt;script&gt;alert(1)&lt;/script&gt;", payload)


def test_is_encoded_reflected_false():
    assert not _is_encoded_reflected("<html>safe</html>", "<script>alert(1)</script>")


@pytest.mark.asyncio
async def test_img_onerror_reflected_detected():
    payload = "<img src=x onerror=alert(1)>"
    config = ClientConfig(rate_limit=0)
    client = HTTPClient(config)
    with respx.mock:
        respx.get(f"http://example.com/?q={payload}").mock(
            return_value=httpx.Response(
                200,
                text=f"<html><body>You searched: {payload}</body></html>",
            )
        )
        async with client:
            result = await _test_payload(client, f"http://example.com/?q={payload}", payload)
    assert isinstance(result, XSSVulnerability)
    assert result.type == "reflected"


@pytest.mark.asyncio
async def test_attr_payload_reflected_detected():
    payload = '" onerror="alert(1)'
    config = ClientConfig(rate_limit=0)
    client = HTTPClient(config)
    with respx.mock:
        respx.get(f"http://example.com/?q={payload}").mock(
            return_value=httpx.Response(
                200,
                text=f'<html><body><input value="{payload}"></body></html>',
            )
        )
        async with client:
            result = await _test_payload(client, f"http://example.com/?q={payload}", payload)
    assert isinstance(result, XSSVulnerability)
    assert result.type == "reflected"


def test_extract_forms_basic():
    html = """
    <html><body>
      <form action="/search" method="post">
        <input name="q" type="text">
        <input name="submit" type="submit">
      </form>
    </body></html>
    """
    forms = _extract_forms(html, "http://example.com")
    assert len(forms) == 1
    assert forms[0]["action"] == "http://example.com/search"
    assert forms[0]["method"] == "post"
    assert "q" in forms[0]["fields"]


def test_extract_forms_no_forms():
    html = "<html><body><p>No forms here</p></body></html>"
    assert _extract_forms(html, "http://example.com") == []


@pytest.mark.asyncio
async def test_post_form_scanning():
    payload = "<script>alert(1)</script>"
    config = ClientConfig(rate_limit=0)
    client = HTTPClient(config)
    with respx.mock:
        # Page fetch returns a form
        respx.get("http://example.com/form").mock(
            return_value=httpx.Response(
                200,
                text='<html><body><form action="/submit" method="post"><input name="msg"></form></body></html>',
            )
        )
        # POST submission reflects the payload
        respx.post("http://example.com/submit").mock(
            return_value=httpx.Response(
                200,
                text=f"<html><body>You said: {payload}</body></html>",
            )
        )
        async with client:
            from modules.xss import _test_payload_post, _extract_forms
            page_html = '<html><body><form action="/submit" method="post"><input name="msg"></form></body></html>'
            forms = _extract_forms(page_html, "http://example.com")
            result = await _test_payload_post(
                client, forms[0]["action"], forms[0]["fields"], payload
            )
    assert isinstance(result, XSSVulnerability)
    assert result.type == "reflected"
