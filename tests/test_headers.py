import pytest
import respx
import httpx
from modules.headers import analyze_headers, HeaderResult


@pytest.mark.asyncio
async def test_analyze_headers_all_missing_grade_f():
    with respx.mock:
        respx.get("http://example.com/").mock(
            return_value=httpx.Response(200, headers={"content-type": "text/html"})
        )
        result = await analyze_headers("http://example.com/")
    assert result.score <= 40
    assert result.grade == "F"
    assert isinstance(result.missing_headers, list)
    assert len(result.missing_headers) > 0


@pytest.mark.asyncio
async def test_analyze_headers_error_path_returns_list_not_none():
    with respx.mock:
        respx.get("http://example.com/").mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )
        result = await analyze_headers("http://example.com/")
    # Fix 3: error path must return list, not None
    assert isinstance(result.analysis, list)
    assert isinstance(result.missing_headers, list)


@pytest.mark.asyncio
async def test_analyze_headers_with_security_headers():
    headers = {
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "geolocation=()",
        "cross-origin-opener-policy": "same-origin",
        "cross-origin-embedder-policy": "require-corp",
        "cross-origin-resource-policy": "same-origin",
        "x-xss-protection": "1; mode=block",
    }
    with respx.mock:
        respx.get("http://example.com/").mock(
            return_value=httpx.Response(200, headers=headers)
        )
        result = await analyze_headers("http://example.com/")
    assert result.score >= 90
    assert result.grade == "A"
    assert result.missing_headers == []
