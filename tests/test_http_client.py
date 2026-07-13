import asyncio

import pytest
import respx
import httpx
from pynzor.utils.http_client import HTTPClient, ClientConfig


@pytest.mark.asyncio
async def test_request_sends_custom_method_headers_and_raw_body():
    """request() forwards the HTTP method, custom headers, and raw body content."""
    captured = {}

    def responder(request):
        captured["method"] = request.method
        captured["body"] = request.content.decode()
        captured["x_test"] = request.headers.get("X-Test")
        return httpx.Response(200, text="ok")

    with respx.mock:
        respx.route(method="PUT", host="example.com").mock(side_effect=responder)
        client = HTTPClient(ClientConfig(rate_limit=0))
        async with client:
            resp = await client.request(
                "PUT",
                "http://example.com/x",
                headers={"X-Test": "abc"},
                content="raw=body",
            )

    assert resp.status_code == 200
    assert captured["method"] == "PUT"
    assert captured["body"] == "raw=body"
    assert captured["x_test"] == "abc"


@pytest.mark.asyncio
async def test_request_defaults_to_get_with_no_body():
    """request() issues a plain GET when given no body."""
    with respx.mock:
        route = respx.get("http://example.com/").mock(return_value=httpx.Response(200, text="hi"))
        client = HTTPClient(ClientConfig(rate_limit=0))
        async with client:
            resp = await client.request("GET", "http://example.com/")

    assert resp.status_code == 200
    assert route.called


@pytest.mark.asyncio
async def test_request_without_context_manager_raises():
    """Using the client outside its async context manager is a RuntimeError."""
    client = HTTPClient(ClientConfig(rate_limit=0))
    with pytest.raises(RuntimeError):
        await client.get("http://example.com/")


@pytest.mark.asyncio
async def test_timeout_retries_then_returns_error():
    """Timeouts are retried up to max_retries, then returned as an error Response."""
    calls = 0

    def responder(request):
        nonlocal calls
        calls += 1
        raise httpx.TimeoutException("slow", request=request)

    with respx.mock:
        respx.get("http://example.com/").mock(side_effect=responder)
        client = HTTPClient(ClientConfig(rate_limit=0, max_retries=2))
        async with client:
            resp = await client.get("http://example.com/")

    assert resp.status_code == 0
    assert resp.error is not None and "Timeout" in resp.error
    assert calls == 2  # retried until the final attempt


@pytest.mark.asyncio
async def test_request_error_returns_immediately_without_retry():
    """A non-timeout request error returns at once, with no retries."""
    calls = 0

    def responder(request):
        nonlocal calls
        calls += 1
        raise httpx.ConnectError("refused", request=request)

    with respx.mock:
        respx.get("http://example.com/").mock(side_effect=responder)
        client = HTTPClient(ClientConfig(rate_limit=0, max_retries=3))
        async with client:
            resp = await client.get("http://example.com/")

    assert resp.status_code == 0
    assert resp.error is not None and "Request error" in resp.error
    assert calls == 1  # no retry for non-timeout errors


@pytest.mark.asyncio
async def test_semaphore_bounds_concurrency():
    """max_concurrency caps the number of in-flight requests at any moment."""
    in_flight = 0
    peak = 0

    async def fake_request(method, url, **kwargs):
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0.02)
        in_flight -= 1
        return httpx.Response(200, text="ok", request=httpx.Request(method, url))

    client = HTTPClient(ClientConfig(rate_limit=0, max_concurrency=2))
    async with client:
        # Replace the underlying transport call with a concurrency-tracking stub.
        client._client.request = fake_request  # type: ignore[union-attr]
        results = await asyncio.gather(*[client.get(f"http://example.com/{i}") for i in range(6)])

    assert all(r.status_code == 200 for r in results)
    assert peak <= 2
