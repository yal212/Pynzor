import pytest
import respx
import httpx
from utils.http_client import HTTPClient, ClientConfig


@pytest.mark.asyncio
async def test_request_sends_custom_method_headers_and_raw_body():
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
    with respx.mock:
        route = respx.get("http://example.com/").mock(
            return_value=httpx.Response(200, text="hi")
        )
        client = HTTPClient(ClientConfig(rate_limit=0))
        async with client:
            resp = await client.request("GET", "http://example.com/")

    assert resp.status_code == 200
    assert route.called
