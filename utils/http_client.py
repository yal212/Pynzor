import asyncio
from typing import Optional
import httpx
from dataclasses import dataclass, field
from datetime import datetime


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]


@dataclass
class Response:
    url: str
    status_code: int
    headers: dict
    body: Optional[str]
    latency: float
    error: Optional[str] = None


@dataclass
class ClientConfig:
    timeout: float = 10.0
    max_retries: int = 3
    rate_limit: float = 0.1
    user_agent: Optional[str] = None
    follow_redirects: bool = True
    verify_ssl: bool = True


class HTTPClient:
    def __init__(self, config: Optional[ClientConfig] = None):
        self.config = config or ClientConfig()
        self._client: Optional[httpx.AsyncClient] = None
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._last_request_time: float = 0

    async def __aenter__(self):
        headers = {}
        if self.config.user_agent:
            headers["User-Agent"] = self.config.user_agent
        else:
            headers["User-Agent"] = USER_AGENTS[0]

        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.config.timeout),
            follow_redirects=self.config.follow_redirects,
            verify=self.config.verify_ssl,
            headers=headers,
        )
        self._semaphore = asyncio.Semaphore(50)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            await self._client.aclose()
        self._client = None

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def get(self, url: str) -> Response:
        return await self._request("GET", url)

    async def post(
        self, url: str, data: Optional[dict] = None, json: Optional[dict] = None
    ) -> Response:
        return await self._request("POST", url, data=data, json=json)

    async def _request(
        self,
        method: str,
        url: str,
        data: Optional[dict] = None,
        json: Optional[dict] = None,
    ) -> Response:
        if not self._client:
            raise RuntimeError("HTTPClient must be used as context manager")

        await self._rate_limit()

        for attempt in range(self.config.max_retries):
            try:
                start = datetime.now()
                response = await self._client.request(
                    method,
                    url,
                    data=data,
                    json=json,
                )
                latency = (datetime.now() - start).total_seconds()

                return Response(
                    url=str(response.url),
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    body=response.text,
                    latency=latency,
                )
            except httpx.TimeoutException as e:
                if attempt == self.config.max_retries - 1:
                    return Response(
                        url=url,
                        status_code=0,
                        headers={},
                        body=None,
                        latency=0,
                        error=f"Timeout: {e}",
                    )
            except httpx.RequestError as e:
                return Response(
                    url=url,
                    status_code=0,
                    headers={},
                    body=None,
                    latency=0,
                    error=f"Request error: {e}",
                )
            except Exception as e:
                return Response(
                    url=url,
                    status_code=0,
                    headers={},
                    body=None,
                    latency=0,
                    error=str(e),
                )

            await asyncio.sleep(0.5 * (attempt + 1))

        return Response(
            url=url,
            status_code=0,
            headers={},
            body=None,
            latency=0,
            error="Max retries exceeded",
        )

    async def _rate_limit(self):
        now = asyncio.get_event_loop().time()
        elapsed = now - self._last_request_time
        if elapsed < self.config.rate_limit:
            await asyncio.sleep(self.config.rate_limit - elapsed)
        self._last_request_time = asyncio.get_event_loop().time()
