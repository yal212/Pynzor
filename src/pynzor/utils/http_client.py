import asyncio
from typing import Optional
import httpx
from dataclasses import dataclass
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
    """An HTTP response, or a failed request when ``error`` is set."""

    url: str
    status_code: int
    headers: dict
    body: Optional[str]
    latency: float
    error: Optional[str] = None


@dataclass
class ClientConfig:
    """Configuration for an :class:`HTTPClient` (timeouts, retries, rate limit)."""

    timeout: float = 10.0
    max_retries: int = 3
    rate_limit: float = 0.1
    max_concurrency: int = 50
    user_agent: Optional[str] = None
    follow_redirects: bool = True
    verify_ssl: bool = True


class HTTPClient:
    """Async HTTP client wrapping httpx with retries and rate limiting.

    Intended for use as an async context manager (``async with HTTPClient()``),
    which opens and closes the underlying httpx client.
    """

    def __init__(self, config: Optional[ClientConfig] = None):
        """Initialize the client.

        Args:
            config: Optional client configuration; defaults to ``ClientConfig()``.
        """
        self.config = config or ClientConfig()
        self._client: Optional[httpx.AsyncClient] = None
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._last_request_time: float = 0

    async def __aenter__(self):
        """Open the underlying httpx client and return self.

        Returns:
            The ready-to-use :class:`HTTPClient` instance.
        """
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
        self._semaphore = asyncio.Semaphore(self.config.max_concurrency)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Close the underlying httpx client on context exit."""
        if self._client:
            await self._client.aclose()
        self._client = None

    async def close(self) -> None:
        """Close the underlying httpx client if open.

        Several call sites in the codebase call ``await http.close()`` rather
        than relying solely on the async context manager. Provide an
        idempotent async close method so callers can safely close the client
        whether it was entered via ``async with`` or instantiated manually.
        """
        if self._client:
            try:
                await self._client.aclose()
            finally:
                self._client = None

    # alias for compatibility with httpx naming
    aclose = close

    async def get(self, url: str) -> Response:
        """Send a GET request.

        Args:
            url: Target URL.

        Returns:
            The :class:`Response`.
        """
        return await self._request("GET", url)

    async def post(
        self, url: str, data: Optional[dict] = None, json: Optional[dict] = None
    ) -> Response:
        """Send a POST request with form or JSON data.

        Args:
            url: Target URL.
            data: Optional form-encoded body.
            json: Optional JSON body.

        Returns:
            The :class:`Response`.
        """
        return await self._request("POST", url, data=data, json=json)

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        data: Optional[dict] = None,
        json: Optional[dict] = None,
        content: Optional[str] = None,
    ) -> Response:
        """Send a request with an arbitrary method, per-request headers, and an
        optional raw body (``content``, the ``--data-binary`` equivalent)."""
        return await self._request(
            method, url, data=data, json=json, headers=headers, content=content
        )

    async def _request(
        self,
        method: str,
        url: str,
        data: Optional[dict] = None,
        json: Optional[dict] = None,
        headers: Optional[dict] = None,
        content: Optional[str] = None,
    ) -> Response:
        """Perform a request with rate limiting and retry handling.

        Retries on timeouts up to ``config.max_retries``; other request errors
        return immediately. Failures are returned as a :class:`Response` with
        ``status_code`` 0 and ``error`` set rather than raising.

        Args:
            method: HTTP method.
            url: Target URL.
            data: Optional form-encoded body.
            json: Optional JSON body.
            headers: Optional per-request headers.
            content: Optional raw body (``--data-binary`` equivalent).

        Returns:
            The :class:`Response`, including the error path.

        Raises:
            RuntimeError: If the client was not opened as a context manager.
        """
        if self._client is None or self._semaphore is None:
            raise RuntimeError("HTTPClient must be used as context manager")

        async with self._semaphore:
            await self._rate_limit()

            for attempt in range(self.config.max_retries):
                try:
                    start = datetime.now()
                    response = await self._client.request(
                        method,
                        url,
                        data=data,
                        json=json,
                        headers=headers,
                        content=content,
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
        """Sleep as needed to honor the configured minimum inter-request delay."""
        now = asyncio.get_event_loop().time()
        elapsed = now - self._last_request_time
        if elapsed < self.config.rate_limit:
            await asyncio.sleep(self.config.rate_limit - elapsed)
        self._last_request_time = asyncio.get_event_loop().time()
