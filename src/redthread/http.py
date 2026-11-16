from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlencode

import httpx

from redthread.audit import AuditLog
from redthread.budget import RunBudget
from redthread.errors import RequestFailed
from redthread.models import Response
from redthread.ratelimit import RateLimiter
from redthread.scope import Scope

_REDIRECTS = {301, 302, 303, 307, 308}


class HttpSession:
    def __init__(
        self,
        name: str,
        scope: Scope,
        limiter: RateLimiter,
        budget: RunBudget,
        audit: AuditLog,
        *,
        headers: dict[str, str] | None = None,
        verify_tls: bool = True,
        timeout: float = 12.0,
        max_body: int = 1_500_000,
    ):
        self.name = name
        self.scope = scope
        self.limiter = limiter
        self.budget = budget
        self.audit = audit
        self.max_body = max_body
        self._headers = {
            "User-Agent": "redthread/0.1 (+authorized exposure validation)",
            "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.7",
        }
        if headers:
            self._headers.update(headers)
        self._client = httpx.AsyncClient(
            follow_redirects=False,
            verify=verify_tls,
            timeout=httpx.Timeout(timeout, connect=min(timeout, 10.0)),
            limits=httpx.Limits(max_connections=12, max_keepalive_connections=6),
        )

    @property
    def headers(self) -> dict[str, str]:
        return dict(self._headers)

    def set_header(self, name: str, value: str) -> None:
        self._headers[name] = value

    def update_headers(self, headers: dict[str, str]) -> None:
        self._headers.update(headers)

    def cookie_names(self) -> list[str]:
        return sorted(self._client.cookies.keys())

    def set_cookie(self, name: str, value: str, *, domain: str = "", path: str = "/") -> None:
        self._client.cookies.set(name, value, domain=domain, path=path)

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        json: Any = None,
        content: bytes | str | None = None,
        follow: bool = False,
        max_redirects: int = 5,
        label: str = "",
    ) -> Response:
        method = method.upper()
        if params:
            encoded = urlencode(params, doseq=True)
            url = url + ("&" if "?" in url else "?") + encoded
        self.scope.check(url, method)

        current_method = method
        current_url = url
        current_data = data
        current_json = json
        current_content = content
        current_headers = dict(headers or {})
        history: list[str] = []

        for hop in range(max_redirects + 1):
            response = await self._send(
                current_method,
                current_url,
                headers=current_headers,
                data=current_data,
                json=current_json,
                content=current_content,
                label=label,
            )
            if not follow or response.status not in _REDIRECTS:
                if history:
                    response.history = tuple(history)
                return response

            location = response.header("location")
            if not location:
                return response
            if hop >= max_redirects:
                raise RequestFailed(f"too many redirects starting at {url}")

            history.append(current_url)
            current_url = self.scope.check_redirect(current_url, location)
            if response.status in (301, 302, 303) and current_method not in ("GET", "HEAD"):
                current_method = "GET"
                current_data = None
                current_json = None
                current_content = None
                current_headers = {
                    key: value
                    for key, value in current_headers.items()
                    if key.lower() not in ("content-type", "content-length")
                }

        raise RequestFailed("redirect loop")

    async def _send(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None,
        data: dict[str, Any] | None,
        json: Any,
        content: bytes | str | None,
        label: str,
    ) -> Response:
        self.budget.consume_request()
        await self.limiter.acquire()

        merged = dict(self._headers)
        if headers:
            merged.update(headers)
        request = self._client.build_request(
            method,
            url,
            headers=merged,
            data=data,
            json=json,
            content=content,
        )
        started = time.perf_counter()
        body = bytearray()
        status: int | None = None
        response_headers: dict[str, str] = {}
        set_cookies: tuple[str, ...] = ()
        try:
            raw = await self._client.send(request, stream=True)
            status = raw.status_code
            response_headers = {k.lower(): v for k, v in raw.headers.items()}
            set_cookies = tuple(raw.headers.get_list("set-cookie"))
            async for chunk in raw.aiter_bytes():
                body.extend(chunk)
                if len(body) >= self.max_body:
                    break
            await raw.aclose()
        except httpx.HTTPError as exc:
            elapsed_ms = (time.perf_counter() - started) * 1000
            self.audit.request(
                identity=self.name,
                method=method,
                url=url,
                status=None,
                elapsed_ms=elapsed_ms,
                error=f"{type(exc).__name__}: {exc}",
            )
            raise RequestFailed(f"{method} {url} failed: {exc}") from exc

        elapsed_ms = (time.perf_counter() - started) * 1000
        self.audit.request(
            identity=self.name,
            method=method,
            url=url,
            status=status,
            bytes_read=len(body),
            elapsed_ms=elapsed_ms,
        )
        if label:
            self.audit.record("probe", identity=self.name, label=label, url=url, status=status)
        return Response(
            url=url,
            status=status or 0,
            headers=response_headers,
            body=bytes(body),
            elapsed_ms=elapsed_ms,
            set_cookies=set_cookies,
        )

    async def close(self) -> None:
        await self._client.aclose()
