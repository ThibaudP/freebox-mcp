"""The authenticated httpx client that FastMCP drives.

Responsibilities layered on a plain httpx.AsyncClient:
  * resolve the API prefix (``/api/v{major}``) lazily from discovery on the
    pinned HTTPS origin, and fail the call — never fall back — if that fails;
  * enforce the runtime endpoint policy (``policy.authorize``) on the raw,
    still-encoded path of every request and rewrite it to the canonical form;
  * inject the ``X-Fbx-App-Auth`` session header, opening/refreshing the session
    lazily and transparently retrying once on ``auth_required``;
  * unwrap the Freebox ``APIResponse`` envelope so tools return ``result`` and
    surface ``success: false``, redirects and non-JSON replies as clean errors.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re

import httpx

from .auth import FreeboxError, Session, TokenStore, open_session
from .config import Settings
from .discovery import Endpoint, afetch_discovery, choose_endpoint
from .policy import PolicyError, authorize
from .tls import freebox_ssl_context

log = logging.getLogger("freebox_mcp.client")

# Field names whose values are secrets (Wi-Fi keys, WPS PINs, passwords, tokens).
_SECRET_FIELD_RE = re.compile(
    r"(?i)(^key$|_key$|^key_|^psk$|passphrase|password|passwd|secret|token|(^|_)pin$)"
)
REDACTED = "<redacted>"


def redact(data: object) -> object:
    """Recursively replace secret-named values; identifiers (MAC/IP/ids) are kept."""
    if isinstance(data, dict):
        return {
            k: REDACTED if _SECRET_FIELD_RE.search(str(k)) else redact(v) for k, v in data.items()
        }
    if isinstance(data, list):
        return [redact(v) for v in data]
    return data


class SessionManager:
    """Lazily resolves the endpoint, opens and caches a Freebox session."""

    def __init__(
        self,
        raw: httpx.AsyncClient,
        settings: Settings,
        store: TokenStore,
        endpoint: Endpoint | None = None,
    ):
        self._raw = raw
        self._settings = settings
        self._store = store
        self._endpoint = endpoint
        self._app_id = settings.app_id
        self._app_token: str | None = None
        self._token: str | None = None
        self.permissions: dict = {}
        self._lock = asyncio.Lock()
        self._endpoint_lock = asyncio.Lock()

    @property
    def registered(self) -> bool:
        return bool(self._app_token)

    async def endpoint(self) -> Endpoint:
        if self._endpoint is None:
            async with self._endpoint_lock:
                if self._endpoint is None:
                    discovery = await afetch_discovery(self._settings, self._raw)
                    self._endpoint = choose_endpoint(self._settings, discovery)
        return self._endpoint

    async def prefix(self) -> str:
        return (await self.endpoint()).api_path_prefix

    async def get_token(self) -> str:
        if self._token:
            return self._token
        async with self._lock:
            # double-checked: another caller may have opened the session while we waited
            if self._token:
                return self._token
            return await self._open()

    async def refresh(self) -> str:
        async with self._lock:
            return await self._open()

    async def _open(self) -> str:
        """Open a new session. The caller must hold self._lock."""
        endpoint = await self.endpoint()
        creds = self._store.get(endpoint.discovery.uid)
        if creds:
            self._app_token, self._app_id = creds.app_token, creds.app_id
        if not self._app_token:
            raise FreeboxError(
                "This app is not authorized on the Freebox yet. Run `freebox-mcp authorize` "
                "and press the button on the Freebox front panel.",
                error_code="not_registered",
            )
        session: Session = await open_session(
            self._raw, endpoint.api_path_prefix, self._app_id, self._app_token
        )
        self._token = session.session_token
        self.permissions = session.permissions
        log.debug("opened Freebox session (permissions: %s)", sorted(session.permissions))
        return self._token

    async def aclose(self) -> None:
        await self._raw.aclose()


class FreeboxTransport(httpx.AsyncBaseTransport):
    """Unwraps the APIResponse envelope and retries once on auth_required."""

    def __init__(self, inner: httpx.AsyncBaseTransport, session: SessionManager):
        self._inner = inner
        self._session = session

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self._inner.handle_async_request(request)
        await response.aread()
        unwrapped, retry = self._process(response, request, allow_retry=True)
        if retry:
            # refresh session, re-inject header, resend once
            token = await self._session.refresh()
            request.headers["X-Fbx-App-Auth"] = token
            response = await self._inner.handle_async_request(request)
            await response.aread()
            unwrapped, _ = self._process(response, request, allow_retry=False)
        return unwrapped

    def _process(
        self, response: httpx.Response, request: httpx.Request, allow_retry: bool
    ) -> tuple[httpx.Response, bool]:
        if response.is_redirect:
            return _error(request, "redirect_refused", "redirects are never followed"), False
        body = None
        if "json" in response.headers.get("content-type", ""):
            try:
                body = json.loads(response.content)
            except (json.JSONDecodeError, ValueError):
                body = None
        if not isinstance(body, dict) or "success" not in body:
            return _error(
                request,
                "unexpected_response",
                f"HTTP {response.status_code} without a Freebox JSON envelope",
            ), False

        if body["success"]:
            result = body.get("result", {"success": True})
            return _json_response(200, redact(result), request), False

        error_code = body.get("error_code")
        if error_code == "auth_required" and allow_retry and self._session.registered:
            return response, True
        return _error(request, error_code, body.get("msg", "Freebox API error")), False


def _error(request: httpx.Request, error_code: str | None, msg: str) -> httpx.Response:
    payload = {"freebox_error": True, "error_code": error_code, "msg": msg}
    return _json_response(409, payload, request)


def _json_response(status: int, data: object, request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        status_code=status,
        headers={"content-type": "application/json"},
        content=json.dumps(data).encode(),
        request=request,
    )


def _make_request_hook(session: SessionManager, settings: Settings):
    origin = httpx.URL(settings.origin)

    async def hook(request: httpx.Request) -> None:
        url = request.url
        if url.scheme != "https" or url.netloc != origin.netloc:
            raise PolicyError(f"request target {url.scheme}://{url.host} refused", request)
        canonical = authorize(request.method, url.raw_path, writes_enabled=settings.enable_writes)
        prefix = await session.prefix()
        # Set the raw, already-encoded path: never re-derive it from a decoded one.
        request.url = url.copy_with(raw_path=(prefix + canonical).encode("ascii"))
        request.headers["X-Fbx-App-Auth"] = await session.get_token()

    return hook


def _verify(settings: Settings):
    return freebox_ssl_context(str(settings.cert_bundle))


def build_session_manager(
    settings: Settings, endpoint: Endpoint | None, store: TokenStore
) -> SessionManager:
    """Session client: used only for discovery and the /login/ handshake."""
    raw = httpx.AsyncClient(
        base_url=settings.origin,
        verify=_verify(settings),
        timeout=settings.request_timeout,
        follow_redirects=False,
    )
    return SessionManager(raw, settings, store, endpoint)


def build_client(
    settings: Settings, endpoint: Endpoint | None, session: SessionManager
) -> httpx.AsyncClient:
    inner = httpx.AsyncHTTPTransport(verify=_verify(settings), retries=1)
    transport = FreeboxTransport(inner, session)
    return httpx.AsyncClient(
        base_url=settings.origin,
        transport=transport,
        timeout=settings.request_timeout,
        follow_redirects=False,
        event_hooks={"request": [_make_request_hook(session, settings)]},
    )
