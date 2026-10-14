"""Freebox discovery: learn the API version from the pinned HTTPS origin.

``GET {origin}/api_version`` is an unauthenticated bootstrap call (no session
header, no secret). It is made over HTTPS verified against the bundled Freebox
CAs, without following redirects. Only the API path prefix, uid and model are
used; the advertised remote ``api_domain``/``https_port``/``https_available``
are informational and never select the target. Any failure is fatal — there
is no cleartext fallback.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

import httpx

from .auth import FreeboxError
from .config import Settings
from .tls import freebox_ssl_context

log = logging.getLogger("freebox_mcp.discovery")

_API_BASE_RE = re.compile(r"^/(?:[a-z0-9_]+/)+$")
_API_VERSION_RE = re.compile(r"^(\d{1,3})\.\d{1,3}$")


@dataclass(frozen=True)
class Discovery:
    api_domain: str | None
    https_port: int | None
    https_available: bool
    api_base_url: str  # e.g. "/api/"
    api_version: str  # e.g. "16.0"
    box_model_name: str | None
    uid: str | None

    @property
    def api_major(self) -> int:
        m = _API_VERSION_RE.match(str(self.api_version))
        if not m:
            raise FreeboxError(f"unexpected api_version {self.api_version!r}", "bad_discovery")
        return int(m.group(1))

    @property
    def version_prefix(self) -> str:
        return f"v{self.api_major}"

    @property
    def api_path_prefix(self) -> str:
        """e.g. '/api/v16' — prepended to every spec path at request time."""
        if not _API_BASE_RE.match(str(self.api_base_url)) or ".." in self.api_base_url:
            raise FreeboxError(f"unexpected api_base_url {self.api_base_url!r}", "bad_discovery")
        base = self.api_base_url.strip("/")
        return f"/{base}/{self.version_prefix}"


def https_client(settings: Settings) -> httpx.Client:
    """Sync client for the CLI auth flow: pinned origin, Freebox CA, no redirects."""
    return httpx.Client(
        base_url=settings.origin,
        verify=freebox_ssl_context(str(settings.cert_bundle)),
        timeout=settings.request_timeout,
        follow_redirects=False,
    )


def parse_discovery(resp: httpx.Response) -> Discovery:
    if resp.status_code != 200:
        raise FreeboxError(
            f"discovery returned HTTP {resp.status_code} (redirects are not followed)",
            "bad_discovery",
        )
    try:
        data = resp.json()
    except ValueError as exc:
        raise FreeboxError("discovery response is not JSON", "bad_discovery") from exc
    if not isinstance(data, dict):
        raise FreeboxError("discovery response is not an object", "bad_discovery")
    d = Discovery(
        api_domain=data.get("api_domain"),
        https_port=data.get("https_port"),
        https_available=bool(data.get("https_available")),
        api_base_url=data.get("api_base_url", "/api/"),
        api_version=str(data.get("api_version", "")),
        box_model_name=data.get("box_model_name"),
        uid=data.get("uid"),
    )
    _ = d.api_path_prefix  # validate eagerly
    return d


def fetch_discovery(settings: Settings, client: httpx.Client | None = None) -> Discovery:
    owns = client is None
    client = client or https_client(settings)
    try:
        resp = client.get(f"{settings.origin}/api_version", follow_redirects=False)
    finally:
        if owns:
            client.close()
    return parse_discovery(resp)


async def afetch_discovery(settings: Settings, client: httpx.AsyncClient) -> Discovery:
    resp = await client.get(f"{settings.origin}/api_version", follow_redirects=False)
    return parse_discovery(resp)


@dataclass(frozen=True)
class Endpoint:
    base_url: str  # https://host[:port] — NO path
    secure: bool
    api_path_prefix: str  # "/api/v16"
    discovery: Discovery


def choose_endpoint(settings: Settings, discovery: Discovery | None = None) -> Endpoint:
    """Return the pinned HTTPS endpoint.

    ``https_available`` is not checked: it describes *remote* access
    (``api_domain:https_port``), which is never a target. The local origin is
    HTTPS by construction (config refuses ``http://``) and discovery has just
    been fetched from it over verified TLS without redirects.
    """
    discovery = discovery or fetch_discovery(settings)
    return Endpoint(settings.origin, True, discovery.api_path_prefix, discovery)
