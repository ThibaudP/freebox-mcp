"""End-to-end flow against a mocked Freebox (respx): discover -> session -> call.

Exercises the request hook (version prefix + policy + token), the HMAC session
open, renewal on ``auth_required``, and the envelope-unwrapping transport
together, over the pinned HTTPS origin, with no real network.
"""

from __future__ import annotations

import json

from freebox_mcp.auth import TokenStore, compute_password
from freebox_mcp.client import build_client, build_session_manager
from freebox_mcp.config import Settings
from freebox_mcp.discovery import choose_endpoint, fetch_discovery
from tests.conftest import ORIGIN, PREFIX, ok


async def test_full_call_flow(box):
    session_route = box.routes[2]
    system_route = box.get(f"{ORIGIN}{PREFIX}/system/").respond(
        json=ok({"firmware_version": "4.12.1"})
    )

    settings = Settings()
    store = TokenStore(settings.credentials_path)
    endpoint = choose_endpoint(settings, fetch_discovery(settings))
    session = build_session_manager(settings, endpoint, store)
    client = build_client(settings, endpoint, session)
    try:
        resp = await client.get("/system/")
    finally:
        await client.aclose()
        await session.aclose()

    assert resp.json() == {"firmware_version": "4.12.1"}
    assert session.permissions == {"settings": True}
    # the session password must be HMAC-SHA1(app_token, challenge)
    sent = session_route.calls.last.request
    assert json.loads(sent.content)["password"] == compute_password("DUMMY-APP-TOKEN", "chA")
    # the data call carried the session token and the version-prefixed path
    sys_req = system_route.calls.last.request
    assert sys_req.headers["X-Fbx-App-Auth"] == "S-TOKEN"
    assert sys_req.url.path == "/api/v16/system/"
    assert sys_req.url.scheme == "https"


async def test_session_renewal_on_auth_required(box):
    """An expired session is reopened once and the call is replayed."""
    import httpx

    replies = iter(
        [
            {"success": False, "error_code": "auth_required", "msg": "expired"},
            ok({"firmware_version": "4.12.1"}),
        ]
    )
    system = box.get(f"{ORIGIN}{PREFIX}/system/").mock(
        side_effect=lambda r: httpx.Response(200, json=next(replies))
    )
    settings = Settings()
    session = build_session_manager(settings, None, TokenStore(settings.credentials_path))
    client = build_client(settings, None, session)
    try:
        resp = await client.get("/system/")
    finally:
        await client.aclose()
        await session.aclose()
    assert resp.json() == {"firmware_version": "4.12.1"}
    assert system.call_count == 2
    assert box.routes[2].call_count == 2  # login/session opened twice


async def test_unpaired_box_is_a_clear_error(box, isolated_env):
    import pytest

    from freebox_mcp.auth import FreeboxError

    settings = Settings()
    settings.credentials_path.unlink()
    session = build_session_manager(settings, None, TokenStore(settings.credentials_path))
    client = build_client(settings, None, session)
    with pytest.raises(FreeboxError, match="authorize"):
        await client.get("/system/")
    await client.aclose()
    await session.aclose()
