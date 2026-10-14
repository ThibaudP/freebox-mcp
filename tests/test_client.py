"""Transport behaviour: envelope unwrap, error surfacing, auth retry, path prefix,
and the fail-closed handling of non-envelope replies."""

from __future__ import annotations

import httpx
import pytest

from freebox_mcp.client import FreeboxTransport, _make_request_hook
from freebox_mcp.config import Settings
from freebox_mcp.policy import PolicyError


class _Session:
    def __init__(self, registered=True, token="sess-tok"):
        self._registered = registered
        self._token = token
        self.refreshed = 0

    @property
    def registered(self):
        return self._registered

    async def get_token(self):
        return self._token

    async def prefix(self):
        return "/api/v16"

    async def refresh(self):
        self.refreshed += 1
        self._token = "refreshed-tok"
        return self._token


def _req(url="https://mafreebox.freebox.fr/api/v16/system/"):
    return httpx.Request("GET", url)


async def test_unwrap_success():
    inner = httpx.MockTransport(
        lambda r: httpx.Response(
            200, json={"success": True, "result": {"firmware_version": "4.12"}}
        )
    )
    t = FreeboxTransport(inner, _Session())
    resp = await t.handle_async_request(_req())
    assert resp.status_code == 200
    assert resp.json() == {"firmware_version": "4.12"}


async def test_error_surfaced():
    inner = httpx.MockTransport(
        lambda r: httpx.Response(
            200, json={"success": False, "error_code": "noent", "msg": "no such entry"}
        )
    )
    t = FreeboxTransport(inner, _Session(registered=False))
    resp = await t.handle_async_request(_req())
    assert resp.status_code == 409
    body = resp.json()
    assert body["freebox_error"] and body["error_code"] == "noent"


async def test_auth_required_triggers_one_retry():
    calls = {"n": 0}

    def handler(r: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(200, json={"success": False, "error_code": "auth_required"})
        return httpx.Response(200, json={"success": True, "result": {"ok": 1}})

    session = _Session(registered=True)
    t = FreeboxTransport(httpx.MockTransport(handler), session)
    resp = await t.handle_async_request(_req())
    assert resp.json() == {"ok": 1}
    assert session.refreshed == 1
    assert calls["n"] == 2


async def test_non_json_reply_is_an_error_not_passed_through():
    inner = httpx.MockTransport(
        lambda r: httpx.Response(
            200, content=b"BINARYDATA", headers={"content-type": "application/octet-stream"}
        )
    )
    t = FreeboxTransport(inner, _Session())
    resp = await t.handle_async_request(_req())
    assert resp.status_code == 409
    assert resp.json()["error_code"] == "unexpected_response"
    assert b"BINARYDATA" not in resp.content


async def test_redirect_reply_is_an_error():
    inner = httpx.MockTransport(
        lambda r: httpx.Response(302, headers={"location": "https://evil.example/"})
    )
    resp = await FreeboxTransport(inner, _Session()).handle_async_request(_req())
    assert resp.status_code == 409
    assert resp.json()["error_code"] == "redirect_refused"


async def test_request_hook_prefixes_path_and_injects_token():
    hook = _make_request_hook(_Session(), Settings())
    req = httpx.Request("GET", "https://mafreebox.freebox.fr/wifi/config/")
    await hook(req)
    assert req.url.path == "/api/v16/wifi/config/"
    assert req.headers["X-Fbx-App-Auth"] == "sess-tok"


@pytest.mark.parametrize(
    "url",
    [
        "https://mafreebox.freebox.fr/login/",
        "http://mafreebox.freebox.fr/system/",
        "https://evil.example/system/",
        "https://mafreebox.freebox.fr:8443/system/",
    ],
)
async def test_request_hook_refuses_login_and_foreign_targets(url):
    hook = _make_request_hook(_Session(), Settings())
    req = httpx.Request("GET", url)
    with pytest.raises(PolicyError):
        await hook(req)
    assert "X-Fbx-App-Auth" not in req.headers


# Firmware answers {"success": true} with no "result" for these empty collections.
def _absent_result(method, path, body=None):
    inner = httpx.MockTransport(lambda r: httpx.Response(200, json=body or {"success": True}))
    t = FreeboxTransport(inner, _Session())
    return t.handle_async_request(httpx.Request(method, f"https://mafreebox.freebox.fr{path}"))


@pytest.mark.parametrize("path", ["/api/v16/dhcp/static_lease/", "/api/v16/fw/redir/"])
async def test_absent_result_on_known_empty_collection_get_is_empty_list(path):
    assert (await _absent_result("GET", path)).json() == []


@pytest.mark.parametrize(
    "method,path,body,expected",
    [
        ("GET", "/api/v16/dhcp/static_lease/", {"success": True, "result": []}, []),
        ("GET", "/api/v16/dhcp/static_lease/", {"success": True, "result": None}, None),
        ("GET", "/api/v16/dhcp/static_lease/", {"success": True, "result": {"a": 1}}, {"a": 1}),
        ("GET", "/api/v16/dhcp/config/", None, {"success": True}),
        ("GET", "/api/v16/dhcp/static_lease/3", None, {"success": True}),
        ("GET", "/api/v16/fw/redir/3/", None, {"success": True}),
        ("GET", "/api/v16/fw/redirx/", None, {"success": True}),
        ("POST", "/api/v16/dhcp/static_lease/", None, {"success": True}),
        ("PUT", "/api/v16/fw/redir/", None, {"success": True}),
    ],
)
async def test_absent_result_normalisation_is_scoped(method, path, body, expected):
    assert (await _absent_result(method, path, body)).json() == expected


async def test_error_on_empty_collection_get_is_not_treated_as_empty():
    body = {"success": False, "error_code": "nodev", "msg": "x"}
    resp = await _absent_result("GET", "/api/v16/fw/redir/", body)
    assert resp.status_code == 409 and resp.json()["error_code"] == "nodev"
