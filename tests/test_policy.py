"""Runtime endpoint policy: the final method + path allowlist enforced on every
request, independently of which tools are registered."""

from __future__ import annotations

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from freebox_mcp.config import Settings
from freebox_mcp.policy import PolicyError, authorize
from freebox_mcp.server import create_server

from tests.conftest import ORIGIN, PREFIX, ok


@pytest.mark.parametrize(
    "method,raw,expected",
    [
        ("GET", "/system/", "/system/"),
        ("GET", "/lan/browser/pub/", "/lan/browser/pub/"),
        (
            "GET",
            "/lan/browser/pub/ether-00%3A11%3A22%3AAA%3Abb%3Acc/",
            "/lan/browser/pub/ether-00:11:22:AA:bb:cc/",
        ),
        (
            "GET",
            "/dhcp/static_lease/00%3A11%3A22%3A33%3A44%3A55",
            "/dhcp/static_lease/00:11:22:33:44:55",
        ),
        ("GET", "/fw/redir/12", "/fw/redir/12"),
        ("GET", "/wifi/bss/", "/wifi/bss/"),
    ],
)
def test_allowed_reads(method, raw, expected):
    assert authorize(method, raw.encode(), writes_enabled=False) == expected


@pytest.mark.parametrize(
    "method,raw",
    [
        ("GET", "/lan/browser/%2E%2E%2F%2E%2E%2Fwifi%2Fbss/"),
        ("GET", "/lan/browser/%2e%2e/"),
        ("GET", "/lan/browser/./"),
        ("GET", "/lan/browser/../"),
        ("GET", "/lan/browser/a%5Cb/"),
        ("GET", "/lan/browser/a%2Fb/"),
        ("GET", "/lan/browser/%252e%252e/"),
        ("GET", "/lan/browser/pub/?x=1"),
        ("GET", "/lan/browser/%7Binterface%7D/"),
        ("GET", "/lan/browser//"),
        ("GET", "/System/"),
        ("GET", "/%73ystem/"),
        ("GET", "//system/"),
        ("GET", "/login/"),
        ("POST", "/login/session/"),
        ("GET", "/fs/ls/"),
        ("GET", "/fw/redir/abc"),
        ("GET", "/fw/redir/-1"),
        ("GET", "/dhcp/static_lease/not-a-mac"),
        ("POST", "/system/reboot/"),
        ("PUT", "/dhcp/config/"),
        ("PUT", "/lan/config/"),
        ("PUT", "/wifi/config/"),
        ("PUT", "/fw/dmz/"),
        ("POST", "/dhcp/static_lease/"),
        ("DELETE", "/fw/redir/3"),
        ("PATCH", "/system/"),
    ],
)
def test_denied(method, raw):
    with pytest.raises(PolicyError):
        authorize(method, raw.encode(), writes_enabled=False)


@pytest.mark.parametrize(
    "method,raw",
    [
        ("POST", "/dhcp/static_lease/"),
        ("PUT", "/dhcp/static_lease/00:11:22:33:44:55"),
        ("DELETE", "/dhcp/static_lease/00:11:22:33:44:55"),
        ("POST", "/fw/redir/"),
        ("PUT", "/fw/redir/3"),
        ("DELETE", "/fw/redir/3"),
    ],
)
def test_targeted_writes_allowed_only_when_enabled(method, raw):
    with pytest.raises(PolicyError):
        authorize(method, raw.encode(), writes_enabled=False)
    assert authorize(method, raw.encode(), writes_enabled=True)


@pytest.mark.parametrize("raw", ["/system/reboot/", "/dhcp/config/", "/fw/dmz/", "/wifi/config/"])
def test_other_writes_denied_even_when_enabled(raw):
    for method in ("POST", "PUT", "DELETE"):
        with pytest.raises(PolicyError):
            authorize(method, raw.encode(), writes_enabled=True)


async def test_lan_interface_traversal_regression(box):
    """Upstream: interface='../../wifi/bss' on the LAN tool reached /api/v8/wifi/bss/."""
    lan = box.get(f"{ORIGIN}{PREFIX}/lan/browser/pub/").respond(json=ok([]))
    bss = box.get(f"{ORIGIN}{PREFIX}/wifi/bss/").respond(json=ok([]))
    async with Client(create_server(Settings())) as c:
        with pytest.raises(ToolError):
            await c.call_tool("get_lan_browser_interface", {"interface": "../../wifi/bss"})
        assert not bss.called
        await c.call_tool("get_lan_browser_interface", {"interface": "pub"})
    assert lan.called
    assert lan.calls.last.request.url.raw_path == f"{PREFIX}/lan/browser/pub/".encode()


@pytest.mark.parametrize(
    "bad", ["..", ".", "%2e%2e", "a/b", "a\\b", "pub?x=1", "pub#x", "", "%252e", "pub/../x"]
)
async def test_lan_interface_bad_values_never_reach_network(box, bad):
    async with Client(create_server(Settings())) as c:
        with pytest.raises(ToolError):
            await c.call_tool("get_lan_browser_interface", {"interface": bad})
    sent = [call.request.url.path for call in box.calls]
    assert not any("/lan/" in p or "/wifi/" in p for p in sent), sent


async def test_lan_host_id_with_colons_is_preserved(box):
    route = box.get(f"{ORIGIN}{PREFIX}/lan/browser/pub/ether-00:11:22:33:44:55/").respond(
        json=ok({"id": "ether-00:11:22:33:44:55"})
    )
    async with Client(create_server(Settings())) as c:
        res = await c.call_tool(
            "get_lan_browser_interface_hostid",
            {"interface": "pub", "hostid": "ether-00:11:22:33:44:55"},
        )
    assert route.called
    assert res.structured_content["id"] == "ether-00:11:22:33:44:55"
    assert route.calls.last.request.headers["X-Fbx-App-Auth"] == "S-TOKEN"


async def test_missing_required_argument_is_rejected(box):
    async with Client(create_server(Settings())) as c:
        with pytest.raises(ToolError):
            await c.call_tool("get_lan_browser_interface", {})
    assert not any("/lan/" in call.request.url.path for call in box.calls)


async def test_redirect_on_regular_request_is_not_followed(box):
    box.get(f"{ORIGIN}{PREFIX}/system/").respond(
        302, headers={"location": "https://evil.example/steal"}
    )
    evil = box.get("https://evil.example/steal").respond(json=ok({}))
    async with Client(create_server(Settings())) as c:
        with pytest.raises(ToolError):
            await c.call_tool("get_system", {})
    assert not evil.called


async def test_connection_error_is_an_error_not_a_result(paired):
    import httpx
    import respx

    with respx.mock(assert_all_called=False) as router:
        router.get(f"{ORIGIN}/api_version").mock(side_effect=httpx.ConnectError("down"))
        plain = router.get("http://mafreebox.freebox.fr/api_version").respond(json={})
        async with Client(create_server(Settings())) as c:
            with pytest.raises(ToolError):
                await c.call_tool("get_system", {})
        assert not plain.called
