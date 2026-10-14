"""The default tool surface: a curated set of generated read tools, with
accurate annotations, built without touching the network."""

from __future__ import annotations

import json

import pytest

from freebox_mcp.config import Settings
from freebox_mcp.policy import READ_ROUTES
from freebox_mcp.server import READ_OPERATIONS, create_server
from freebox_mcp.spec import load_spec

EXPECTED_READS = {
    "get_system",
    "get_connection",
    "get_connection_config",
    "get_connection_ipv6_config",
    "get_connection_ftth",
    "get_lan_config",
    "get_lan_browser_interfaces",
    "get_lan_browser_interface",
    "get_lan_browser_interface_hostid",
    "get_switch_status",
    "get_dhcp_config",
    "get_dhcp_dynamic_lease",
    "get_dhcp_static_lease",
    "get_dhcp_static_lease_id",
    "get_fw_redir",
    "get_fw_redir_redir_id",
    "get_fw_dmz",
    "get_fw_incoming",
    "get_wifi_config",
    "get_wifi_ap",
    "get_wifi_bss",
}


def _spec_operation_ids() -> set[str]:
    spec = load_spec()
    return {
        op["operationId"]
        for item in spec["paths"].values()
        for m, op in item.items()
        if m in ("get", "post", "put", "delete")
    }


async def test_default_surface_is_exactly_the_curated_reads():
    tools = {t.name: t for t in await create_server(Settings()).list_tools()}
    assert set(tools) == EXPECTED_READS
    assert set(tools) <= _spec_operation_ids()


async def test_read_tools_are_annotated_read_only():
    for tool in await create_server(Settings()).list_tools():
        ann = tool.annotations
        assert ann is not None, tool.name
        assert ann.readOnlyHint is True, tool.name
        assert ann.destructiveHint is False, tool.name
        assert ann.idempotentHint is True, tool.name
        assert ann.openWorldHint is False, tool.name


@pytest.mark.parametrize(
    "excluded",
    [
        "post_system_reboot",
        "put_dhcp_config",
        "put_lan_config",
        "put_fw_dmz",
        "put_wifi_config",
        "post_lan_wol_interface",
        "put_connection_config",
        "get_vm",
        "get_fs_ls_path",
        "get_contact",
        "get_call_log",
        "get_vpn_user",
        "get_upnpigd_redir",
    ],
)
async def test_out_of_scope_operations_are_not_registered(excluded):
    tools = {t.name for t in await create_server(Settings()).list_tools()}
    assert excluded not in tools


def test_every_read_operation_is_covered_by_the_runtime_policy():
    spec = load_spec()
    by_id = {
        op["operationId"]: (m.upper(), path)
        for path, item in spec["paths"].items()
        for m, op in item.items()
        if m in ("get", "post", "put", "delete")
    }
    policy_paths = {(m, t.split("{")[0]) for m, t in READ_ROUTES}
    for op_id in READ_OPERATIONS:
        method, path = by_id[op_id]
        assert method == "GET"
        assert (method, path.split("{")[0]) in policy_paths, op_id


async def test_get_system_works_when_remote_https_is_off(box):
    """https_available=false (remote access off) must not block the local HTTPS origin."""
    from fastmcp import Client

    from tests.conftest import DISCOVERY, ORIGIN, PREFIX, ok

    box.get(f"{ORIGIN}/api_version").respond(json={**DISCOVERY, "https_available": False})
    system = box.get(f"{ORIGIN}{PREFIX}/system/").respond(json=ok({"firmware_version": "4.12.1"}))
    async with Client(create_server(Settings())) as c:
        res = await c.call_tool("get_system", {})
    assert system.call_count == 1
    assert system.calls.last.request.url.scheme == "https"
    assert "4.12.1" in json.dumps(res.structured_content)


def test_create_server_needs_no_network(monkeypatch):
    import httpx

    def boom(*a, **kw):
        raise AssertionError("network used at startup")

    monkeypatch.setattr(httpx.Client, "send", boom)
    monkeypatch.setattr(httpx.AsyncClient, "send", boom)
    create_server(Settings())
