"""Targeted writes: DHCP static leases and NAT port forwards.

Off unless FREEBOX_ENABLE_WRITES; preview (dry run) by default; apply only with
dry_run=false AND the state hash returned by a preview of the current state.
All requests below hit a respx-mocked box — never a real one.
"""

from __future__ import annotations

import json

import httpx
import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from freebox_mcp.config import Settings
from freebox_mcp.server import create_server
from tests.conftest import ORIGIN, PREFIX, ok

API = f"{ORIGIN}{PREFIX}"
WRITE_TOOLS = {
    "dhcp_static_lease_create",
    "dhcp_static_lease_update",
    "dhcp_static_lease_delete",
    "nat_port_forward_create",
    "nat_port_forward_update",
    "nat_port_forward_delete",
}
DHCP_CONFIG = {
    "enabled": True,
    "gateway": "192.168.1.254",
    "netmask": "255.255.255.0",
    "ip_range_start": "192.168.1.10",
    "ip_range_end": "192.168.1.50",
}
LEASE = {
    "id": "00:11:22:33:44:55",
    "mac": "00:11:22:33:44:55",
    "ip": "192.168.1.20",
    "comment": "nas",
    "hostname": "nas",
    "host": {"last_activity": 1700000000},
}
REDIR = {
    "id": 3,
    "enabled": True,
    "ip_proto": "tcp",
    "wan_port_start": 2222,
    "wan_port_end": 2222,
    "lan_ip": "192.168.1.20",
    "lan_port": 22,
    "src_ip": "0.0.0.0",
    "comment": "ssh",
    "hostname": "nas",
}


@pytest.fixture
def writes(monkeypatch):
    monkeypatch.setenv("FREEBOX_ENABLE_WRITES", "true")


@pytest.fixture
def lan(box):
    box.get(f"{API}/dhcp/config/").respond(json=ok(DHCP_CONFIG))
    box.get(f"{API}/dhcp/static_lease/").respond(json=ok([LEASE]))
    box.get(f"{API}/dhcp/static_lease/00:11:22:33:44:55").respond(json=ok(LEASE))
    box.get(f"{API}/fw/redir/").respond(json=ok([REDIR]))
    box.get(f"{API}/fw/redir/3").respond(json=ok(REDIR))
    return box


async def _call(name, args):
    async with Client(create_server(Settings())) as c:
        return (await c.call_tool(name, args)).structured_content


# --------------------------------------------------------------------------- #
# Gating and annotations
# --------------------------------------------------------------------------- #
async def test_write_tools_absent_by_default():
    tools = {t.name for t in await create_server(Settings()).list_tools()}
    assert not tools & WRITE_TOOLS


async def test_write_tools_registered_with_accurate_annotations(writes):
    tools = {t.name: t for t in await create_server(Settings()).list_tools()}
    assert WRITE_TOOLS <= set(tools)
    for name in WRITE_TOOLS:
        ann = tools[name].annotations
        assert ann.readOnlyHint is False and ann.openWorldHint is False
        assert ann.destructiveHint is (not name.endswith("_create"))
        props = tools[name].parameters["properties"]
        assert props["dry_run"]["default"] is True
        assert "expected_state_hash" in props


# --------------------------------------------------------------------------- #
# DHCP static leases
# --------------------------------------------------------------------------- #
async def test_lease_create_preview_does_not_mutate(writes, lan):
    post = lan.post(f"{API}/dhcp/static_lease/").respond(json=ok({}))
    res = await _call(
        "dhcp_static_lease_create", {"mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.1.30"}
    )
    assert res["mode"] == "preview" and res["applied"] is False
    assert res["request"] == {
        "method": "POST",
        "path": "/dhcp/static_lease/",
        "body": {"mac": "AA:BB:CC:DD:EE:01", "ip": "192.168.1.30", "comment": ""},
    }
    assert res["diff"]["before"] is None
    assert len(res["expected_state_hash"]) == 64
    assert not post.called


@pytest.mark.parametrize(
    "args",
    [
        {"mac": "zz:bb:cc:dd:ee:01", "ip": "192.168.1.30"},
        {"mac": "ff:ff:ff:ff:ff:ff", "ip": "192.168.1.30"},
        {"mac": "01:00:5e:00:00:01", "ip": "192.168.1.30"},
        {"mac": "aa:bb:cc:dd:ee:01", "ip": "8.8.8.8"},
        {"mac": "aa:bb:cc:dd:ee:01", "ip": "10.0.0.5"},
        {"mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.1.254"},
        {"mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.1.255"},
        {"mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.1.0"},
        {"mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.1.300"},
        {"mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.1.30", "comment": "x\nINJECT"},
        {"mac": "00:11:22:33:44:55", "ip": "192.168.1.31"},  # MAC already reserved
        {"mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.1.20"},  # IP already reserved
    ],
)
async def test_lease_create_rejects_invalid_or_conflicting(writes, lan, args):
    post = lan.post(f"{API}/dhcp/static_lease/").respond(json=ok({}))
    with pytest.raises(ToolError):
        await _call(
            "dhcp_static_lease_create", {**args, "dry_run": False, "expected_state_hash": "0" * 64}
        )
    assert not post.called


async def test_lease_create_apply_requires_hash(writes, lan):
    post = lan.post(f"{API}/dhcp/static_lease/").respond(json=ok({}))
    args = {"mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.1.30", "dry_run": False}
    with pytest.raises(ToolError, match="expected_state_hash"):
        await _call("dhcp_static_lease_create", args)
    with pytest.raises(ToolError, match="changed"):
        await _call("dhcp_static_lease_create", {**args, "expected_state_hash": "f" * 64})
    assert not post.called


async def test_lease_create_apply_with_preview_hash(writes, lan):
    post = lan.post(f"{API}/dhcp/static_lease/").respond(
        json=ok({"id": "AA:BB:CC:DD:EE:01", "ip": "192.168.1.30"})
    )
    args = {"mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.1.30", "comment": "printer"}
    preview = await _call("dhcp_static_lease_create", args)
    res = await _call(
        "dhcp_static_lease_create",
        {**args, "dry_run": False, "expected_state_hash": preview["expected_state_hash"]},
    )
    assert res["mode"] == "applied" and res["applied"] is True
    assert post.call_count == 1
    sent = post.calls.last.request
    assert sent.headers["X-Fbx-App-Auth"] == "S-TOKEN"
    assert json.loads(sent.content) == {
        "mac": "AA:BB:CC:DD:EE:01",
        "ip": "192.168.1.30",
        "comment": "printer",
    }


async def test_stale_preview_hash_is_refused(writes, box):
    box.get(f"{API}/dhcp/config/").respond(json=ok(DHCP_CONFIG))
    states = iter([[LEASE], [LEASE, {**LEASE, "id": "AA:00:00:00:00:02", "ip": "192.168.1.40"}]])
    box.get(f"{API}/dhcp/static_lease/").mock(side_effect=lambda r: _resp(ok(next(states))))
    post = box.post(f"{API}/dhcp/static_lease/").respond(json=ok({}))
    args = {"mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.1.30"}
    preview = await _call("dhcp_static_lease_create", args)
    with pytest.raises(ToolError, match="changed"):
        await _call(
            "dhcp_static_lease_create",
            {**args, "dry_run": False, "expected_state_hash": preview["expected_state_hash"]},
        )
    assert not post.called


def _resp(body):
    import httpx

    return httpx.Response(200, json=body)


async def test_volatile_host_fields_do_not_break_the_hash(writes, box):
    box.get(f"{API}/dhcp/config/").respond(json=ok(DHCP_CONFIG))
    states = iter([[LEASE], [{**LEASE, "host": {"last_activity": 1800000000}}]])
    box.get(f"{API}/dhcp/static_lease/").mock(side_effect=lambda r: _resp(ok(next(states))))
    post = box.post(f"{API}/dhcp/static_lease/").respond(json=ok({}))
    args = {"mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.1.30"}
    preview = await _call("dhcp_static_lease_create", args)
    await _call(
        "dhcp_static_lease_create",
        {**args, "dry_run": False, "expected_state_hash": preview["expected_state_hash"]},
    )
    assert post.called


async def test_lease_update_preview_and_apply(writes, lan):
    put = lan.put(f"{API}/dhcp/static_lease/00:11:22:33:44:55").respond(json=ok(LEASE))
    args = {"lease_id": "00:11:22:33:44:55", "ip": "192.168.1.21", "comment": "nas2"}
    preview = await _call("dhcp_static_lease_update", args)
    assert preview["diff"]["before"]["ip"] == "192.168.1.20"
    assert preview["diff"]["after"]["ip"] == "192.168.1.21"
    assert not put.called
    await _call(
        "dhcp_static_lease_update",
        {**args, "dry_run": False, "expected_state_hash": preview["expected_state_hash"]},
    )
    assert json.loads(put.calls.last.request.content) == {"ip": "192.168.1.21", "comment": "nas2"}


async def test_lease_delete_preview_and_apply(writes, lan):
    delete = lan.delete(f"{API}/dhcp/static_lease/00:11:22:33:44:55").respond(json=ok({}))
    preview = await _call("dhcp_static_lease_delete", {"lease_id": "00:11:22:33:44:55"})
    assert preview["diff"]["after"] is None and not delete.called
    with pytest.raises(ToolError):
        await _call("dhcp_static_lease_delete", {"lease_id": "00:11:22:33:44:55", "dry_run": False})
    await _call(
        "dhcp_static_lease_delete",
        {
            "lease_id": "00:11:22:33:44:55",
            "dry_run": False,
            "expected_state_hash": preview["expected_state_hash"],
        },
    )
    assert delete.call_count == 1


@pytest.mark.parametrize("lease_id", ["../../system/reboot", "00:11:22:33:44", "x"])
async def test_lease_id_is_validated(writes, lan, lease_id):
    with pytest.raises(ToolError):
        await _call("dhcp_static_lease_delete", {"lease_id": lease_id})


# --------------------------------------------------------------------------- #
# NAT port forwards
# --------------------------------------------------------------------------- #
NEW_FWD = {"ip_proto": "udp", "wan_port_start": 51820, "lan_ip": "192.168.1.30", "lan_port": 51820}


async def test_port_forward_create_preview_and_apply(writes, lan):
    post = lan.post(f"{API}/fw/redir/").respond(json=ok({**NEW_FWD, "id": 4}))
    preview = await _call("nat_port_forward_create", {**NEW_FWD, "comment": "wireguard"})
    body = {
        "enabled": True,
        "ip_proto": "udp",
        "wan_port_start": 51820,
        "wan_port_end": 51820,
        "lan_ip": "192.168.1.30",
        "lan_port": 51820,
        "src_ip": "0.0.0.0",
        "comment": "wireguard",
    }
    assert preview["request"] == {"method": "POST", "path": "/fw/redir/", "body": body}
    assert not post.called
    res = await _call(
        "nat_port_forward_create",
        {
            **NEW_FWD,
            "comment": "wireguard",
            "dry_run": False,
            "expected_state_hash": preview["expected_state_hash"],
        },
    )
    assert res["applied"] is True
    assert json.loads(post.calls.last.request.content) == body


@pytest.mark.parametrize(
    "override",
    [
        {"ip_proto": "icmp"},
        {"wan_port_start": 0},
        {"wan_port_start": 70000},
        {"wan_port_start": 100, "wan_port_end": 90},
        {"lan_port": 65535, "wan_port_start": 100, "wan_port_end": 110},
        {"lan_ip": "1.2.3.4"},
        {"lan_ip": "127.0.0.1"},
        {"lan_ip": "169.254.1.1"},
        {"lan_ip": "10.0.0.5"},
        {"lan_ip": "192.168.1.254"},
        {"lan_ip": "evil.example"},
        {"src_ip": "not-an-ip"},
        {"ip_proto": "tcp", "wan_port_start": 2220, "wan_port_end": 2230},  # overlaps id 3
    ],
)
async def test_port_forward_create_rejects_invalid(writes, lan, override):
    post = lan.post(f"{API}/fw/redir/").respond(json=ok({}))
    with pytest.raises(ToolError):
        await _call("nat_port_forward_create", {**NEW_FWD, **override})
    assert not post.called


async def test_port_forward_update_and_delete(writes, lan):
    put = lan.put(f"{API}/fw/redir/3").respond(json=ok(REDIR))
    delete = lan.delete(f"{API}/fw/redir/3").respond(json=ok({}))
    preview = await _call("nat_port_forward_update", {"redir_id": 3, "enabled": False})
    assert preview["diff"]["after"]["enabled"] is False and not put.called
    await _call(
        "nat_port_forward_update",
        {
            "redir_id": 3,
            "enabled": False,
            "dry_run": False,
            "expected_state_hash": preview["expected_state_hash"],
        },
    )
    assert json.loads(put.calls.last.request.content) == {"enabled": False}

    preview = await _call("nat_port_forward_delete", {"redir_id": 3})
    await _call(
        "nat_port_forward_delete",
        {"redir_id": 3, "dry_run": False, "expected_state_hash": preview["expected_state_hash"]},
    )
    assert delete.call_count == 1


# --------------------------------------------------------------------------- #
# Preview binding: the hash covers tool + method + path + body AND the state.
# Not a human approval: it only ties an apply to the exact previewed request
# (plus optimistic concurrency on the state).
# --------------------------------------------------------------------------- #
LEASE_ID = LEASE["id"]
MUTATIONS = [
    ("POST", f"{API}/dhcp/static_lease/"),
    ("PUT", f"{API}/dhcp/static_lease/{LEASE_ID}"),
    ("DELETE", f"{API}/dhcp/static_lease/{LEASE_ID}"),
    ("POST", f"{API}/fw/redir/"),
    ("PUT", f"{API}/fw/redir/3"),
    ("DELETE", f"{API}/fw/redir/3"),
]


@pytest.mark.parametrize(
    "preview_tool, preview_args, apply_tool, apply_args",
    [
        pytest.param(
            "dhcp_static_lease_update",
            {"lease_id": LEASE_ID, "ip": "192.168.1.21"},
            "dhcp_static_lease_update",
            {"lease_id": LEASE_ID, "ip": "192.168.1.22"},
            id="dhcp-update-changed-ip",
        ),
        pytest.param(
            "dhcp_static_lease_update",
            {"lease_id": LEASE_ID, "ip": "192.168.1.21"},
            "dhcp_static_lease_delete",
            {"lease_id": LEASE_ID},
            id="dhcp-update-to-delete",
        ),
        pytest.param(
            "dhcp_static_lease_create",
            {"mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.1.30"},
            "dhcp_static_lease_create",
            {"mac": "aa:bb:cc:dd:ee:02", "ip": "192.168.1.30"},
            id="dhcp-create-changed-mac",
        ),
        pytest.param(
            "nat_port_forward_create",
            NEW_FWD,
            "nat_port_forward_create",
            {**NEW_FWD, "lan_port": 51821},
            id="nat-create-changed-lan-port",
        ),
        pytest.param(
            "nat_port_forward_create",
            {**NEW_FWD, "comment": "wireguard"},
            "nat_port_forward_create",
            {**NEW_FWD, "comment": "wireguard", "lan_ip": "192.168.1.31"},
            id="nat-create-changed-payload",
        ),
        pytest.param(
            "nat_port_forward_update",
            {"redir_id": 3, "lan_port": 2222},
            "nat_port_forward_update",
            {"redir_id": 3, "lan_port": 23},
            id="nat-update-changed-lan-port",
        ),
        pytest.param(
            "nat_port_forward_update",
            {"redir_id": 3, "enabled": False},
            "nat_port_forward_delete",
            {"redir_id": 3},
            id="nat-update-to-delete",
        ),
    ],
)
async def test_preview_hash_does_not_authorize_a_different_request(
    writes, lan, preview_tool, preview_args, apply_tool, apply_args
):
    routes = [lan.route(method=m, url=u).respond(json=ok({})) for m, u in MUTATIONS]
    preview = await _call(preview_tool, preview_args)
    with pytest.raises(ToolError, match="new preview"):
        await _call(
            apply_tool,
            {**apply_args, "dry_run": False, "expected_state_hash": preview["expected_state_hash"]},
        )
    assert not any(r.called for r in routes)


async def test_same_state_gives_each_operation_its_own_hash(writes, lan):
    hashes = {
        (await _call(tool, args))["expected_state_hash"]
        for tool, args in [
            ("dhcp_static_lease_update", {"lease_id": LEASE_ID, "comment": "x"}),
            ("dhcp_static_lease_delete", {"lease_id": LEASE_ID}),
            ("nat_port_forward_update", {"redir_id": 3, "comment": "x"}),
            ("nat_port_forward_delete", {"redir_id": 3}),
        ]
    }
    assert len(hashes) == 4


# --------------------------------------------------------------------------- #
# Ambiguous mutation failures: outcome unknown, never retried automatically
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "failure",
    [
        httpx.ReadTimeout("timed out"),
        httpx.ReadError("connection reset"),
        httpx.RemoteProtocolError("server disconnected"),
        httpx.Response(502, text="<html>bad gateway</html>"),
    ],
    ids=["read-timeout", "read-error", "protocol-error", "no-envelope"],
)
async def test_ambiguous_mutation_failure_reports_unknown_outcome_once(writes, lan, failure):
    if isinstance(failure, httpx.Response):
        post = lan.post(f"{API}/fw/redir/").mock(return_value=failure)
    else:
        post = lan.post(f"{API}/fw/redir/").mock(side_effect=failure)
    preview = await _call("nat_port_forward_create", NEW_FWD)
    with pytest.raises(ToolError, match="outcome unknown") as err:
        await _call(
            "nat_port_forward_create",
            {**NEW_FWD, "dry_run": False, "expected_state_hash": preview["expected_state_hash"]},
        )
    assert "re-read the state" in str(err.value).lower() and "preview" in str(err.value)
    assert post.call_count == 1  # never retried automatically


async def test_connect_failure_on_mutation_is_a_plain_failure(writes, lan):
    post = lan.post(f"{API}/fw/redir/").mock(side_effect=httpx.ConnectError("refused"))
    preview = await _call("nat_port_forward_create", NEW_FWD)
    with pytest.raises(ToolError, match="failed") as err:
        await _call(
            "nat_port_forward_create",
            {**NEW_FWD, "dry_run": False, "expected_state_hash": preview["expected_state_hash"]},
        )
    assert "outcome unknown" not in str(err.value)
    assert post.call_count == 1


async def test_definite_refusal_is_not_unknown(writes, lan):
    lan.post(f"{API}/fw/redir/").respond(
        json={"success": False, "error_code": "inval", "msg": "Invalid request"}
    )
    preview = await _call("nat_port_forward_create", NEW_FWD)
    with pytest.raises(ToolError, match="refused") as err:
        await _call(
            "nat_port_forward_create",
            {**NEW_FWD, "dry_run": False, "expected_state_hash": preview["expected_state_hash"]},
        )
    assert "outcome unknown" not in str(err.value)


# --------------------------------------------------------------------------- #
# DHCP lease ids: resolved case-insensitively to the id the box returned
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "box_id, given",
    [
        ("aa:bb:cc:dd:ee:0f", "AA:BB:CC:DD:EE:0F"),
        ("AA:BB:CC:DD:EE:0F", "aa:bb:cc:dd:ee:0f"),
        ("Aa:bB:cc:DD:ee:0F", "aa:bb:cc:dd:ee:0f"),
    ],
)
@pytest.mark.parametrize(
    "tool, method, extra",
    [
        ("dhcp_static_lease_update", "PUT", {"comment": "renamed"}),
        ("dhcp_static_lease_delete", "DELETE", {}),
    ],
)
async def test_lease_id_uses_exact_box_id(writes, box, box_id, given, tool, method, extra):
    lease = {**LEASE, "id": box_id, "mac": box_id, "ip": "192.168.1.25"}
    box.get(f"{API}/dhcp/config/").respond(json=ok(DHCP_CONFIG))
    box.get(f"{API}/dhcp/static_lease/").respond(json=ok([LEASE, lease]))
    # Only the exact box-returned id is mocked: any other spelling is an unmocked request.
    box.get(f"{API}/dhcp/static_lease/{box_id}").respond(json=ok(lease))
    mutation = box.route(method=method, url=f"{API}/dhcp/static_lease/{box_id}").respond(
        json=ok(lease)
    )
    args = {"lease_id": given, **extra}
    preview = await _call(tool, args)
    assert preview["request"]["path"] == f"/dhcp/static_lease/{box_id}"
    assert preview["diff"]["before"]["id"] == box_id
    await _call(
        tool, {**args, "dry_run": False, "expected_state_hash": preview["expected_state_hash"]}
    )
    assert mutation.call_count == 1
    assert mutation.calls.last.request.url.path == f"{PREFIX}/dhcp/static_lease/{box_id}"


async def test_unknown_lease_id_is_refused_without_mutation(writes, lan):
    delete = lan.delete(url__regex=rf"{API}/dhcp/static_lease/.+").respond(json=ok({}))
    with pytest.raises(ToolError, match="no static lease"):
        await _call("dhcp_static_lease_delete", {"lease_id": "aa:bb:cc:dd:ee:99"})
    assert not delete.called


async def test_policy_still_blocks_writes_if_tools_bypassed(lan):
    """Even with a client in hand, write methods are refused unless enabled."""
    from freebox_mcp.auth import TokenStore
    from freebox_mcp.client import build_client, build_session_manager
    from freebox_mcp.policy import PolicyError

    settings = Settings()
    session = build_session_manager(settings, None, TokenStore(settings.credentials_path))
    client = build_client(settings, None, session)
    post = lan.post(f"{API}/fw/redir/").respond(json=ok({}))
    with pytest.raises(PolicyError):
        await client.post("/fw/redir/", json=NEW_FWD)
    await client.aclose()
    assert not post.called


@pytest.mark.parametrize(
    "tool,args,route",
    [
        (
            "dhcp_static_lease_create",
            {"mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.1.30"},
            "dhcp/static_lease",
        ),
        ("nat_port_forward_create", NEW_FWD, "fw/redir"),
    ],
)
async def test_create_preview_with_absent_result_empty_state(writes, lan, tool, args, route):
    # firmware answers {"success": true} without "result" for an empty collection
    lan.get(f"{API}/dhcp/static_lease/").respond(json={"success": True})
    lan.get(f"{API}/fw/redir/").respond(json={"success": True})
    post = lan.post(f"{API}/{route}/").respond(json=ok({}))
    res = await _call(tool, args)
    assert res["mode"] == "preview" and res["applied"] is False
    assert res["diff"]["before"] is None
    assert not post.called
