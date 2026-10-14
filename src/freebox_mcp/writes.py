"""Targeted write tools: DHCP static leases and NAT port forwards.

Registered only when FREEBOX_ENABLE_WRITES is on. Every tool is a preview by
default (``dry_run=true``): it reads the current state, validates the inputs,
and returns the exact request it would send, a before/after diff and an
``expected_state_hash`` — without mutating anything. The hash covers the tool,
method, path and body of that exact request together with the current state.
The tool mutates only when called again with ``dry_run=false`` AND a hash
recomputed at apply time matches: an apply for a different request (other
tool, target or payload) or against a changed state is refused. That is exact
preview binding plus optimistic concurrency, nothing more.

This is not a human approval mechanism: every argument, including dry_run and
the hash, is chosen by the model. Human consent for a real change must be
obtained by the agent/operator layer before the apply call.

A mutation that fails after it may have reached the box (timeout, read or
protocol error) has an unknown outcome: it is never retried automatically, and
the state must be re-read (new preview) before deciding to retry.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from typing import Annotated, Literal

import httpx
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from .policy import PolicyError

LEASE_FIELDS = ("id", "mac", "ip", "comment")
REDIR_FIELDS = (
    "id",
    "enabled",
    "ip_proto",
    "wan_port_start",
    "wan_port_end",
    "lan_ip",
    "lan_port",
    "src_ip",
    "comment",
)
_PRIVATE_NETS = tuple(
    ipaddress.IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$")
_COMMENT_RE = re.compile(r"^[^\x00-\x1f\x7f]{0,63}$")

CREATE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False
)
MODIFY = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False
)

DryRun = Annotated[
    bool,
    Field(description="true (default): preview only, nothing is changed. false: apply."),
]
ExpectedHash = Annotated[
    str | None,
    Field(
        description="Required when dry_run=false: the expected_state_hash returned by a "
        "preview of this exact request. A mismatch means the request or the state differs "
        "from the preview: re-preview."
    ),
]
Mac = Annotated[str, Field(description="MAC address, e.g. 00:11:22:33:44:55")]
Ipv4 = Annotated[str, Field(description="IPv4 address inside the Freebox LAN subnet")]
Port = Annotated[int, Field(ge=1, le=65535)]
Comment = Annotated[str, Field(max_length=63)]


# --------------------------------------------------------------------------- #
# Validation helpers
# --------------------------------------------------------------------------- #
def state_hash(state: object) -> str:
    canonical = json.dumps(state, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _project(obj: object, fields: tuple[str, ...]) -> dict:
    if not isinstance(obj, dict):
        raise ToolError("unexpected Freebox reply: not an object")
    return {f: obj.get(f) for f in fields}


def _project_list(data: object, fields: tuple[str, ...]) -> list[dict]:
    # The Freebox omits ``result`` for empty lists (the transport then yields an object).
    items = data if isinstance(data, list) else []
    return sorted((_project(i, fields) for i in items), key=lambda i: str(i.get("id")))


def _mac(value: str) -> str:
    if not _MAC_RE.fullmatch(value or ""):
        raise ToolError(f"invalid MAC address {value!r}")
    mac = value.upper()
    if int(mac[:2], 16) & 1 or mac == "00:00:00:00:00:00":
        raise ToolError(f"{mac} is not a unicast MAC address")
    return mac


def _comment(value: str) -> str:
    if not _COMMENT_RE.fullmatch(value):
        raise ToolError("comment must be at most 63 printable characters")
    return value


def _lan_subnet(dhcp_config: object) -> tuple[ipaddress.IPv4Network, ipaddress.IPv4Address]:
    try:
        gateway = ipaddress.IPv4Address(dhcp_config["gateway"])
        net = ipaddress.IPv4Network(f"{gateway}/{dhcp_config['netmask']}", strict=False)
    except (KeyError, TypeError, ValueError) as exc:
        raise ToolError("cannot determine the LAN subnet from the DHCP config") from exc
    return net, gateway


def _lan_ip(value: str, dhcp_config: object) -> str:
    """A private (RFC 1918) host address inside the Freebox LAN, not the gateway."""
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError as exc:
        raise ToolError(f"invalid IPv4 address {value!r}") from exc
    if not any(ip in n for n in _PRIVATE_NETS):
        raise ToolError(f"{ip} is not a private (RFC 1918) LAN address")
    net, gateway = _lan_subnet(dhcp_config)
    if ip not in net or ip in (net.network_address, net.broadcast_address, gateway):
        raise ToolError(f"{ip} is not a usable host address in the LAN {net}")
    return str(ip)


def _src_ip(value: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError as exc:
        raise ToolError(f"invalid source IPv4 {value!r} (use 0.0.0.0 for any)") from exc


def _check_ports(start: int, end: int, lan_port: int) -> None:
    for name, port in (("wan_port_start", start), ("wan_port_end", end), ("lan_port", lan_port)):
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ToolError(f"{name} must be an integer port in 1..65535")
    if end < start:
        raise ToolError("wan_port_end must be >= wan_port_start")
    if lan_port + (end - start) > 65535:
        raise ToolError("the LAN port range would exceed 65535")


def _check_no_overlap(redirs: list[dict], proto: str, start: int, end: int, skip_id=None):
    for r in redirs:
        if r.get("id") == skip_id or r.get("ip_proto") != proto:
            continue
        try:
            r_start, r_end = int(r["wan_port_start"]), int(r["wan_port_end"] or r["wan_port_start"])
        except (KeyError, TypeError, ValueError):
            continue
        if start <= r_end and r_start <= end:
            raise ToolError(
                f"WAN {proto} ports {start}-{end} overlap existing port forward id {r.get('id')}"
            )


# --------------------------------------------------------------------------- #
# Preview / apply core
# --------------------------------------------------------------------------- #
# Failures that happen before anything reaches the box.
_NOT_SENT = (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout, PolicyError)


def _unknown_outcome(method: str, path: str, reason: str) -> ToolError:
    return ToolError(
        f"{method} {path}: outcome unknown ({reason}). The Freebox may or may not have "
        "applied this change. It was not retried. Re-read the state (run the preview "
        "again) before deciding whether to retry."
    )


async def _send(client: httpx.AsyncClient, method: str, path: str, body=None) -> object:
    try:
        resp = await client.request(method, path, json=body)
    except httpx.HTTPError as exc:
        reason = f"{type(exc).__name__}: {exc}"
        if method != "GET" and not isinstance(exc, _NOT_SENT):
            raise _unknown_outcome(method, path, reason) from exc
        raise ToolError(f"{method} {path} failed: {reason}") from exc
    try:
        data = resp.json()
    except ValueError:
        data = None
    if resp.status_code >= 400:
        if method != "GET" and isinstance(data, dict):
            if data.get("error_code") == "unexpected_response":
                raise _unknown_outcome(method, path, str(data.get("msg")))
        raise ToolError(f"Freebox refused {method} {path}: {data}")
    return data


def _lookup_lease(leases: list[dict], lease_id: str) -> dict:
    """The existing lease for a MAC, matched case-insensitively, with the box's own id."""
    mac = _mac(lease_id)
    for lease in leases:
        if mac in (str(lease.get("id", "")).upper(), str(lease.get("mac", "")).upper()):
            if not _MAC_RE.fullmatch(str(lease.get("id", ""))):
                raise ToolError(f"unexpected static lease id {lease.get('id')!r} from the Freebox")
            return lease
    raise ToolError(f"no static lease for {mac}")


async def _finish(
    client: httpx.AsyncClient,
    *,
    tool: str,
    method: str,
    path: str,
    body: dict | None,
    before: dict | None,
    after: dict | None,
    state: object,
    dry_run: bool,
    expected_state_hash: str | None,
) -> dict:
    request = {"method": method, "path": path, "body": body}
    out = {"request": request, "diff": {"before": before, "after": after}}
    # Binds the exact request (tool, method, path, body) to the state it was previewed on.
    current_hash = state_hash({"tool": tool, **request, "state": state})
    if dry_run:
        return {
            "mode": "preview",
            "applied": False,
            **out,
            "expected_state_hash": current_hash,
            "note": "Nothing was changed. To apply, get explicit human approval for this exact "
            "change, then call the same tool again with the same arguments, dry_run=false and "
            "this expected_state_hash (it is only valid for this exact request and state).",
        }
    if not expected_state_hash:
        raise ToolError("dry_run=false requires expected_state_hash from a preview")
    if expected_state_hash != current_hash:
        raise ToolError(
            "this request or the current state changed since the preview "
            "(the hash binds the exact tool, method, path and body to the state); "
            "run a new preview"
        )
    result = await _send(client, method, path, body)
    return {"mode": "applied", "applied": True, **out, "result": result}


def register_write_tools(mcp: FastMCP, client: httpx.AsyncClient) -> None:
    # ----------------------------- DHCP --------------------------------------
    @mcp.tool(annotations=CREATE)
    async def dhcp_static_lease_create(
        mac: Mac,
        ip: Ipv4,
        comment: Comment = "",
        dry_run: DryRun = True,
        expected_state_hash: ExpectedHash = None,
    ) -> dict:
        """Reserve a LAN IPv4 for a MAC address (DHCP static lease).
        Preview by default; see dry_run / expected_state_hash."""
        mac, comment = _mac(mac), _comment(comment)
        ip = _lan_ip(ip, await _send(client, "GET", "/dhcp/config/"))
        leases = _project_list(await _send(client, "GET", "/dhcp/static_lease/"), LEASE_FIELDS)
        for lease in leases:
            if str(lease.get("mac", "")).upper() == mac or lease.get("ip") == ip:
                raise ToolError(f"conflicts with existing static lease {lease['id']}: update it")
        body = {"mac": mac, "ip": ip, "comment": comment}
        return await _finish(
            client,
            tool="dhcp_static_lease_create",
            method="POST",
            path="/dhcp/static_lease/",
            body=body,
            before=None,
            after=body,
            state=leases,
            dry_run=dry_run,
            expected_state_hash=expected_state_hash,
        )

    @mcp.tool(annotations=MODIFY)
    async def dhcp_static_lease_update(
        lease_id: Annotated[str, Field(description="Static lease id (its MAC address)")],
        ip: Ipv4 | None = None,
        comment: Comment | None = None,
        dry_run: DryRun = True,
        expected_state_hash: ExpectedHash = None,
    ) -> dict:
        """Change the IPv4 and/or comment of an existing DHCP static lease.
        Preview by default; see dry_run / expected_state_hash."""
        leases = _project_list(await _send(client, "GET", "/dhcp/static_lease/"), LEASE_FIELDS)
        before = _lookup_lease(leases, lease_id)
        path = f"/dhcp/static_lease/{before['id']}"
        body: dict = {}
        if ip is not None:
            body["ip"] = _lan_ip(ip, await _send(client, "GET", "/dhcp/config/"))
        if comment is not None:
            body["comment"] = _comment(comment)
        if not body:
            raise ToolError("nothing to update: give ip and/or comment")
        if "ip" in body and body["ip"] != before["ip"]:
            for lease in leases:
                if lease.get("ip") == body["ip"]:
                    raise ToolError(f"{body['ip']} is already reserved by lease {lease['id']}")
        return await _finish(
            client,
            tool="dhcp_static_lease_update",
            method="PUT",
            path=path,
            body=body,
            before=before,
            after={**before, **body},
            state=before,
            dry_run=dry_run,
            expected_state_hash=expected_state_hash,
        )

    @mcp.tool(annotations=MODIFY)
    async def dhcp_static_lease_delete(
        lease_id: Annotated[str, Field(description="Static lease id (its MAC address)")],
        dry_run: DryRun = True,
        expected_state_hash: ExpectedHash = None,
    ) -> dict:
        """Remove a DHCP static lease. Preview by default; see dry_run / expected_state_hash."""
        leases = _project_list(await _send(client, "GET", "/dhcp/static_lease/"), LEASE_FIELDS)
        before = _lookup_lease(leases, lease_id)
        path = f"/dhcp/static_lease/{before['id']}"
        return await _finish(
            client,
            tool="dhcp_static_lease_delete",
            method="DELETE",
            path=path,
            body=None,
            before=before,
            after=None,
            state=before,
            dry_run=dry_run,
            expected_state_hash=expected_state_hash,
        )

    # ----------------------------- NAT ---------------------------------------
    @mcp.tool(annotations=CREATE)
    async def nat_port_forward_create(
        ip_proto: Literal["tcp", "udp"],
        wan_port_start: Port,
        lan_ip: Ipv4,
        lan_port: Port,
        wan_port_end: Port | None = None,
        src_ip: Annotated[str, Field(description="Allowed source IPv4; 0.0.0.0 = any")] = "0.0.0.0",
        comment: Comment = "",
        enabled: bool = True,
        dry_run: DryRun = True,
        expected_state_hash: ExpectedHash = None,
    ) -> dict:
        """Forward a WAN port (range) to a host on the LAN (NAT port forward).
        Preview by default; see dry_run / expected_state_hash."""
        end = wan_port_start if wan_port_end is None else wan_port_end
        _check_ports(wan_port_start, end, lan_port)
        lan_ip = _lan_ip(lan_ip, await _send(client, "GET", "/dhcp/config/"))
        src_ip, comment = _src_ip(src_ip), _comment(comment)
        redirs = _project_list(await _send(client, "GET", "/fw/redir/"), REDIR_FIELDS)
        _check_no_overlap(redirs, ip_proto, wan_port_start, end)
        body = {
            "enabled": enabled,
            "ip_proto": ip_proto,
            "wan_port_start": wan_port_start,
            "wan_port_end": end,
            "lan_ip": lan_ip,
            "lan_port": lan_port,
            "src_ip": src_ip,
            "comment": comment,
        }
        return await _finish(
            client,
            tool="nat_port_forward_create",
            method="POST",
            path="/fw/redir/",
            body=body,
            before=None,
            after=body,
            state=redirs,
            dry_run=dry_run,
            expected_state_hash=expected_state_hash,
        )

    @mcp.tool(annotations=MODIFY)
    async def nat_port_forward_update(
        redir_id: Annotated[int, Field(ge=0, le=999_999_999)],
        enabled: bool | None = None,
        ip_proto: Literal["tcp", "udp"] | None = None,
        wan_port_start: Port | None = None,
        wan_port_end: Port | None = None,
        lan_ip: Ipv4 | None = None,
        lan_port: Port | None = None,
        src_ip: str | None = None,
        comment: Comment | None = None,
        dry_run: DryRun = True,
        expected_state_hash: ExpectedHash = None,
    ) -> dict:
        """Change fields of an existing NAT port forward (only the given ones).
        Preview by default; see dry_run / expected_state_hash."""
        path = f"/fw/redir/{redir_id}"
        before = _project(await _send(client, "GET", path), REDIR_FIELDS)
        changes = {
            k: v
            for k, v in {
                "enabled": enabled,
                "ip_proto": ip_proto,
                "wan_port_start": wan_port_start,
                "wan_port_end": wan_port_end,
                "lan_ip": lan_ip,
                "lan_port": lan_port,
                "src_ip": src_ip,
                "comment": comment,
            }.items()
            if v is not None
        }
        if not changes:
            raise ToolError("nothing to update")
        after = {**before, **changes}
        try:
            start, end, lport = (
                int(after["wan_port_start"]),
                int(after["wan_port_end"]),
                int(after["lan_port"]),
            )
        except (TypeError, ValueError) as exc:
            raise ToolError("current port forward has unexpected port values") from exc
        _check_ports(start, end, lport)
        if "lan_ip" in changes:
            changes["lan_ip"] = _lan_ip(lan_ip, await _send(client, "GET", "/dhcp/config/"))
        if "src_ip" in changes:
            changes["src_ip"] = _src_ip(src_ip)
        if "comment" in changes:
            _comment(comment)
        if {"ip_proto", "wan_port_start", "wan_port_end"} & changes.keys():
            redirs = _project_list(await _send(client, "GET", "/fw/redir/"), REDIR_FIELDS)
            _check_no_overlap(redirs, after["ip_proto"], start, end, skip_id=before["id"])
        return await _finish(
            client,
            tool="nat_port_forward_update",
            method="PUT",
            path=path,
            body=changes,
            before=before,
            after={**before, **changes},
            state=before,
            dry_run=dry_run,
            expected_state_hash=expected_state_hash,
        )

    @mcp.tool(annotations=MODIFY)
    async def nat_port_forward_delete(
        redir_id: Annotated[int, Field(ge=0, le=999_999_999)],
        dry_run: DryRun = True,
        expected_state_hash: ExpectedHash = None,
    ) -> dict:
        """Remove a NAT port forward. Preview by default; see dry_run / expected_state_hash."""
        path = f"/fw/redir/{redir_id}"
        before = _project(await _send(client, "GET", path), REDIR_FIELDS)
        return await _finish(
            client,
            tool="nat_port_forward_delete",
            method="DELETE",
            path=path,
            body=None,
            before=before,
            after=None,
            state=before,
            dry_run=dry_run,
            expected_state_hash=expected_state_hash,
        )
