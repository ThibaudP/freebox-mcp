"""Brick 3 — the generated client, narrowed for a Freebox Pop V1.

Three bricks, one contract:
    scraper    tools/scrape.py          official docs        -> tools/cache/
    generator  tools/build*.py          cache                -> spec/freebox-openapi.json
    client     FastMCP.from_openapi()    spec                 -> MCP tools

Hardened fork: only a curated list of read operations (``READ_OPERATIONS``) is
generated from the spec, with read-only annotations. The optional DHCP static
lease / NAT port forward write tools are hand-written in ``writes.py`` (bounded
schemas, preview by default) and only registered when FREEBOX_ENABLE_WRITES is
on. Independently of what is registered, every request is checked against the
exact runtime allowlist in ``policy.py``. App registration / session login live
in the CLI (`freebox-mcp authorize`), never as tools.
"""

from __future__ import annotations

import logging

from fastmcp import FastMCP
from fastmcp.server.providers.openapi import MCPType, RouteMap
from mcp.types import ToolAnnotations

from .auth import TokenStore
from .client import build_client, build_session_manager
from .config import Settings, load_settings
from .spec import load_spec

log = logging.getLogger("freebox_mcp.server")

# Generated read tools exposed by default (operationIds from the bundled spec).
READ_OPERATIONS: tuple[str, ...] = (
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
)

READ_ONLY = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False
)


def _curated_spec(spec: dict) -> dict:
    """The bundled spec restricted to the GET operations in READ_OPERATIONS."""
    wanted = set(READ_OPERATIONS)
    paths: dict = {}
    for path, item in spec["paths"].items():
        get = item.get("get")
        if get and get.get("operationId") in wanted:
            paths[path] = {"get": get}
    missing = wanted - {item["get"]["operationId"] for item in paths.values()}
    if missing:
        raise RuntimeError(f"bundled spec lacks curated operations: {sorted(missing)}")
    return {**spec, "paths": paths}


def _annotate_read(route, component) -> None:
    component.annotations = READ_ONLY


def create_server(settings: Settings | None = None) -> FastMCP:
    """Build the server without touching the network: discovery, session and
    policy checks all happen lazily, per request, and fail the call on error."""
    settings = settings or load_settings()
    store = TokenStore(settings.credentials_path)
    session = build_session_manager(settings, None, store)
    client = build_client(settings, None, session)

    mcp = FastMCP.from_openapi(
        _curated_spec(load_spec()),
        client=client,
        name="Freebox OS",
        route_maps=[RouteMap(methods=["GET"], mcp_type=MCPType.TOOL)],
        mcp_component_fn=_annotate_read,
        validate_output=False,
    )
    if settings.enable_writes:
        from .writes import register_write_tools

        register_write_tools(mcp, client)
    return mcp
