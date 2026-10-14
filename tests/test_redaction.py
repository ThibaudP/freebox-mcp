"""Secrets in Freebox replies (Wi-Fi keys, passwords, tokens) never reach the
model, while useful identifiers (MAC, IP, ids, SSIDs) are kept."""

from __future__ import annotations

import json

from fastmcp import Client

from freebox_mcp.config import Settings
from freebox_mcp.server import create_server
from tests.conftest import ORIGIN, PREFIX, ok

SECRET = "Sup3r-Secret-WPA-Passphrase"

BSS = [
    {
        "id": "00:24:D4:AA:BB:C0",
        "phy_id": 0,
        "status": {"state": "active", "sta_count": 3},
        "config": {
            "enabled": True,
            "ssid": "HomeNet",
            "encryption": "wpa2_psk_ccmp",
            "key": SECRET,
            "wps_pin": "12345670",
            "eapol_version": 2,
            "radius_secret": SECRET,
        },
    }
]


async def test_wifi_bss_key_is_redacted_but_identifiers_kept(box):
    box.get(f"{ORIGIN}{PREFIX}/wifi/bss/").respond(json=ok(BSS))
    async with Client(create_server(Settings())) as c:
        res = await c.call_tool("get_wifi_bss", {})
    dumped = json.dumps(res.structured_content) + "".join(
        getattr(block, "text", "") for block in res.content
    )
    assert SECRET not in dumped
    assert "12345670" not in dumped
    cfg = res.structured_content["result"][0]["config"]
    assert cfg["key"] == "<redacted>"
    assert cfg["ssid"] == "HomeNet"
    assert cfg["encryption"] == "wpa2_psk_ccmp"
    assert cfg["eapol_version"] == 2
    assert res.structured_content["result"][0]["id"] == "00:24:D4:AA:BB:C0"


async def test_dhcp_lease_identifiers_are_not_redacted(box):
    lease = {"id": "00:11:22:33:44:55", "mac": "00:11:22:33:44:55", "ip": "192.168.1.20"}
    box.get(f"{ORIGIN}{PREFIX}/dhcp/static_lease/").respond(json=ok([lease]))
    async with Client(create_server(Settings())) as c:
        res = await c.call_tool("get_dhcp_static_lease", {})
    assert res.structured_content["result"] == [lease]
