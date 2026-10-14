# freebox-mcp (hardened Freebox Pop fork)

A narrow, hardened **stdio** [Model Context Protocol](https://modelcontextprotocol.io) server for
the **Freebox OS API**, aimed at a Freebox Pop. It is a fork of
[Nelson-PROIA/freebox-mcp](https://github.com/Nelson-PROIA/freebox-mcp) (MIT, © 2026 Nelson
Proia), which exposes the whole API as tools generated from an OpenAPI document scraped from the
official documentation (<https://dev.freebox.fr/sdk/os/>).

This fork keeps the upstream spec, HMAC session auth and bundled Freebox CAs, and changes:

- **HTTPS only** to one pinned origin, verified against the bundled Freebox CAs; no HTTP fallback,
  no redirects. The API prefix (`/api/vN`) is read from discovery on that origin.
- **stdio only** — no HTTP server mode, no raw "call any operation" command.
- **Curated tools** — 21 read tools by default, plus 6 optional DHCP/NAT write tools.
- **Exact runtime allowlist** of method + path, checked on the raw encoded path of every request
  (fixes an upstream path traversal: `interface='../../wifi/bss'` used to reach `/wifi/bss/`).
- **Secrets redacted** from replies (Wi-Fi keys, WPS PINs, passwords, tokens).
- **No publishing** — no release workflow, no auto-merge, `Private :: Do Not Upload` classifier.

Status: tested offline against a mocked box only. Not yet validated on a real Freebox Pop
(API v16 is expected, not verified). See *Limitations*.

## Tools

### Read tools (always on; `readOnlyHint=true`)

| Area | Tools |
|---|---|
| System | `get_system` |
| Connection | `get_connection` (status), `get_connection_config`, `get_connection_ipv6_config`, `get_connection_ftth` |
| LAN | `get_lan_config`, `get_lan_browser_interfaces`, `get_lan_browser_interface` (hosts), `get_lan_browser_interface_hostid`, `get_switch_status` |
| DHCP | `get_dhcp_config`, `get_dhcp_dynamic_lease`, `get_dhcp_static_lease`, `get_dhcp_static_lease_id` |
| NAT / firewall | `get_fw_redir`, `get_fw_redir_redir_id`, `get_fw_dmz`, `get_fw_incoming` |
| Wi-Fi (sanitized) | `get_wifi_config`, `get_wifi_ap`, `get_wifi_bss` |

Names are the upstream generated `operationId`s. Wi-Fi replies are passed through the secret
redactor (`key`, `*_key`, `*pin`, `*password*`, `*secret*`, `*token*`, … become `<redacted>`).
MAC addresses, IPs and ids are kept: they are needed to manage leases and forwards.

The bundled official documentation has **no connection log endpoint**, so none is exposed.

### Write tools (only when `FREEBOX_ENABLE_WRITES=true`)

| Tool | Request it can send | Annotations |
|---|---|---|
| `dhcp_static_lease_create` | `POST /dhcp/static_lease/` | not read-only, not destructive |
| `dhcp_static_lease_update` | `PUT /dhcp/static_lease/{mac}` | destructive |
| `dhcp_static_lease_delete` | `DELETE /dhcp/static_lease/{mac}` | destructive |
| `nat_port_forward_create` | `POST /fw/redir/` | not read-only, not destructive |
| `nat_port_forward_update` | `PUT /fw/redir/{id}` | destructive |
| `nat_port_forward_delete` | `DELETE /fw/redir/{id}` | destructive |

Validation: MAC must be unicast; LAN IPs must be RFC 1918, inside the subnet given by the DHCP
config (gateway + netmask), and not the network, broadcast or gateway address; ports 1–65535 with
`wan_port_end >= wan_port_start` and the LAN range within 65535; protocol `tcp`/`udp`; source IP a
valid IPv4 (`0.0.0.0` = any); comments ≤ 63 printable characters. Duplicate MAC/IP reservations
and overlapping WAN port ranges are refused.

Everything else is **not reachable**, even with writes enabled: reboot, DHCP/LAN/connection/Wi-Fi
configuration changes, DMZ, Wake-on-LAN, VMs (unsupported on Pop), files, downloads, contacts,
calls, passwords, VPN, DDNS, UPnP, parental control, auth/revoke.

## Writes and consent

Each write tool runs in two steps:

1. **Preview** (default, `dry_run=true`): reads the current state, validates the input, and returns
   the exact request (`method`, `path`, `body`), a `before`/`after` diff, and an
   `expected_state_hash`. **Nothing is changed.**
2. **Apply**: the same call (same tool, same arguments) with `dry_run=false` **and**
   `expected_state_hash` from the preview. The tool re-reads the state and recomputes the hash
   over the tool, method, path and body of the request **and** that state; if it differs, it
   refuses and asks for a new preview. Only then does it send the request.

DHCP static lease ids are MAC addresses: update/delete look the lease up in the box's list
case-insensitively and use the id exactly as the box returned it.

If a mutation fails after it may have reached the box (timeout, read or protocol error, reply
without a Freebox envelope), the tool reports **outcome unknown**. It is never retried
automatically: re-read the state (run the preview again) before deciding whether to retry.

Be clear about what these mechanisms are and are not:

- **All tool arguments are chosen by the model**, including `dry_run` and the hash. The preview hash
  binds an apply to the exact previewed request (another tool, target or payload is refused) and
  prevents *stale* changes (someone else changed the lease list or the rule in between). It is
  **not** proof that a human approved anything.
- `FREEBOX_ENABLE_WRITES` narrows what the server can do at all. It is an operator setting, **not a
  per-action approval**.
- **Human consent belongs to the agent / operator layer.** An agent must get explicit
  conversational authorization from the user for each real administrative change (show the
  preview, then apply). This server does not and cannot implement that approval.

## Install (local, pinned)

Requires [uv](https://docs.astral.sh/uv/). Dependencies are locked in `uv.lock`.

```bash
git clone https://github.com/ThibaudP/freebox-mcp.git
cd freebox-mcp
git checkout <reviewed-commit-sha>
uv sync --frozen                     # runtime only; add --group dev for tests
```

The launcher `scripts/freebox-mcp-stdio.sh` execs `.venv/bin/freebox-mcp` from the checkout. It
performs no installs and no network fetches (no `uvx`, no floating versions).

## Pairing (one time, manual, on your LAN)

```bash
/ABSOLUTE/PATH/TO/freebox-mcp/.venv/bin/freebox-mcp discover    # optional: check HTTPS + API version
/ABSOLUTE/PATH/TO/freebox-mcp/.venv/bin/freebox-mcp authorize   # then press ► on the box
/ABSOLUTE/PATH/TO/freebox-mcp/.venv/bin/freebox-mcp login       # prints granted permissions only
```

`authorize` requires someone to **physically press the button on the Freebox**. The app token is
saved to `$XDG_CONFIG_HOME/freebox-mcp/credentials.json` (default `~/.config/freebox-mcp/`), file
`0600`, directory `0700`. It is never printed, logged or exposed through MCP. Pairing and session
login are CLI-only; no MCP tool can authorize, revoke or read credentials.

### Freebox permissions

- **Reads only:** in Freebox OS (*Paramètres ▸ Gestion des accès ▸ Applications*), leave the
  `settings` permission **unticked** for this app.
- **Writes:** DHCP lease and port-forward changes need `settings`. Grant it only if you set
  `FREEBOX_ENABLE_WRITES=true`, and revoke it when you no longer need writes.

## MCP client configuration (placeholder example)

Use absolute paths. Replace the placeholders; do not commit real LAN addresses or tokens.

```json
{
  "mcpServers": {
    "freebox": {
      "command": "/ABSOLUTE/PATH/TO/freebox-mcp/scripts/freebox-mcp-stdio.sh",
      "args": [],
      "env": {
        "FREEBOX_API_BASE_URL": "https://mafreebox.freebox.fr",
        "FREEBOX_ENABLE_WRITES": "false"
      }
    }
  }
}
```

Adapt the same `command` / `env` to your MCP client's own config format.

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `FREEBOX_API_BASE_URL` | `https://mafreebox.freebox.fr` | Pinned HTTPS origin (`https://host[:port]`, no path). An `http://` URL is an error. |
| `FREEBOX_ENABLE_WRITES` | off | `true` registers and allows the 6 DHCP/NAT write tools (still preview-first). |
| `FREEBOX_REQUEST_TIMEOUT` | `20` | Seconds per request. |
| `FREEBOX_APP_ID` / `FREEBOX_APP_NAME` / `FREEBOX_DEVICE_NAME` | `freebox-mcp` / `Freebox MCP` / hostname | App identity on the box. |
| `XDG_CONFIG_HOME` | `~/.config` | Base directory of the credential store. |

Removed upstream settings: `FREEBOX_TRANSPORT` (only `https` is accepted), `FREEBOX_DISCOVERY_URL`
(an error if set), `FREEBOX_SECTIONS` / `FREEBOX_EXCLUDE_SECTIONS` (replaced by the curated list).

## CLI

```
freebox-mcp              run the MCP server over stdio (the only transport)
freebox-mcp authorize    register the app (press the button on the box)
freebox-mcp login        open a session and print granted permissions
freebox-mcp discover     print discovery info and the pinned HTTPS endpoint
freebox-mcp tools        list the exposed MCP tools (offline)
```

## Testing

All tests are offline: the box is mocked with `respx` and the server is driven in memory with
`fastmcp.Client`. No test reads the real home directory (HOME and XDG_CONFIG_HOME are isolated).

```bash
uv sync --frozen --group dev
uv run --frozen pytest -q -m "not live"
uv run --frozen ruff check . && uv run --frozen ruff format --check .
uv build
```

The `live` suite (`FREEBOX_TEST=1 uv run pytest -m live`) talks to a real, already-paired box and
is opt-in only.

## Rollback

Remove (or disable) the `freebox` entry in your MCP client configuration and restart the client.
To revoke the box-side access, delete the app in Freebox OS (*Gestion des accès ▸ Applications*)
and delete `$XDG_CONFIG_HOME/freebox-mcp/credentials.json`.

## Limitations and possible later scope

- Not validated against a real Freebox Pop: API v16, HTTPS on `mafreebox.freebox.fr`, redaction
  coverage and permission behaviour are unverified.
- Freebox leaf certificates have no Authority Key Identifier, which Python >= 3.13 rejects under
  its default `VERIFY_X509_STRICT`. Only that flag is cleared (`src/freebox_mcp/tls.py`); CA
  pinning, `CERT_REQUIRED`, hostname checking and TLS >= 1.2 are unchanged.
- The discovery flag `https_available` describes *remote* HTTPS access (`api_domain:https_port`),
  which this server never uses. It is shown by `discover` for information only and does not gate
  the local origin, which is HTTPS by construction and verified on every connection.
- Possible later opt-in scope (deliberately **not** in V1): reboot, Wi-Fi on/off or settings,
  DHCP range / LAN config changes, DMZ, Wake-on-LAN. Each would need its own bounded schema,
  preview and allowlist entry.

## Regenerating the spec

The upstream deterministic pipeline is kept (`python -m tools.build --offline` rebuilds the spec
from the committed cache; CI checks for drift). The curated tool list and allowlist do not change
when the spec is regenerated.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Nelson Proia; fork changes under the same
license. Not affiliated with Free / Iliad.
