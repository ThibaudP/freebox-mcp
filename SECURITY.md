# Security Policy

## Reporting a vulnerability

Please report security issues privately via GitHub's **"Report a vulnerability"**
(Security ▸ Advisories) on this repository. Do not open a public issue for
suspected vulnerabilities.

## Threat model & design (hardened fork)

This server talks to a Freebox on your local network and holds credentials that
grant access to it. Every tool argument is chosen by the language model, so the
server treats tool input as untrusted.

- **HTTPS only, pinned origin.** Discovery (`/api_version`) and all API calls go to
  one configured origin (`FREEBOX_API_BASE_URL`, default `https://mafreebox.freebox.fr`),
  verified against the **bundled Freebox root CAs only** (`src/freebox_mcp/certs/`;
  the system trust store is not used), with `CERT_REQUIRED`, hostname checking and
  TLS >= 1.2. Only OpenSSL's `VERIFY_X509_STRICT` (Python >= 3.13 default) is
  cleared, because Freebox leaf certificates lack an Authority Key Identifier;
  standard chain verification still applies. There is no HTTP fallback: discovery errors,
  `FREEBOX_TRANSPORT=http` or an `http://` base URL are errors. The remote-access
  fields advertised by discovery (`api_domain`, `https_port`, `https_available`)
  are informational only; they never select or gate the target.
  Redirects are never followed, for authentication or regular requests.
- **stdio only.** There is no HTTP server mode, so there is no unauthenticated
  network admin endpoint.
- **Exact endpoint allowlist.** `policy.py` checks the method and the raw,
  still-encoded path of every outgoing request against a curated list, after tool
  registration and independently of it. Path parameters are decoded once and must
  match strict patterns (interface name, LAN host id, MAC, integer id); dot
  segments, slashes, backslashes, double-encoding and query strings are refused.
  The `/login/` handshake uses a separate session client and is not reachable
  from tools.
- **Writes are opt-in and preview-first.** See README *Writes and consent*. The
  operator flag narrows the reachable surface; the preview hash binds an apply to
  the exact previewed request (tool, method, path, body) and state, preventing
  substituted or stale changes. Neither is a human-approval mechanism.
- **Secrets.** The `app_token` never transits the network (only
  `HMAC-SHA1(app_token, challenge)`). It is stored at
  `$XDG_CONFIG_HOME/freebox-mcp/credentials.json` (default `~/.config/...`), file
  `0600`, directory `0700`, written atomically, and never logged or returned.
  Secret-named fields in Freebox replies (Wi-Fi keys, WPS PINs, passwords,
  tokens) are replaced with `<redacted>` before reaching the model.

## Permissions

The app gets only what you approve on the Freebox. Reads need no `settings`
permission. The optional DHCP / NAT write tools need the `settings` permission;
if you do not enable writes, leave `settings` unticked for this app in Freebox OS
(*Paramètres ▸ Gestion des accès ▸ Applications*) as a second line of defence.
