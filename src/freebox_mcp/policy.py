"""The runtime endpoint policy: an exact (method, path template) allowlist.

Every request leaving the MCP runtime client is checked here on its *raw,
still-encoded* path, after tool registration and independently of it. Each path
parameter is percent-decoded exactly once and must fully match a strict
per-type pattern, so dot segments, slashes, backslashes, double encodings and
any other surprise are rejected rather than normalised. The returned canonical
path is re-encoded by us; nothing decoded is ever handed back to httpx.

The login handshake is deliberately NOT here: it goes through the separate
session client (``SessionManager``), never through the tool client.
"""

from __future__ import annotations

import re
from urllib.parse import quote, unquote

import httpx

PARAM_PATTERNS: dict[str, re.Pattern[str]] = {
    # LAN browser interface names, e.g. "pub", "wifiguest".
    "iface": re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}$"),
    # LAN host ids, e.g. "ether-00:11:22:33:44:55".
    "hostid": re.compile(r"^[A-Za-z0-9][A-Za-z0-9_:-]{0,63}$"),
    # DHCP static lease ids are the MAC address.
    "mac": re.compile(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$"),
    "int": re.compile(r"^[0-9]{1,9}$"),
}

# (method, template). Templates mirror the official spec paths exactly.
READ_ROUTES: tuple[tuple[str, str], ...] = (
    ("GET", "/system/"),
    ("GET", "/connection/"),
    ("GET", "/connection/config/"),
    ("GET", "/connection/ipv6/config/"),
    ("GET", "/connection/ftth/"),
    ("GET", "/lan/config/"),
    ("GET", "/lan/browser/interfaces/"),
    ("GET", "/lan/browser/{iface}/"),
    ("GET", "/lan/browser/{iface}/{hostid}/"),
    ("GET", "/switch/status/"),
    ("GET", "/dhcp/config/"),
    ("GET", "/dhcp/dynamic_lease/"),
    ("GET", "/dhcp/static_lease/"),
    ("GET", "/dhcp/static_lease/{mac}"),
    ("GET", "/fw/redir/"),
    ("GET", "/fw/redir/{int}"),
    ("GET", "/fw/dmz/"),
    ("GET", "/fw/incoming/"),
    # Wi-Fi state: responses are passed through the secret redactor.
    ("GET", "/wifi/config/"),
    ("GET", "/wifi/ap/"),
    ("GET", "/wifi/bss/"),
)

# Only reachable when FREEBOX_ENABLE_WRITES is on (and then only via the
# preview/apply write tools).
WRITE_ROUTES: tuple[tuple[str, str], ...] = (
    ("POST", "/dhcp/static_lease/"),
    ("PUT", "/dhcp/static_lease/{mac}"),
    ("DELETE", "/dhcp/static_lease/{mac}"),
    ("POST", "/fw/redir/"),
    ("PUT", "/fw/redir/{int}"),
    ("DELETE", "/fw/redir/{int}"),
)


class PolicyError(httpx.RequestError):
    """A request the runtime policy refuses to send."""

    def __init__(self, message: str, request: httpx.Request | None = None):
        super().__init__(message, request=request)


def _match(template: str, raw_segments: list[str]) -> str | None:
    tmpl = template.split("/")
    if len(tmpl) != len(raw_segments):
        return None
    out: list[str] = []
    for t, raw in zip(tmpl, raw_segments, strict=True):
        if t.startswith("{") and t.endswith("}"):
            value = unquote(raw, errors="strict")
            if not PARAM_PATTERNS[t[1:-1]].fullmatch(value):
                return None
            out.append(quote(value, safe=":"))
        elif t != raw:
            return None
        else:
            out.append(t)
    return "/".join(out)


def authorize(method: str, raw_path: bytes, *, writes_enabled: bool) -> str:
    """Return the canonical spec-relative path, or raise PolicyError."""
    try:
        path = raw_path.decode("ascii")
    except UnicodeDecodeError as exc:
        raise PolicyError("non-ASCII request path refused") from exc
    if "?" in path or "#" in path:
        raise PolicyError("query strings and fragments are not allowed")
    segments = path.split("/")
    routes = READ_ROUTES + (WRITE_ROUTES if writes_enabled else ())
    method = method.upper()
    for m, template in routes:
        if m != method:
            continue
        try:
            canonical = _match(template, segments)
        except UnicodeDecodeError:
            canonical = None
        if canonical is not None:
            return canonical
    raise PolicyError(f"{method} {path} is not allowed by the freebox-mcp endpoint policy")
