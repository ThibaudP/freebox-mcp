"""freebox-mcp command line.

freebox-mcp                 run the MCP server over stdio (the only transport)
freebox-mcp authorize       register the app (press the button on the box)
freebox-mcp login           open a session and print granted permissions
freebox-mcp discover        print discovery info and the pinned HTTPS endpoint
freebox-mcp tools           list the exposed MCP tools (offline)

There is deliberately no HTTP server mode and no raw "call any operation" command.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys

from . import __version__
from .auth import (
    BoxCredentials,
    FreeboxError,
    TokenStore,
    request_authorization,
    wait_for_authorization,
)
from .client import build_session_manager
from .config import load_settings
from .discovery import choose_endpoint, fetch_discovery, https_client
from .server import create_server


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def cmd_discover(args) -> int:
    settings = load_settings()
    endpoint = choose_endpoint(settings)
    d = endpoint.discovery
    print(
        json.dumps(
            {
                "box_model": d.box_model_name,
                "api_version": d.api_version,
                "api_major": d.api_major,
                "uid": d.uid,
                "api_domain": d.api_domain,
                "https_port": d.https_port,
                "https_available": d.https_available,
                "pinned_base_url": endpoint.base_url,
                "api_path_prefix": endpoint.api_path_prefix,
                "transport": "https",
            },
            indent=2,
        )
    )
    return 0


def cmd_authorize(args) -> int:
    settings = load_settings()
    # Auth-only client: pinned HTTPS origin, Freebox CA, no redirects. The /login/
    # POSTs live here, never in the MCP runtime client.
    with https_client(settings) as http:
        endpoint = choose_endpoint(settings, fetch_discovery(settings, http))
        req = request_authorization(
            http,
            endpoint.api_path_prefix,
            settings.app_id,
            settings.app_name,
            settings.app_version,
            settings.device_name,
        )
        print(">>> Press the button (►) on the front panel of the Freebox to grant access.")
        print(
            f"    app_id={settings.app_id}  track_id={req.track_id}  (waiting up to {args.timeout}s)"
        )
        status = wait_for_authorization(
            http, endpoint.api_path_prefix, req.track_id, timeout=args.timeout
        )
    if status == "granted":
        store = TokenStore(settings.credentials_path)
        store.set(
            endpoint.discovery.uid,
            BoxCredentials(
                app_id=settings.app_id,
                app_token=req.app_token,
                track_id=req.track_id,
                box_model=endpoint.discovery.box_model_name,
            ),
        )
        print(f"✓ Authorized. Credentials saved to {settings.credentials_path} (0600).")
        return 0
    print(f"✗ Authorization {status}. Re-run and press the button in time.", file=sys.stderr)
    return 1


async def _login() -> dict:
    settings = load_settings()
    endpoint = choose_endpoint(settings)
    store = TokenStore(settings.credentials_path)
    session = build_session_manager(settings, endpoint, store)
    try:
        await session.refresh()
    finally:
        await session.aclose()
    return {
        "box": endpoint.discovery.box_model_name,
        "transport": "https",
        "permissions": session.permissions,
    }


def cmd_login(args) -> int:
    try:
        info = asyncio.run(_login())
    except FreeboxError as e:
        print(f"✗ {e} (error_code={e.error_code})", file=sys.stderr)
        return 1
    print(json.dumps(info, indent=2))
    return 0


def cmd_tools(args) -> int:
    async def _list():
        mcp = create_server()
        tools = await mcp.list_tools()
        return sorted(t.name for t in tools)

    names = asyncio.run(_list())
    for n in names:
        print(n)
    print(f"\n{len(names)} tools", file=sys.stderr)
    return 0


def cmd_run(args) -> int:
    create_server().run(transport="stdio", show_banner=False)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="freebox-mcp",
        description="Hardened stdio MCP server for the Freebox OS API (Freebox Pop V1).",
    )
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=f"freebox-mcp {__version__}")
    p.set_defaults(func=cmd_run)

    sub = p.add_subparsers()
    sub.add_parser("discover", help="print discovery + pinned endpoint").set_defaults(
        func=cmd_discover
    )
    a = sub.add_parser("authorize", help="register the app (press the button)")
    a.add_argument("--timeout", type=int, default=90)
    a.set_defaults(func=cmd_authorize)
    sub.add_parser("login", help="open a session, print permissions").set_defaults(func=cmd_login)
    sub.add_parser("tools", help="list exposed tools (offline)").set_defaults(func=cmd_tools)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(getattr(args, "verbose", False))
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
