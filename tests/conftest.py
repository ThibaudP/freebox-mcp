"""Shared fixtures. Tests run against the committed pipeline cache + spec, so
they are hermetic (no network) except the opt-in live suite.

Every test runs with an isolated HOME / XDG_CONFIG_HOME and without any
inherited FREEBOX_* variable, so real credentials can never be read or written.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import respx

REPO = Path(__file__).resolve().parent.parent
ORIGIN = "https://mafreebox.freebox.fr"
PREFIX = "/api/v16"

DISCOVERY = {
    "box_model_name": "Freebox Pop Test",
    "api_base_url": "/api/",
    "api_version": "16.0",
    "https_available": True,
    "api_domain": "test.fbxos.fr",
    "https_port": 55688,
    "uid": "test-uid",
}


@pytest.fixture(autouse=True)
def isolated_env(request, tmp_path, monkeypatch):
    if request.node.get_closest_marker("live"):
        return None  # opt-in live suite (FREEBOX_TEST=1) uses the operator's real config
    for key in list(os.environ):
        if key.startswith("FREEBOX_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    return tmp_path


@pytest.fixture(scope="session")
def repo() -> Path:
    return REPO


@pytest.fixture(scope="session")
def spec() -> dict:
    return json.loads((REPO / "spec" / "freebox-openapi.json").read_text())


@pytest.fixture(scope="session")
def ir() -> dict:
    return json.loads((REPO / "tools" / "cache" / "ir.json").read_text())


@pytest.fixture
def paired(isolated_env):
    """A dummy app_token stored for the mocked box uid, in the isolated config dir."""
    from freebox_mcp.auth import BoxCredentials, TokenStore
    from freebox_mcp.config import Settings

    TokenStore(Settings().credentials_path).set(
        "test-uid", BoxCredentials(app_id="freebox-mcp", app_token="DUMMY-APP-TOKEN")
    )


@pytest.fixture
def box(paired):
    """A mocked Freebox over HTTPS: discovery + login handshake. Any other
    unmocked request fails the test (respx raises AllMockedAssertionError)."""
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{ORIGIN}/api_version").respond(json=DISCOVERY)
        router.get(f"{ORIGIN}{PREFIX}/login/").respond(
            json={"success": True, "result": {"challenge": "chA", "logged_in": False}}
        )
        router.post(f"{ORIGIN}{PREFIX}/login/session/").respond(
            json={
                "success": True,
                "result": {"session_token": "S-TOKEN", "permissions": {"settings": True}},
            }
        )
        yield router


def ok(result) -> dict:
    return {"success": True, "result": result}
