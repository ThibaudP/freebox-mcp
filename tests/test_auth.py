"""Auth primitives: HMAC-SHA1 session password + secure token storage."""

from __future__ import annotations

import json
import stat

from freebox_mcp.auth import BoxCredentials, TokenStore, compute_password


def test_hmac_sha1_known_vector():
    # HMAC-SHA1(key="appToken123", msg="challengeABC")
    assert (
        compute_password("appToken123", "challengeABC")
        == "866f9fbd227cfeee97e4725699bf346ba3585d82"
    )
    assert len(compute_password("k", "c")) == 40  # sha1 hex, not sha256


def test_token_store_roundtrip_and_permissions(tmp_path):
    path = tmp_path / "credentials.json"
    store = TokenStore(path)
    assert store.get("uid-1") is None
    store.set("uid-1", BoxCredentials(app_id="freebox-mcp", app_token="deadbeef", track_id=7))
    got = store.get("uid-1")
    assert got.app_token == "deadbeef"
    assert got.app_id == "freebox-mcp"
    # file must be owner-read/write only (0600)
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600, oct(mode)
    # second box does not clobber the first
    store.set("uid-2", BoxCredentials(app_id="freebox-mcp", app_token="cafe"))
    data = json.loads(path.read_text())
    assert set(data["boxes"]) == {"uid-1", "uid-2"}


def test_token_store_private_dir_and_atomic_write(tmp_path):
    import os

    base = tmp_path / "cfg"
    base.mkdir(mode=0o755)
    path = base / "freebox-mcp" / "credentials.json"
    old = os.umask(0)
    try:
        TokenStore(path).set("u", BoxCredentials(app_id="a", app_token="t"))
    finally:
        os.umask(old)
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert sorted(p.name for p in path.parent.iterdir()) == ["credentials.json"]


def test_token_store_tightens_existing_loose_dir(tmp_path):
    d = tmp_path / "freebox-mcp"
    d.mkdir(mode=0o777)
    d.chmod(0o777)
    TokenStore(d / "credentials.json").set("u", BoxCredentials(app_id="a", app_token="t"))
    assert stat.S_IMODE(d.stat().st_mode) == 0o700


def test_default_credentials_path_is_isolated(isolated_env):
    from freebox_mcp.config import Settings

    assert str(Settings().credentials_path).startswith(str(isolated_env))


def test_cli_authorize_over_https_stores_token_without_printing_it(isolated_env, capsys):
    import respx

    from freebox_mcp.__main__ import main
    from freebox_mcp.config import Settings
    from tests.conftest import DISCOVERY, ORIGIN, PREFIX, ok

    with respx.mock(assert_all_called=False) as router:
        router.get(f"{ORIGIN}/api_version").respond(json=DISCOVERY)
        router.post(f"{ORIGIN}{PREFIX}/login/authorize/").respond(
            json=ok({"app_token": "NEW-SECRET-APP-TOKEN", "track_id": 42})
        )
        router.get(f"{ORIGIN}{PREFIX}/login/authorize/42").respond(json=ok({"status": "granted"}))
        assert main(["authorize", "--timeout", "1"]) == 0
    out = capsys.readouterr()
    assert "NEW-SECRET-APP-TOKEN" not in out.out + out.err
    path = Settings().credentials_path
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert TokenStore(path).get("test-uid").app_token == "NEW-SECRET-APP-TOKEN"


def test_cli_login_prints_permissions_not_tokens(box, capsys):
    from freebox_mcp.__main__ import main

    assert main(["login"]) == 0
    out = capsys.readouterr()
    assert "settings" in out.out
    assert "DUMMY-APP-TOKEN" not in out.out + out.err and "S-TOKEN" not in out.out + out.err


def test_cli_has_no_http_server_or_raw_call():
    import pytest

    from freebox_mcp.__main__ import main

    for argv in (["--http"], ["call", "get_system"]):
        with pytest.raises(SystemExit):
            main(argv)
