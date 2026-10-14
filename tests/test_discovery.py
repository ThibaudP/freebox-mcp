"""Discovery parsing and transport selection (no network).

The hardened fork is HTTPS-only: discovery is fetched from the configured
(pinned) HTTPS origin, verified against the bundled Freebox CAs, and every
failure is fatal — there is no cleartext fallback.
"""

from __future__ import annotations

import ssl

import httpx
import pytest
import respx

from freebox_mcp.auth import FreeboxError
from freebox_mcp.config import CERT_BUNDLE, Settings
from freebox_mcp.discovery import Discovery, choose_endpoint, fetch_discovery
from freebox_mcp.tls import freebox_ssl_context

ORIGIN = "https://mafreebox.freebox.fr"

DISCOVERY = {
    "box_model_name": "Freebox Pop Test",
    "api_base_url": "/api/",
    "api_version": "16.0",
    "https_available": True,
    "api_domain": "attacker.example",
    "https_port": 4443,
    "uid": "uid",
}


def _disc(**kw) -> Discovery:
    base = dict(
        api_domain="abcd.fbxos.fr",
        https_port=55688,
        https_available=True,
        api_base_url="/api/",
        api_version="16.0",
        box_model_name="Freebox Server",
        uid="uid",
    )
    base.update(kw)
    return Discovery(**base)


def test_api_major_and_prefix():
    assert _disc(api_version="16.0").api_major == 16
    assert _disc(api_version="8.1").api_major == 8
    assert _disc(api_version="16.0").api_path_prefix == "/api/v16"


def test_garbage_api_version_is_rejected_not_defaulted():
    with pytest.raises(FreeboxError):
        _ = _disc(api_version="garbage").api_major


def test_default_origin_is_https():
    ep = choose_endpoint(Settings(), _disc())
    assert ep.base_url == ORIGIN
    assert ep.secure is True
    assert ep.api_path_prefix == "/api/v16"


@pytest.mark.parametrize("transport", ["http", "auto", "HTTP"])
def test_http_or_auto_transport_is_rejected(transport):
    with pytest.raises(ValueError, match="HTTPS"):
        Settings(transport=transport)


def test_http_transport_env_is_rejected(monkeypatch):
    monkeypatch.setenv("FREEBOX_TRANSPORT", "http")
    with pytest.raises(ValueError, match="HTTPS"):
        Settings()


@pytest.mark.parametrize(
    "override",
    [
        "http://mafreebox.freebox.fr",
        "https://user:pw@box.example",
        "https://box.example/api/",
        "https://box.example?x=1",
        "ftp://box.example",
    ],
)
def test_unsafe_base_url_override_is_rejected(override):
    with pytest.raises(ValueError):
        Settings(base_url_override=override)


def test_https_override_is_pinned_even_if_discovery_advertises_other_domain():
    settings = Settings(base_url_override="https://abcd.fbxos.fr:55688/")
    ep = choose_endpoint(settings, _disc(api_domain="attacker.example", https_port=1))
    assert ep.base_url == "https://abcd.fbxos.fr:55688"
    assert ep.secure is True


def test_discovery_url_env_is_rejected(monkeypatch):
    monkeypatch.setenv("FREEBOX_DISCOVERY_URL", "http://mafreebox.freebox.fr/api_version")
    with pytest.raises(ValueError):
        Settings()


def test_remote_https_flag_false_still_uses_pinned_https_origin():
    # https_available describes REMOTE access (api_domain:https_port), not the local
    # origin, which discovery has just reached over verified HTTPS.
    ep = choose_endpoint(Settings(), _disc(https_available=False))
    assert ep.base_url == ORIGIN
    assert ep.secure is True
    assert ep.discovery.https_available is False


@respx.mock
def test_discovery_is_fetched_over_pinned_https_origin():
    route = respx.get(f"{ORIGIN}/api_version").respond(json=DISCOVERY)
    d = fetch_discovery(Settings())
    assert route.called
    assert d.api_path_prefix == "/api/v16"
    # The advertised remote domain is informational only; it never becomes the target.
    assert choose_endpoint(Settings(), d).base_url == ORIGIN


@respx.mock
def test_discovery_failure_raises_instead_of_falling_back():
    respx.get(f"{ORIGIN}/api_version").mock(side_effect=httpx.ConnectError("boom"))
    plain = respx.get("http://mafreebox.freebox.fr/api_version").respond(json=DISCOVERY)
    with pytest.raises(httpx.ConnectError):
        fetch_discovery(Settings())
    assert not plain.called


@respx.mock
def test_discovery_redirect_is_rejected():
    respx.get(f"{ORIGIN}/api_version").respond(
        302, headers={"location": "http://evil.example/api_version"}
    )
    evil = respx.get("http://evil.example/api_version").respond(json=DISCOVERY)
    with pytest.raises(FreeboxError):
        fetch_discovery(Settings())
    assert not evil.called


@respx.mock
def test_discovery_rejects_malformed_api_base_url():
    respx.get(f"{ORIGIN}/api_version").respond(json={**DISCOVERY, "api_base_url": "/../x/"})
    with pytest.raises(FreeboxError):
        fetch_discovery(Settings())


def test_ssl_context_trusts_only_bundled_freebox_cas():
    ctx = freebox_ssl_context(str(CERT_BUNDLE))
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2
    subjects = {dict(x[0] for x in c["subject"])["commonName"] for c in ctx.get_ca_certs()}
    assert subjects == {"Freebox Root CA", "Freebox ECC Root CA"}
