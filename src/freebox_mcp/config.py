"""Runtime configuration, loaded from the environment with safe defaults.

Hardened fork: the box is only ever reached over verified HTTPS at a single,
operator-configured origin. Settings that would weaken that (cleartext
transport, a separate discovery URL) are rejected instead of honoured.
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__

CERT_BUNDLE = Path(__file__).resolve().parent / "certs" / "freebox_rootca.pem"
DEFAULT_ORIGIN = "https://mafreebox.freebox.fr"


def _default_credentials_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return Path(base) / "freebox-mcp" / "credentials.json"


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes")


def normalize_origin(url: str) -> str:
    """Validate an ``https://host[:port]`` origin; reject anything else."""
    parts = urlsplit(url.strip())
    if parts.scheme != "https":
        raise ValueError(f"FREEBOX_API_BASE_URL must be an HTTPS origin, got {url!r}")
    if not parts.hostname or parts.username or parts.password:
        raise ValueError("FREEBOX_API_BASE_URL must be https://host[:port] without credentials")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValueError("FREEBOX_API_BASE_URL must not contain a path, query or fragment")
    _ = parts.port  # raises ValueError on a malformed port
    return f"https://{parts.netloc}"


@dataclass(frozen=True)
class Settings:
    # Identity shown in the Freebox "authorized apps" list.
    app_id: str = field(default_factory=lambda: os.environ.get("FREEBOX_APP_ID", "freebox-mcp"))
    app_name: str = field(default_factory=lambda: os.environ.get("FREEBOX_APP_NAME", "Freebox MCP"))
    app_version: str = field(
        default_factory=lambda: os.environ.get("FREEBOX_APP_VERSION", __version__)
    )
    device_name: str = field(
        default_factory=lambda: os.environ.get("FREEBOX_DEVICE_NAME") or socket.gethostname()
    )

    # Pinned HTTPS origin. Discovery (/api_version) and every API call go to this
    # origin only; the remote domain advertised by discovery is never followed.
    base_url_override: str | None = field(
        default_factory=lambda: os.environ.get("FREEBOX_API_BASE_URL") or None
    )
    # Only "https" is accepted; kept so a stale FREEBOX_TRANSPORT=http fails loudly.
    transport: str = field(default_factory=lambda: os.environ.get("FREEBOX_TRANSPORT", "https"))
    https_probe_timeout: float = field(
        default_factory=lambda: float(os.environ.get("FREEBOX_HTTPS_PROBE_TIMEOUT", "5"))
    )
    request_timeout: float = field(
        default_factory=lambda: float(os.environ.get("FREEBOX_REQUEST_TIMEOUT", "20"))
    )

    # Opt-in for the DHCP static lease / NAT port forward write tools. Off by
    # default; even when on, every write is a preview unless dry_run=false and
    # the preview's state hash is supplied.
    enable_writes: bool = field(default_factory=lambda: _env_flag("FREEBOX_ENABLE_WRITES"))

    credentials_path: Path = field(default_factory=_default_credentials_path)
    cert_bundle: Path = CERT_BUNDLE

    def __post_init__(self) -> None:
        if self.transport.strip().lower() != "https":
            raise ValueError(
                f"FREEBOX_TRANSPORT={self.transport!r} is not supported: this build is HTTPS-only"
            )
        if os.environ.get("FREEBOX_DISCOVERY_URL"):
            raise ValueError(
                "FREEBOX_DISCOVERY_URL is not supported: discovery is fetched from the pinned "
                "HTTPS origin (FREEBOX_API_BASE_URL)"
            )
        object.__setattr__(
            self, "base_url_override", normalize_origin(self.base_url_override or DEFAULT_ORIGIN)
        )

    @property
    def origin(self) -> str:
        return self.base_url_override or DEFAULT_ORIGIN


def load_settings() -> Settings:
    return Settings()
