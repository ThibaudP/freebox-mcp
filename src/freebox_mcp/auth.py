"""Freebox authentication: app registration + session challenge (HMAC-SHA1).

Flow (https://dev.freebox.fr/sdk/os/login/):
  1. POST /login/authorize/  {app_id, app_name, app_version, device_name}
        -> {app_token, track_id}   (user must approve on the Freebox LCD)
  2. poll GET /login/authorize/{track_id} until status == "granted"
  3. GET  /login/                -> {challenge}
  4. password = HMAC-SHA1(app_token, challenge)
  5. POST /login/session/  {app_id, password} -> {session_token, permissions}

The long-lived ``app_token`` is the only real secret; it NEVER transits the wire
(only the per-challenge HMAC does). It is stored locally with 0600 permissions
and is never logged.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import httpx


class FreeboxError(RuntimeError):
    def __init__(self, message: str, error_code: str | None = None):
        super().__init__(message)
        self.error_code = error_code


def compute_password(app_token: str, challenge: str) -> str:
    """Session password = HMAC-SHA1(app_token, challenge), hex digest."""
    return hmac.new(app_token.encode(), challenge.encode(), hashlib.sha1).hexdigest()


def _result(resp: httpx.Response) -> dict:
    if resp.is_redirect:
        raise FreeboxError("redirect refused on an authentication request", "redirect_refused")
    try:
        body = resp.json()
    except ValueError as exc:
        raise FreeboxError(f"HTTP {resp.status_code}: not a Freebox JSON reply") from exc
    if not isinstance(body, dict) or not body.get("success", False):
        body = body if isinstance(body, dict) else {}
        raise FreeboxError(body.get("msg", "Freebox API error"), body.get("error_code"))
    return body.get("result", {})


# --------------------------------------------------------------------------- #
# Credential storage
# --------------------------------------------------------------------------- #
@dataclass
class BoxCredentials:
    app_id: str
    app_token: str
    track_id: int | None = None
    box_model: str | None = None


class TokenStore:
    """Per-box app_token storage at credentials_path (file 0600, directory 0700)."""

    def __init__(self, path: Path):
        self.path = path

    def _load(self) -> dict:
        if not self.path.exists():
            return {"version": 1, "boxes": {}}
        try:
            return json.loads(self.path.read_text())
        except (json.JSONDecodeError, OSError):
            return {"version": 1, "boxes": {}}

    def get(self, uid: str | None) -> BoxCredentials | None:
        data = self._load()
        entry = data.get("boxes", {}).get(uid or "default")
        if not entry:
            return None
        return BoxCredentials(**entry)

    def set(self, uid: str | None, creds: BoxCredentials) -> None:
        data = self._load()
        data.setdefault("boxes", {})[uid or "default"] = {
            "app_id": creds.app_id,
            "app_token": creds.app_token,
            "track_id": creds.track_id,
            "box_model": creds.box_model,
        }
        # Private directory (0700), then an atomic write via a unique 0600 temp file.
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        fd, tmp = tempfile.mkstemp(prefix=".credentials-", dir=self.path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
        os.chmod(self.path, 0o600)


# --------------------------------------------------------------------------- #
# Registration (interactive — used by the CLI)
# --------------------------------------------------------------------------- #
@dataclass
class AuthorizationRequest:
    app_token: str
    track_id: int


def request_authorization(
    http: httpx.Client, prefix: str, app_id: str, app_name: str, app_version: str, device_name: str
) -> AuthorizationRequest:
    res = _result(
        http.post(
            f"{prefix}/login/authorize/",
            json={
                "app_id": app_id,
                "app_name": app_name,
                "app_version": app_version,
                "device_name": device_name,
            },
        )
    )
    return AuthorizationRequest(app_token=res["app_token"], track_id=res["track_id"])


def poll_authorization(http: httpx.Client, prefix: str, track_id: int) -> str:
    """Return the current authorization status: unknown/pending/granted/denied/timeout."""
    res = _result(http.get(f"{prefix}/login/authorize/{track_id}"))
    return res.get("status", "unknown")


def wait_for_authorization(
    http: httpx.Client, prefix: str, track_id: int, timeout: float = 90.0, interval: float = 2.0
) -> str:
    deadline = time.monotonic() + timeout
    status = "pending"
    while time.monotonic() < deadline:
        status = poll_authorization(http, prefix, track_id)
        if status != "pending":
            return status
        time.sleep(interval)
    return status


# --------------------------------------------------------------------------- #
# Session (used at runtime, async)
# --------------------------------------------------------------------------- #
@dataclass
class Session:
    session_token: str
    permissions: dict


async def open_session(
    http: httpx.AsyncClient, prefix: str, app_id: str, app_token: str
) -> Session:
    login = await http.get(f"{prefix}/login/")
    challenge = _result(login)["challenge"]
    password = compute_password(app_token, challenge)
    resp = await http.post(
        f"{prefix}/login/session/", json={"app_id": app_id, "password": password}
    )
    res = _result(resp)
    return Session(session_token=res["session_token"], permissions=res.get("permissions", {}))
