"""Login to the servermanager itself through the SSO (authentik, OpenID Connect).

Authorization code flow with PKCE, state and nonce. The browser is sent to the public login page of
authentik; the code is exchanged over the internal, pinned API address of authentik (server to server,
TLS-authenticated, so the ID token needs no separate signature check – OIDC Core 3.1.3.7). Users are
matched by user name; administrators only when allowed explicitly; a local second factor stays required.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
from types import SimpleNamespace
from typing import Optional
from urllib.parse import urlencode

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import security, settings
from .authentik import Authentik
from .models import ROLE_USER, SsoClient, SsoServer, User

KIND = "servermanager"
CALLBACK = "/login/sso/callback"
STATE_TTL = 600
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{1,63}$")
TARGET = SimpleNamespace(id=0, name="Servermanager")


class LoginError(Exception):
    pass


def active(db: Session) -> Optional[tuple[SsoServer, SsoClient]]:
    client = db.execute(select(SsoClient).where(SsoClient.target_kind == KIND,
                                                SsoClient.status == "active")).scalars().first()
    if client is None or not client.secret_enc:
        return None
    srv = db.get(SsoServer, client.sso_id)
    return (srv, client) if srv is not None else None


def redirect_uri(app_url: str) -> str:
    return f"{app_url.rstrip('/')}{CALLBACK}"


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def authorize_url(au: Authentik, client: SsoClient, state: str, nonce: str, challenge: str) -> str:
    q = {"response_type": "code", "client_id": client.client_id, "redirect_uri": redirect_uri(client.app_url),
         "scope": "openid profile email", "state": state, "nonce": nonce, "code_challenge": challenge,
         "code_challenge_method": "S256"}
    return f"{au.endpoints('')['authorize']}?{urlencode(q)}"


def _claims(id_token: str) -> dict:
    try:
        payload = id_token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (IndexError, ValueError):
        raise LoginError("authentik hat kein gültiges ID-Token geliefert") from None


def exchange(au: Authentik, client: SsoClient, code: str, verifier: str, nonce: str) -> dict:
    """Code -> tokens -> user info. Checks nonce and audience of the ID token."""
    tokens = au.oidc_token(code, redirect_uri(client.app_url), client.client_id,
                           security.decrypt(client.secret_enc), verifier)
    claims = _claims(tokens.get("id_token") or "")
    aud = claims.get("aud")
    if client.client_id not in (aud if isinstance(aud, list) else [aud]):
        raise LoginError("ID-Token ist nicht für den Servermanager ausgestellt")
    if not nonce or not secrets.compare_digest(str(claims.get("nonce") or ""), nonce):
        raise LoginError("ID-Token passt nicht zu dieser Anmeldung (nonce)")
    if not tokens.get("access_token"):
        raise LoginError("authentik hat kein Zugriffstoken geliefert")
    info = au.oidc_userinfo(tokens["access_token"])
    if info.get("sub") != claims.get("sub"):
        raise LoginError("Benutzerinformationen passen nicht zum ID-Token")
    return info


def resolve_user(db: Session, info: dict) -> tuple[User, bool]:
    """Local user for the SSO identity (created if allowed). Returns (user, created)."""
    username = str(info.get("preferred_username") or "").strip()
    if not USERNAME_RE.match(username):
        raise LoginError("Der authentik-Benutzername ist für den Servermanager nicht zulässig")
    group = (settings.get(db, "login.sso_group") or "").strip()
    if group and group not in [str(x) for x in (info.get("groups") or [])]:
        raise LoginError(f"Keine Berechtigung: Mitgliedschaft in der authentik-Gruppe „{group}“ erforderlich")
    user = db.execute(select(User).where(func.lower(User.username) == username.lower())).scalar_one_or_none()
    if user is None:
        if not settings.get(db, "login.sso_auto_create"):
            raise LoginError(f"Für „{username}“ gibt es kein Konto im Servermanager – bitte einen Administrator "
                             "fragen")
        user = User(username=username, display_name=str(info.get("name") or "")[:128],
                    email=str(info.get("email") or "")[:255], role=ROLE_USER,
                    password_hash=security.hash_password(secrets.token_urlsafe(32)))
        db.add(user)
        db.flush()
        return user, True
    if not user.active:
        raise LoginError("Das Konto ist im Servermanager deaktiviert")
    if user.is_admin and not settings.get(db, "login.sso_admins"):
        raise LoginError("Administratoren melden sich mit Passwort an (SSO für Administratoren ist nicht "
                         "freigegeben)")
    return user, False
