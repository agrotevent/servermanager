"""Connect applications (Nextcloud, Mailcow, Pangolin) to the SSO (authentik) with one click.

1. OAuth2/OIDC provider + application are created in authentik (via its internal API URL).
2. The application is configured with the public endpoints (reached through Pangolin):
   Nextcloud via ``occ`` (app user_oidc), Mailcow via its API (identity provider),
   Pangolin via its integration API (OIDC identity provider + organization policy).
If step 2 fails, the authentik application is removed again.

Pangolin is special: its callback URL contains the id of the identity provider, so the IdP is created
first (with placeholder credentials), then the authentik application, then the IdP gets the real client.
"""
from __future__ import annotations

import re
from typing import Callable, Optional
from urllib.parse import urlsplit

from .authentik import Authentik, AuthentikError
from .mailcow import MailcowError
from .models import MailcowServer, PangolinServer, SsoClient, SsoServer, System
from .pangolin import PangolinError

Log = Callable[[str], None]


class SsoError(Exception):
    pass


def public_base(url: str) -> str:
    url = (url or "").strip().rstrip("/")
    parts = urlsplit(url if "://" in url else "https://" + url)
    if parts.scheme != "https" or not parts.hostname or parts.username:
        raise SsoError("Öffentliche Adresse als https://name.example.com angeben (über Pangolin erreichbar)")
    return f"https://{parts.netloc}{parts.path.rstrip('/')}"


def slug_for(kind: str, target_id: int) -> str:
    return f"sm-{kind}-{int(target_id)}"


KIND_LABELS = {"nextcloud": "Nextcloud", "mailcow": "Mailcow", "pangolin": "Pangolin"}
TARGET_MODELS = {"nextcloud": System, "mailcow": MailcowServer, "pangolin": PangolinServer}


def redirect_uris(kind: str, app_url: str) -> list[str]:
    if kind == "nextcloud":
        return [f"{app_url}/apps/user_oidc/code", f"{app_url}/index.php/apps/user_oidc/code"]
    return [f"{app_url}/", app_url]


def provider_id(sso: SsoServer) -> str:
    """Identifier of the provider inside Nextcloud (letters/digits only)."""
    return re.sub(r"[^A-Za-z0-9]", "", sso.name or "authentik")[:30] or "authentik"


def _connect_pangolin(au: Authentik, sso: SsoServer, target, app_url: str, slug: str, name: str, log: Log,
                      pangolin) -> dict:
    ends = au.endpoints(slug)
    idp_name = f"{sso.name or 'authentik'}"[:100]
    log(f"Pangolin: Identity Provider „{idp_name}“ anlegen ...")
    idp = pangolin.create_oidc_idp(idp_name, "pending", "pending", ends["authorize"], ends["token"])
    idp_id = int(idp["idpId"])
    redirect = idp.get("redirectUrl") or f"{app_url}/auth/idp/{idp_id}/oidc/callback"
    log(f"Pangolin: IdP {idp_id}, Rückruf-Adresse {redirect}")
    app = None
    try:
        log(f"authentik: Anwendung „{name}“ ({slug}) anlegen ...")
        app = au.create_oidc_app(name, slug, [redirect], app_url)
        log(f"Client-ID {app['client_id']}")
        log("Pangolin: Client-ID und Geheimnis eintragen ...")
        pangolin.update_oidc_idp(idp_id, idp_name, app["client_id"], app["client_secret"], app["authorize"],
                                 app["token"])
        log(f"Pangolin: neue Benutzer automatisch der Organisation „{pangolin.org}“ zuordnen (Rolle Member) ...")
        try:
            pangolin.set_idp_org_policy(idp_id)
        except PangolinError as exc:
            log(f"Hinweis: Organisations-Zuordnung nicht gesetzt ({exc}) – in Pangolin unter Server-Admin → "
                "Identity Provider → Organisationsrichtlinien nachtragen")
    except Exception:
        log("Fehler – entferne Identity Provider und Anwendung wieder")
        try:
            pangolin.delete_idp(idp_id)
        except PangolinError as exc:
            log(f"Aufräumen in Pangolin fehlgeschlagen: {exc}")
        if app:
            try:
                au.delete_oidc_app(slug, app["provider_pk"])
            except AuthentikError as exc:
                log(f"Aufräumen in authentik fehlgeschlagen: {exc}")
        raise
    return {"slug": slug, "provider_pk": app["provider_pk"], "client_id": app["client_id"], "app_url": app_url,
            "target_ref": str(idp_id)}


def connect(au: Authentik, sso: SsoServer, kind: str, target, app_url: str, log: Log,
            nextcloud_occ: Optional[Callable[[str, dict], str]] = None, mailcow=None, pangolin=None) -> dict:
    """Returns the data for the SsoClient record."""
    app_url = public_base(app_url)
    slug = slug_for(kind, target.id)
    name = f"{KIND_LABELS.get(kind, kind)} {target.name}"
    if kind == "pangolin":
        return _connect_pangolin(au, sso, target, app_url, slug, name, log, pangolin)
    log(f"authentik: Anwendung „{name}“ ({slug}) anlegen ...")
    app = au.create_oidc_app(name, slug, redirect_uris(kind, app_url), app_url)
    log(f"Client-ID {app['client_id']}, Discovery {app['discovery']}")
    try:
        if kind == "nextcloud":
            log("Nextcloud: App user_oidc installieren und Anbieter einrichten ...")
            out = nextcloud_occ("oidc_setup", {"SM_OIDC_ID": provider_id(sso), "SM_OIDC_CLIENT": app["client_id"],
                                               "SM_OIDC_SECRET": app["client_secret"],
                                               "SM_OIDC_DISCOVERY": app["discovery"]})
            if "SM_OK" not in out:
                raise SsoError("Nextcloud meldet keinen Erfolg")
        elif kind == "mailcow":
            log("Mailcow: Identity Provider (Generic OIDC) setzen ...")
            mailcow.set_identity_provider({
                "authsource": "generic-oidc", "authorize_url": app["authorize"], "token_url": app["token"],
                "userinfo_url": app["userinfo"], "client_id": app["client_id"],
                "client_secret": app["client_secret"], "redirect_url": f"{app_url}/",
                "client_scopes": "openid profile email", "login_provisioning": "1", "ignore_ssl_error": "0",
                "default_template": "Default"})
        else:
            raise SsoError("Unbekannter Anwendungstyp")
    except Exception:
        log("Fehler – entferne die Anwendung wieder aus authentik")
        try:
            au.delete_oidc_app(slug, app["provider_pk"])
        except AuthentikError as exc:
            log(f"Aufräumen fehlgeschlagen: {exc}")
        raise
    return {"slug": slug, "provider_pk": app["provider_pk"], "client_id": app["client_id"], "app_url": app_url}


def disconnect(au: Authentik, sso: SsoServer, client: SsoClient, log: Log,
               nextcloud_occ: Optional[Callable[[str, dict], str]] = None, mailcow=None, pangolin=None) -> None:
    if client.target_kind == "nextcloud" and nextcloud_occ:
        log("Nextcloud: OIDC-Anbieter entfernen ...")
        nextcloud_occ("oidc_remove", {"SM_OIDC_ID": provider_id(sso)})
    elif client.target_kind == "mailcow" and mailcow is not None:
        log("Mailcow: Identity Provider zurücksetzen ...")
        try:
            mailcow.set_identity_provider({"authsource": ""})
        except MailcowError as exc:
            log(f"Mailcow: konnte nicht zurückgesetzt werden ({exc}) – bitte in der Mailcow-Oberfläche prüfen")
    elif client.target_kind == "pangolin" and pangolin is not None and (client.target_ref or "").isdigit():
        log(f"Pangolin: Identity Provider {client.target_ref} entfernen ...")
        try:
            pangolin.delete_idp(int(client.target_ref))
        except PangolinError as exc:
            if exc.status != 404:
                raise
            log("Pangolin: Identity Provider war bereits entfernt")
    log("authentik: Anwendung entfernen ...")
    au.delete_oidc_app(client.slug, client.provider_pk)


def target_of(db, kind: str, target_id: int):
    model = TARGET_MODELS.get(kind)
    return db.get(model, target_id) if model else None
