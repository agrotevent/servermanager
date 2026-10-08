"""Connect applications (Nextcloud, Mailcow, Pangolin, Proxmox VE, Zammad) to the SSO (authentik) with one click.

1. OAuth2/OIDC provider + application are created in authentik (via its internal API URL).
2. The application is configured with the public endpoints (reached through Pangolin):
   Nextcloud via ``occ`` (app user_oidc), Mailcow via its API (identity provider),
   Pangolin via its integration API (OIDC identity provider + organization policy),
   Proxmox VE via its API (OpenID Connect realm, users created on first login without permissions),
   Zammad via its settings API (OpenID Connect as third-party login, public client with PKCE).
If step 2 fails, the authentik application is removed again.

Pangolin is special: its callback URL contains the id of the identity provider, so the IdP is created
first (with placeholder credentials), then the authentik application, then the IdP gets the real client.
"""
from __future__ import annotations

import re
from typing import Callable, Optional
from urllib.parse import urlsplit

from . import security
from .authentik import Authentik, AuthentikError
from .mailcow import MailcowError
from .models import MailcowServer, PangolinServer, PveServer, SsoClient, SsoServer, System, ZammadServer
from .pangolin import PangolinError
from .pveapi import PveError
from .zammad import ZammadError

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


KIND_LABELS = {"nextcloud": "Nextcloud", "mailcow": "Mailcow", "pangolin": "Pangolin", "pve": "Proxmox",
               "zammad": "Zammad", "servermanager": "Anmeldung am"}
TARGET_MODELS = {"nextcloud": System, "mailcow": MailcowServer, "pangolin": PangolinServer, "pve": PveServer,
                 "zammad": ZammadServer}


def redirect_uris(kind: str, app_url: str) -> list[str]:
    if kind == "nextcloud":
        return [f"{app_url}/apps/user_oidc/code", f"{app_url}/index.php/apps/user_oidc/code"]
    if kind == "servermanager":
        from .sso_login import redirect_uri
        return [redirect_uri(app_url)]
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
            from .pangolin import role_mapping_expression
            rm = getattr(target, "role_map", None) or {}
            pangolin.set_idp_org_policy(idp_id, role_mapping_expression(rm.get("rules") or [],
                                                                        rm.get("default") or "Member"))
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


def pve_realm(sso: SsoServer) -> str:
    """Realm id in Proxmox (letters, digits, - and _, starts with a letter, max. 32)."""
    realm = re.sub(r"[^a-z0-9_-]", "", (sso.name or "").lower())[:32] or "authentik"
    return realm if realm[0].isalpha() else ("sso" + realm)[:32]


def _connect_pve(au: Authentik, sso: SsoServer, target, app_url: str, slug: str, name: str, log: Log, pve,
                 options: dict) -> dict:
    realm = pve_realm(sso)
    existing = {d.get("realm"): d for d in pve.get("access/domains") or []}
    if realm in existing and existing[realm].get("type") != "openid":
        raise SsoError(f"In Proxmox gibt es bereits einen Realm „{realm}“ anderen Typs – SSO-Verbindung umbenennen")
    log(f"authentik: Anwendung „{name}“ ({slug}) anlegen ...")
    app = au.create_oidc_app(name, slug, redirect_uris("pve", app_url), app_url)
    log(f"Client-ID {app['client_id']}, Aussteller {app['issuer']}")
    # exactly authentik's issuer incl. trailing slash – Proxmox compares it with the discovery document
    params = {"issuer-url": app["issuer"], "client-id": app["client_id"],
              "client-key": app["client_secret"], "autocreate": 1, "scopes": "openid email profile",
              "comment": f"authentik {sso.name} (Servermanager)", "default": 1 if options.get("default") else 0}
    if options.get("groups"):
        params.update({"groups-claim": "groups", "groups-autocreate": 1})
    try:
        if realm in existing:
            log(f"Proxmox: vorhandenen OpenID-Realm „{realm}“ aktualisieren ...")
            pve.put(f"access/domains/{realm}", **params)
        else:
            log(f"Proxmox: OpenID-Realm „{realm}“ anlegen (Benutzername = authentik-Benutzername) ...")
            try:
                pve.post("access/domains", realm=realm, type="openid", **{"username-claim": "username"}, **params)
            except PveError as exc:
                if options.get("groups") and exc.status == 400 and "groups" in str(exc):
                    log("Proxmox kennt die Gruppen-Übernahme noch nicht (ab PVE 8.1) – Realm ohne Gruppen anlegen")
                    for k in ("groups-claim", "groups-autocreate"):
                        params.pop(k, None)
                    pve.post("access/domains", realm=realm, type="openid", **{"username-claim": "username"},
                             **params)
                else:
                    raise
    except PveError as exc:
        log("Fehler – entferne die Anwendung wieder aus authentik")
        try:
            au.delete_oidc_app(slug, app["provider_pk"])
        except AuthentikError as exc2:
            log(f"Aufräumen fehlgeschlagen: {exc2}")
        if exc.status == 403:
            raise SsoError(f"{exc} – zum Anlegen eines Realms braucht das API-Token das Recht Realm.Allocate auf "
                           "/access/realm (z. B. Rolle Administrator)") from exc
        raise
    log("Neue Benutzer werden beim ersten Login angelegt – ohne Rechte; Rechte in Proxmox unter "
        "Rechenzentrum → Berechtigungen vergeben (Benutzer <name>@" + realm + ")")
    return {"slug": slug, "provider_pk": app["provider_pk"], "client_id": app["client_id"], "app_url": app_url,
            "target_ref": realm}


def _connect_zammad(au: Authentik, sso: SsoServer, app_url: str, slug: str, name: str, log: Log, zammad,
                    options: dict) -> dict:
    from . import zammad as zlib
    log("Zammad: Einstellungen lesen ...")
    by = zlib.oidc_settings(zammad)
    redirect = zlib.callback_url(by, app_url)
    log(f"Zammad: Rückruf-Adresse {redirect}")
    log(f"authentik: Anwendung „{name}“ ({slug}) als öffentlichen Client mit PKCE anlegen ...")
    app = au.create_oidc_app(name, slug, [redirect], app_url, client_type="public")
    log(f"Client-ID {app['client_id']}, Aussteller {app['issuer']}")
    try:
        log("Zammad: Anmeldung über OpenID Connect einrichten ...")
        zlib.enable_oidc(zammad, by, app["client_id"], app["issuer"], sso.name or "authentik",
                         auto_link=bool(options.get("auto_link", True)))
    except ZammadError:
        log("Fehler – entferne die Anwendung wieder aus authentik")
        try:
            au.delete_oidc_app(slug, app["provider_pk"])
        except AuthentikError as exc:
            log(f"Aufräumen fehlgeschlagen: {exc}")
        raise
    if options.get("auto_link", True):
        log("Bestehende Zammad-Konten werden beim ersten Login über die E-Mail-Adresse bzw. den Benutzernamen "
            "verknüpft")
    return {"slug": slug, "provider_pk": app["provider_pk"], "client_id": app["client_id"], "app_url": app_url,
            "target_ref": "openid_connect"}


def connect(au: Authentik, sso: SsoServer, kind: str, target, app_url: str, log: Log,
            nextcloud_occ: Optional[Callable[[str, dict], str]] = None, mailcow=None, pangolin=None, pve=None,
            zammad=None, options: Optional[dict] = None) -> dict:
    """Returns the data for the SsoClient record."""
    app_url = public_base(app_url)
    slug = slug_for(kind, target.id)
    name = target.name if kind == "servermanager" else f"{KIND_LABELS.get(kind, kind)} {target.name}"
    if kind == "pangolin":
        return _connect_pangolin(au, sso, target, app_url, slug, name, log, pangolin)
    if kind == "pve":
        return _connect_pve(au, sso, target, app_url, slug, name, log, pve, options or {})
    if kind == "zammad":
        return _connect_zammad(au, sso, app_url, slug, name, log, zammad, options or {})
    if kind == "servermanager":
        log(f"authentik: Anwendung „{name}“ ({slug}) anlegen ...")
        app = au.create_oidc_app(name, slug, redirect_uris(kind, app_url), app_url)
        log(f"Client-ID {app['client_id']} – das Geheimnis wird verschlüsselt gespeichert")
        return {"slug": slug, "provider_pk": app["provider_pk"], "client_id": app["client_id"], "app_url": app_url,
                "secret_enc": security.encrypt(app["client_secret"])}
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
               nextcloud_occ: Optional[Callable[[str, dict], str]] = None, mailcow=None, pangolin=None,
               pve=None, zammad=None) -> None:
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
    elif client.target_kind == "pve" and pve is not None and client.target_ref:
        log(f"Proxmox: OpenID-Realm „{client.target_ref}“ entfernen (angelegte Benutzer bleiben bestehen) ...")
        try:
            pve.delete(f"access/domains/{client.target_ref}")
        except PveError as exc:
            if exc.status != 404 and "does not exist" not in str(exc):
                raise
            log("Proxmox: Realm war bereits entfernt")
    elif client.target_kind == "zammad" and zammad is not None:
        from . import zammad as zlib
        log("Zammad: Anmeldung über OpenID Connect abschalten (verknüpfte Konten bleiben bestehen) ...")
        try:
            zlib.disable_oidc(zammad)
        except ZammadError as exc:
            log(f"Zammad: konnte nicht abgeschaltet werden ({exc}) – bitte unter Einstellungen → Sicherheit → "
                "Drittanbieter-Anwendungen prüfen")
    log("authentik: Anwendung entfernen ...")
    au.delete_oidc_app(client.slug, client.provider_pk)


def target_of(db, kind: str, target_id: int):
    if kind == "servermanager":
        from .sso_login import TARGET
        return TARGET
    model = TARGET_MODELS.get(kind)
    return db.get(model, target_id) if model else None
