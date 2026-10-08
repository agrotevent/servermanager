"""Zammad REST API (token auth): tickets, articles, tags, webhook + trigger for updates back."""
from __future__ import annotations

import copy
import hashlib
import hmac
import re
from typing import Any, Optional
from urllib.parse import urlsplit

import requests

from . import tlspin

TAG = "servermanager"
CTI_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
WEBHOOK_NAME = "Servermanager"
TRIGGER_NAME = "Servermanager: Änderungen zurückmelden"
# Zabbix severity -> Zammad default priorities
PRIORITY = {0: "1 low", 1: "1 low", 2: "2 normal", 3: "2 normal", 4: "3 high", 5: "3 high"}


class ZammadError(Exception):
    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status


def normalize_url(url: str) -> str:
    url = (url or "").strip().rstrip("/")
    if not url:
        raise ZammadError("Keine Adresse angegeben")
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ZammadError("Ungültige Adresse")
    if parts.username or parts.password:
        raise ZammadError("Zugangsdaten gehören nicht in die Adresse")
    path = parts.path.rstrip("/")
    if path.endswith("/api/v1"):
        path = path[:-7]
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://{parts.hostname}{port}{path}"


def signature(secret: str, body: bytes) -> str:
    """Value of the X-Hub-Signature header Zammad sends with a signed webhook."""
    return "sha1=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha1).hexdigest()


def signature_ok(secret: str, body: bytes, header: str) -> bool:
    if not secret or not header:
        return False
    return hmac.compare_digest(signature(secret, body).encode(), header.strip().encode("utf-8", "replace"))


class Zammad:
    def __init__(self, url: str, token: str, fingerprint: str = "", verify_ca: bool = True, timeout: int = 20):
        self.base = normalize_url(url)
        token = (token or "").strip()
        if not token:
            raise ZammadError("Kein API-Token hinterlegt")
        self.timeout = timeout
        self.on_behalf_of = ""   # Zammad user id: requests run as this user (header X-On-Behalf-Of)
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.verify = verify_ca
        self.session.headers["Authorization"] = f"Token token={token}"
        self.session.headers["Accept"] = "application/json"
        if fingerprint and self.base.startswith("https://"):
            try:
                adapter = tlspin.PinnedAdapter(fingerprint)
            except tlspin.PinError as exc:
                raise ZammadError(str(exc)) from exc
            self.session.verify = False
            parts = urlsplit(self.base)
            self.session.mount(f"https://{parts.netloc}/", adapter)

    @property
    def web_url(self) -> str:
        return self.base

    def ticket_url(self, ticket_id: Any) -> str:
        return f"{self.base}/#ticket/zoom/{ticket_id}"

    def as_user(self, zammad_user_id: int) -> "Zammad":
        """Same connection, but Zammad carries out each request as this user, with that user's permissions.
        The API token needs the permission admin.user for this."""
        other = copy.copy(self)
        other.on_behalf_of = str(int(zammad_user_id))
        return other

    # ------------------------------------------------------------------ raw
    def request(self, method: str, path: str, body: Optional[dict] = None, params: Optional[dict] = None) -> Any:
        url = f"{self.base}/api/v1/{path.lstrip('/')}"
        try:
            r = self.session.request(method, url, json=body, params=params, timeout=self.timeout,
                                     allow_redirects=False,
                                     headers={"X-On-Behalf-Of": self.on_behalf_of} if self.on_behalf_of else None)
        except requests.exceptions.SSLError as exc:
            raise ZammadError(tlspin.tls_message(self.base, exc)) from exc
        except requests.RequestException as exc:
            raise ZammadError(f"Zammad nicht erreichbar ({self.base}): {exc}") from exc
        try:
            j = r.json() if r.content else None
        except ValueError:
            j = None
        if r.status_code >= 400:
            msg = (j.get("error_human") or j.get("error")) if isinstance(j, dict) else ""
            msg = msg or r.reason or f"HTTP {r.status_code}"
            if self.on_behalf_of and r.status_code in (401, 403):
                msg = f"Keine Berechtigung im Namen des Zammad-Benutzers #{self.on_behalf_of} ({msg}) – dem Token " \
                      "fehlt admin.user oder dem Benutzer das Recht in Zammad (Agent in der Gruppe?)"
            elif r.status_code == 401:
                msg = f"Anmeldung fehlgeschlagen ({msg}) – API-Token prüfen (Profil → Token-Zugriff)"
            elif r.status_code == 403:
                msg = f"Keine Berechtigung ({msg}) – Rechte des Tokens prüfen (ticket.agent, für die Einrichtung " \
                      "zusätzlich admin.webhook und admin.trigger)"
            raise ZammadError(f"Zammad {method} {path}: {msg}", r.status_code)
        if j is None and r.status_code not in (200, 201, 204):
            raise ZammadError(f"Zammad: keine JSON-Antwort (HTTP {r.status_code}) – Adresse prüfen", r.status_code)
        return j

    # ------------------------------------------------------------------ reads
    def me(self) -> dict:
        return self.request("GET", "users/me") or {}

    def groups(self) -> list[dict]:
        return [g for g in (self.request("GET", "groups") or []) if g.get("active", True)]

    def states(self) -> dict[int, str]:
        return {int(s["id"]): s["name"] for s in (self.request("GET", "ticket_states") or [])}

    def ticket(self, ticket_id: int) -> dict:
        return self.request("GET", f"tickets/{int(ticket_id)}", params={"expand": "true"}) or {}

    def find_user(self, login: str = "", email: str = "") -> tuple[Optional[dict], str]:
        """Active Zammad user with exactly this login, otherwise this e-mail address: (user, "login"|"email")."""
        for value, field in ((login, "login"), (email, "email")):
            value = (value or "").strip()
            if not value:
                continue
            for u in self.request("GET", "users/search", params={"query": value, "limit": 10, "expand": "true"}) or []:
                if str(u.get(field) or "").lower() == value.lower() and u.get("active", True):
                    return u, field
        return None, ""

    def tickets_where(self, condition: dict, limit: int = 50) -> list[dict]:
        """Tickets matching a Zammad condition (database search, no Elasticsearch needed), newest change first;
        only those the (acting) user may read."""
        data = self.request("POST", "tickets/search", {"condition": condition, "limit": limit, "sort_by": "updated_at",
                                                       "order_by": "desc"}, params={"expand": "true"})
        if isinstance(data, dict):   # without expand: ids plus assets
            assets = (data.get("assets") or {}).get("Ticket") or {}
            return [assets.get(str(i)) or assets.get(i) for i in data.get("tickets") or []
                    if assets.get(str(i)) or assets.get(i)]
        return [t for t in data or [] if isinstance(t, dict)]

    def find_agent(self, email: str) -> Optional[int]:
        if not email:
            return None
        for u in self.request("GET", "users/search", params={"query": email, "limit": 5}) or []:
            if str(u.get("email", "")).lower() == email.lower() and u.get("active", True):
                return int(u["id"])
        return None

    # ------------------------------------------------------------------ writes
    def create_ticket(self, title: str, group: str, customer: str, body: str, priority: str = "2 normal",
                      tags: tuple[str, ...] = ()) -> dict:
        t = self.request("POST", "tickets", {
            "title": title[:250], "group": group, "customer_id": f"guess:{customer}", "priority": priority,
            "state": "new",
            "article": {"subject": title[:250], "body": body, "type": "note", "internal": False,
                        "content_type": "text/plain"}}) or {}
        if not t.get("id"):
            raise ZammadError("Zammad hat kein Ticket angelegt")
        for tag in (TAG,) + tuple(tags):
            try:
                self.request("POST", "tags/add", {"object": "Ticket", "o_id": t["id"], "item": tag})
            except ZammadError:
                pass
        return t

    def add_note(self, ticket_id: int, body: str, internal: bool = True, subject: str = "") -> dict:
        return self.request("POST", "ticket_articles", {
            "ticket_id": int(ticket_id), "subject": subject[:250], "body": body, "type": "note",
            "internal": internal, "content_type": "text/plain"}) or {}

    def update_ticket(self, ticket_id: int, **fields) -> dict:
        return self.request("PUT", f"tickets/{int(ticket_id)}", fields) or {}

    # ------------------------------------------------------------------ CTI (generic): call events
    def cti(self, token: str, data: dict) -> None:
        """Call event to Zammad's generic CTI endpoint (token from Admin → Integrationen → CTI (generisch))."""
        if not CTI_TOKEN_RE.match(token or ""):
            raise ZammadError("Ungültiges CTI-Token")
        url = f"{self.base}/api/v1/cti/{token}"
        try:
            r = self.session.post(url, data=data, headers={"Authorization": None}, timeout=min(self.timeout, 8),
                                  allow_redirects=False)
        except requests.exceptions.SSLError as exc:
            raise ZammadError(tlspin.tls_message(self.base, exc)) from exc
        except requests.RequestException as exc:
            raise ZammadError(f"Zammad nicht erreichbar ({self.base}): {exc}") from exc
        if r.status_code >= 400:
            hint = " – CTI (generisch) in Zammad aktivieren und Token prüfen" if r.status_code in (401, 404) else ""
            raise ZammadError(f"Zammad CTI: HTTP {r.status_code}{hint}", r.status_code)

    # ------------------------------------------------------------------ webhook + trigger
    def setup_webhook(self, endpoint: str, secret: str, verify_ssl: bool = True) -> dict:
        """Webhook to the servermanager and a trigger for tickets tagged 'servermanager' (idempotent)."""
        hook = {"name": WEBHOOK_NAME, "endpoint": endpoint, "signature_token": secret, "ssl_verify": verify_ssl,
                "active": True, "note": "Angelegt vom Servermanager"}
        existing = next((w for w in self.request("GET", "webhooks") or [] if w.get("name") == WEBHOOK_NAME), None)
        if existing:
            webhook_id = self.request("PUT", f"webhooks/{existing['id']}", hook)["id"]
        else:
            webhook_id = self.request("POST", "webhooks", hook)["id"]
        trigger = {"name": TRIGGER_NAME, "active": True, "activator": "action",
                   "execution_condition_mode": "selective",
                   "condition": {"ticket.tags": {"operator": "contains one", "value": TAG},
                                 "ticket.action": {"operator": "is", "value": "update"}},
                   "perform": {"notification.webhook": {"webhook_id": webhook_id}},
                   "note": "Angelegt vom Servermanager: Änderungen an Servermanager-Tickets zurückmelden"}
        existing = next((t for t in self.request("GET", "triggers") or [] if t.get("name") == TRIGGER_NAME), None)
        if existing:
            trigger_id = self.request("PUT", f"triggers/{existing['id']}", trigger)["id"]
        else:
            trigger_id = self.request("POST", "triggers", trigger)["id"]
        return {"webhook_id": webhook_id, "trigger_id": trigger_id}


# ----------------------------------------------------------------------------- SSO (OpenID Connect)
OIDC_SETTING = "auth_openid_connect"
OIDC_CREDENTIALS = "auth_openid_connect_credentials"
AUTO_LINK_SETTING = "auth_third_party_auto_link_at_inital_login"   # sic, Zammad's spelling


def _setting_value(row: Optional[dict]) -> Any:
    return ((row or {}).get("state_current") or {}).get("value")


def oidc_settings(z: Zammad) -> dict:
    """The settings the OpenID Connect login needs (only those the token may read are listed by Zammad)."""
    try:
        rows = [r for r in z.request("GET", "settings") or [] if isinstance(r, dict)]
    except ZammadError as exc:
        if exc.status == 403:
            raise ZammadError("Für die Anmeldung über authentik braucht das API-Token zusätzlich die Berechtigung "
                              "admin.security (Profil → Token-Zugriff)", 403) from exc
        raise
    by = {r.get("name"): r for r in rows}
    if OIDC_SETTING not in by:
        if "auth_saml" in by:
            raise ZammadError("Diese Zammad-Version kennt die Anmeldung über OpenID Connect noch nicht – bitte "
                              "Zammad aktualisieren")
        raise ZammadError("Für die Anmeldung über authentik braucht das API-Token zusätzlich die Berechtigung "
                          "admin.security (Profil → Token-Zugriff)", 403)
    return by


def callback_url(by: dict, fallback_base: str) -> str:
    """Zammad builds its redirect URI from the settings http_type and fqdn."""
    fqdn, http_type = _setting_value(by.get("fqdn")), _setting_value(by.get("http_type"))
    if fqdn and http_type in ("http", "https"):
        return f"{http_type}://{fqdn}/auth/openid_connect/callback"
    return f"{fallback_base.rstrip('/')}/auth/openid_connect/callback"


def set_setting(z: Zammad, by: dict, name: str, value: Any) -> None:
    row = by.get(name)
    if row is None or not row.get("id"):
        raise ZammadError(f"Zammad-Einstellung {name} nicht gefunden")
    z.request("PUT", f"settings/{int(row['id'])}", {"id": row["id"], "name": name, "state_current": {"value": value}})


def enable_oidc(z: Zammad, by: dict, client_id: str, issuer: str, display_name: str, auto_link: bool) -> None:
    """Public client with PKCE (Zammad sends no client secret); the user is matched by login (= authentik user
    name, the ``sub`` of the provider) or e-mail address."""
    set_setting(z, by, OIDC_CREDENTIALS, {"display_name": display_name[:50], "identifier": client_id,
                                          "issuer": issuer, "uid_field": "sub", "scope": "openid email profile",
                                          "pkce": True})
    set_setting(z, by, OIDC_SETTING, True)
    if auto_link and AUTO_LINK_SETTING in by:
        set_setting(z, by, AUTO_LINK_SETTING, True)


def disable_oidc(z: Zammad) -> None:
    by = oidc_settings(z)
    set_setting(z, by, OIDC_SETTING, False)
    set_setting(z, by, OIDC_CREDENTIALS, {})

