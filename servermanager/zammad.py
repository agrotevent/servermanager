"""Zammad REST API (token auth): tickets, articles, tags, webhook + trigger for updates back."""
from __future__ import annotations

import hashlib
import hmac
from typing import Any, Optional
from urllib.parse import urlsplit

import requests

from . import tlspin

TAG = "servermanager"
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
    return bool(secret) and bool(header) and hmac.compare_digest(signature(secret, body), header.strip())


class Zammad:
    def __init__(self, url: str, token: str, fingerprint: str = "", verify_ca: bool = True, timeout: int = 20):
        self.base = normalize_url(url)
        token = (token or "").strip()
        if not token:
            raise ZammadError("Kein API-Token hinterlegt")
        self.timeout = timeout
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

    # ------------------------------------------------------------------ raw
    def request(self, method: str, path: str, body: Optional[dict] = None, params: Optional[dict] = None) -> Any:
        url = f"{self.base}/api/v1/{path.lstrip('/')}"
        try:
            r = self.session.request(method, url, json=body, params=params, timeout=self.timeout)
        except requests.exceptions.SSLError as exc:
            raise ZammadError(f"TLS-Fehler bei {self.base}: {exc}") from exc
        except requests.RequestException as exc:
            raise ZammadError(f"Zammad nicht erreichbar ({self.base}): {exc}") from exc
        try:
            j = r.json() if r.content else None
        except ValueError:
            j = None
        if r.status_code >= 400:
            msg = (j.get("error_human") or j.get("error")) if isinstance(j, dict) else ""
            msg = msg or r.reason or f"HTTP {r.status_code}"
            if r.status_code == 401:
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
