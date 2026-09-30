"""Client for the Mailcow API (https://<mailcow>/api/v1, header X-API-Key)."""
from __future__ import annotations

import re
from typing import Any, Optional
from urllib.parse import urlsplit

import requests

from . import tlspin

LOCAL_RE = re.compile(r"^[a-z0-9][a-z0-9._+-]{0,63}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$")


class MailcowError(Exception):
    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status


def base_url(url: str) -> str:
    url = (url or "").strip().rstrip("/")
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.hostname or parts.username:
        raise MailcowError("Ungültige Mailcow-Adresse")
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://{parts.hostname}{port}"


class Mailcow:
    def __init__(self, url: str, api_key: str, fingerprint: str = "", verify_ca: bool = True, timeout: int = 20):
        self.base = base_url(url)
        if not api_key:
            raise MailcowError("Kein API-Schlüssel hinterlegt")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers.update({"X-API-Key": api_key, "Accept": "application/json"})
        if fingerprint and self.base.startswith("https://"):
            try:
                adapter = tlspin.PinnedAdapter(fingerprint)
            except tlspin.PinError as exc:
                raise MailcowError(str(exc)) from exc
            self.session.verify = False
            self.session.mount(self.base + "/", adapter)
        else:
            self.session.verify = verify_ca

    def request(self, method: str, path: str, body: Any = None) -> Any:
        url = f"{self.base}/api/v1/{path.lstrip('/')}"
        try:
            r = self.session.request(method, url, json=body, timeout=self.timeout, allow_redirects=False)
        except requests.exceptions.SSLError as exc:
            raise MailcowError(f"TLS-Fehler bei {self.base}: {exc}") from exc
        except requests.RequestException as exc:
            raise MailcowError(f"Mailcow nicht erreichbar ({self.base}): {exc}") from exc
        if r.status_code in (401, 403):
            raise MailcowError("Mailcow: Zugriff verweigert (API-Schlüssel oder erlaubte IPs prüfen)", r.status_code)
        try:
            data = r.json()
        except ValueError:
            raise MailcowError(f"Ungültige Antwort der Mailcow-API ({r.status_code})", r.status_code) from None
        if r.status_code >= 400:
            raise MailcowError(f"Mailcow-Fehler {r.status_code}: {_msg(data)}", r.status_code)
        if method == "POST":
            items = data if isinstance(data, list) else [data]
            errs = [i for i in items if isinstance(i, dict) and i.get("type") in ("danger", "error")]
            if errs:
                raise MailcowError("Mailcow: " + "; ".join(_msg(e) for e in errs))
        return data

    # ------------------------------------------------------------------ read
    def version(self) -> str:
        data = self.request("GET", "get/status/version") or {}
        return data.get("version", "") if isinstance(data, dict) else ""

    def domains(self) -> list[dict]:
        return _list(self.request("GET", "get/domain/all"))

    def mailboxes(self) -> list[dict]:
        return _list(self.request("GET", "get/mailbox/all"))

    def aliases(self) -> list[dict]:
        return _list(self.request("GET", "get/alias/all"))

    # ------------------------------------------------------------------ write
    def add_mailbox(self, local: str, domain: str, name: str, password: str, quota_mb: int = 3072,
                    force_pw_update: bool = False) -> str:
        local, domain = local.strip().lower(), domain.strip().lower()
        if not LOCAL_RE.match(local) or not DOMAIN_RE.match(domain):
            raise MailcowError("Ungültige Adresse")
        self.request("POST", "add/mailbox", {
            "local_part": local, "domain": domain, "name": name[:100], "quota": str(int(quota_mb)),
            "password": password, "password2": password, "active": "1",
            "force_pw_update": "1" if force_pw_update else "0", "tls_enforce_in": "0", "tls_enforce_out": "0"})
        return f"{local}@{domain}"

    def set_mailbox(self, address: str, **attr) -> None:
        self.request("POST", "edit/mailbox", {"items": [address], "attr": {k: str(v) for k, v in attr.items()}})

    def set_password(self, address: str, password: str) -> None:
        self.set_mailbox(address, password=password, password2=password)

    def delete_mailbox(self, address: str) -> None:
        self.request("POST", "delete/mailbox", [address])

    def add_alias(self, address: str, goto: str) -> None:
        self.request("POST", "add/alias", {"address": address.strip().lower(), "goto": goto.strip().lower(),
                                           "active": "1"})

    def delete_alias(self, alias_id: Any) -> None:
        self.request("POST", "delete/alias", [str(alias_id)])

    # ------------------------------------------------------------------ SSO (Mailcow >= 2025-03)
    def identity_provider(self) -> Optional[dict]:
        try:
            data = self.request("GET", "get/identity-provider")
        except MailcowError as exc:
            if exc.status == 404:
                return None
            raise
        return data if isinstance(data, dict) else None

    def set_identity_provider(self, attr: dict) -> None:
        self.request("POST", "edit/identity-provider", {"attr": attr})


def _list(data: Any) -> list[dict]:
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    if isinstance(data, dict) and data:
        return [data]
    return []


def _msg(item: Any) -> str:
    if isinstance(item, dict):
        m = item.get("msg")
        if isinstance(m, list):
            return " ".join(str(x) for x in m)
        return str(m or item.get("message") or item)
    return str(item)[:300]
