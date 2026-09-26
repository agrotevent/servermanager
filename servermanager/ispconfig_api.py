"""ISPConfig 3 remote API (JSON: /remote/json.php?<function>)."""
from __future__ import annotations

import re
import secrets
import string
from typing import Any, Optional
from urllib.parse import urlsplit

import requests

from . import tlspin

# function groups the servermanager's remote user needs (ISPConfig grants them per group)
FUNCTIONS = ["server_get", "server_get_all", "server_get_app_version", "client_get", "client_add",
             "client_get_by_groupid", "sites_web_domain_get", "sites_web_domain_update", "sites_database_get",
             "mail_domain_get", "mail_user_get", "mail_user_add", "mail_user_update", "mail_user_delete",
             "dns_zone_get"]
EMAIL_RE = re.compile(r"^[a-z0-9._%+-]{1,64}@[a-z0-9.-]{1,253}\.[a-z]{2,}$")
USERNAME_RE = re.compile(r"^[a-z0-9._-]{2,64}$")


class IspError(Exception):
    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status


def normalize_url(url: str) -> str:
    url = (url or "").strip().rstrip("/")
    if not url:
        raise IspError("Keine API-Adresse angegeben")
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise IspError("Ungültige API-Adresse")
    if parts.username or parts.password:
        raise IspError("Zugangsdaten gehören nicht in die Adresse")
    path = parts.path.rstrip("/")
    if not path.endswith("json.php"):
        path = (path if path.endswith("/remote") else path + "/remote") + "/json.php"
    port = f":{parts.port}" if parts.port else ":8080"
    return f"{parts.scheme}://{parts.hostname}{port}{path}"


def yes(v: Any) -> bool:
    return str(v).lower() in ("y", "1", "true")


class IspConfig:
    def __init__(self, url: str, username: str, password: str, fingerprint: str = "", verify_ca: bool = False,
                 timeout: int = 30):
        self.url = normalize_url(url)
        if not username or not password:
            raise IspError("Remote-Benutzer und Passwort fehlen")
        self.username, self.password = username, password
        self.timeout = timeout
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.verify = verify_ca
        if fingerprint and self.url.startswith("https://"):
            try:
                adapter = tlspin.PinnedAdapter(fingerprint)
            except tlspin.PinError as exc:
                raise IspError(str(exc)) from exc
            self.session.verify = False
            parts = urlsplit(self.url)
            self.session.mount(f"https://{parts.netloc}/", adapter)
        self.sid: Optional[str] = None

    def __enter__(self) -> "IspConfig":
        self.login()
        return self

    def __exit__(self, *exc) -> None:
        self.logout()

    # ------------------------------------------------------------------ raw
    def _post(self, function: str, body: dict) -> Any:
        try:
            r = self.session.post(f"{self.url}?{function}", json=body, timeout=self.timeout)
        except requests.exceptions.SSLError as exc:
            raise IspError(f"TLS-Fehler bei {self.url}: {exc}") from exc
        except requests.RequestException as exc:
            raise IspError(f"ISPConfig-API nicht erreichbar ({self.url}): {exc}") from exc
        try:
            j = r.json()
        except ValueError:
            raise IspError(f"ISPConfig: keine JSON-Antwort (HTTP {r.status_code}) – Adresse und Port der "
                           "ISPConfig-Oberfläche prüfen", r.status_code) from None
        if not isinstance(j, dict) or j.get("code") != "ok":
            msg = (j.get("message") if isinstance(j, dict) else "") or f"HTTP {r.status_code}"
            if function == "login":
                msg = (f"Anmeldung fehlgeschlagen ({msg}) – Remote-Benutzer, Passwort und erlaubte IP-Adressen "
                       "prüfen (System → Remote-Benutzer)")
            elif "permission" in msg.lower():
                msg = f"{msg} – dem Remote-Benutzer fehlt die Funktion {function}"
            raise IspError(f"ISPConfig {function}: {msg}", r.status_code)
        return j.get("response")

    def login(self) -> str:
        self.sid = str(self._post("login", {"username": self.username, "password": self.password}))
        return self.sid

    def logout(self) -> None:
        if self.sid:
            try:
                self._post("logout", {"session_id": self.sid})
            except IspError:
                pass
            self.sid = None

    def call(self, function: str, **params) -> Any:
        if not self.sid:
            self.login()
        return self._post(function, {"session_id": self.sid, **params})

    def _all(self, function: str, **params) -> list[dict]:
        res = self.call(function, primary_id=-1, **params)
        if isinstance(res, dict):
            res = [res] if res else []
        return [r for r in (res or []) if isinstance(r, dict)]

    # ------------------------------------------------------------------ reads
    def version(self) -> str:
        try:
            v = self.call("server_get_app_version", server_id=0)
        except IspError:
            return ""
        if isinstance(v, dict):
            return str(v.get("ispc_app_version") or "")
        return str(v or "")

    def servers(self) -> list[dict]:
        try:
            res = self.call("server_get_all")
        except IspError:
            return []
        return [r for r in (res or []) if isinstance(r, dict)]

    def clients(self) -> list[dict]:
        return self._all("client_get")

    def websites(self) -> list[dict]:
        return [w for w in self._all("sites_web_domain_get") if w.get("type") in (None, "", "vhost")]

    def databases(self) -> list[dict]:
        return self._all("sites_database_get")

    def mail_domains(self) -> list[dict]:
        return self._all("mail_domain_get")

    def mailboxes(self) -> list[dict]:
        return self._all("mail_user_get")

    def dns_zones(self) -> list[dict]:
        return self._all("dns_zone_get")

    def client_of_group(self, sys_groupid: Any) -> int:
        """Client id that owns records of a system group (0 = admin)."""
        try:
            res = self.call("client_get_by_groupid", group_id=int(sys_groupid or 0))
        except (IspError, ValueError):
            return 0
        if isinstance(res, dict):
            return int(res.get("client_id") or 0)
        return 0

    # ------------------------------------------------------------------ writes
    def set_website_active(self, domain: dict, active: bool) -> Any:
        client_id = self.client_of_group(domain.get("sys_groupid"))
        return self.call("sites_web_domain_update", client_id=client_id, primary_id=int(domain["domain_id"]),
                         params={"active": "y" if active else "n"})

    def add_mailbox(self, domain: dict, local: str, name: str, password: str, quota_mb: int) -> int:
        local = (local or "").strip().lower()
        if not re.match(r"^[a-z0-9._%+-]{1,64}$", local):
            raise IspError("Ungültiger Name vor dem @")
        email = f"{local}@{domain['domain']}"
        params = {"server_id": int(domain.get("server_id") or 1), "email": email, "login": email,
                  "password": password, "name": (name or "")[:100], "uid": 5000, "gid": 5000,
                  "maildir": f"/var/vmail/{domain['domain']}/{local}", "maildir_format": "maildir",
                  "homedir": "/var/vmail", "quota": max(0, int(quota_mb)) * 1024 * 1024, "cc": "",
                  "forward_in_lda": "y", "sender_cc": "", "move_junk": "y", "autoresponder": "n",
                  "autoresponder_text": "", "autoresponder_subject": "Out of office reply", "custom_mailfilter": "",
                  "postfix": "y", "access": "y", "disableimap": "n", "disablepop3": "n", "disabledeliver": "n",
                  "disablesmtp": "n", "disablesieve": "n", "disablelda": "n", "disabledoveadm": "n",
                  "purge_trash_days": 0, "purge_junk_days": 0}
        client_id = self.client_of_group(domain.get("sys_groupid"))
        return int(self.call("mail_user_add", client_id=client_id, params=params) or 0)

    def set_mailbox_password(self, box: dict, password: str) -> Any:
        client_id = self.client_of_group(box.get("sys_groupid"))
        return self.call("mail_user_update", client_id=client_id, primary_id=int(box["mailuser_id"]),
                         params={"password": password})

    def delete_mailbox(self, mailuser_id: int) -> Any:
        return self.call("mail_user_delete", primary_id=int(mailuser_id))

    def add_client(self, company: str, contact: str, email: str, username: str, password: str,
                   language: str = "de") -> int:
        if not EMAIL_RE.match((email or "").lower()):
            raise IspError("Ungültige E-Mail-Adresse")
        if not USERNAME_RE.match(username or ""):
            raise IspError("Benutzername: 2–64 Zeichen aus a–z, 0–9, . _ -")
        if not (contact or "").strip():
            raise IspError("Ansprechpartner angeben")
        params = {"company_name": (company or "")[:64], "contact_name": contact.strip()[:64], "email": email.lower(),
                  "username": username, "password": password, "language": language, "usertheme": "default",
                  "country": "DE", "customer_no": "", "template_master": 0, "template_additional": "",
                  "created_at": 0, "locked": "n", "canceled": "n", "web_php_options": "no,fast-cgi,php-fpm",
                  "ssh_chroot": "no,jailkit", "limit_web_domain": -1, "limit_mailbox": -1, "limit_database": -1,
                  "limit_client": 0, "default_mailserver": 1, "default_webserver": 1, "default_dbserver": 1,
                  "default_dnsserver": 1}
        return int(self.call("client_add", reseller_id=0, params=params) or 0)


def random_password(n: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))
