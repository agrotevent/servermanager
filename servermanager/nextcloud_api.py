"""Nextcloud OCS API: server info (app serverinfo) and user/group provisioning.

Authentication with an administrator account and an app password (Persönliche Einstellungen → Sicherheit →
Neues App-Passwort). All requests carry ``OCS-APIRequest: true`` and ask for JSON; the v2 endpoints answer with
real HTTP status codes and ``{"ocs": {"meta": {...}, "data": ...}}``.
"""
from __future__ import annotations

import re
from typing import Any, Optional
from urllib.parse import quote, urlsplit

import requests

from . import tlspin

UID_RE = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")
GROUP_RE = re.compile(r"^[A-Za-z0-9 ._@-]{1,64}$")
QUOTA_RE = re.compile(r"^(none|default|\d+(\.\d+)?\s*(B|KB|MB|GB|TB)?)$", re.I)
PAGE = 500


class NextcloudError(Exception):
    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status


def normalize_url(url: str) -> str:
    url = (url or "").strip().rstrip("/")
    if not url:
        raise NextcloudError("Keine Adresse angegeben")
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise NextcloudError("Ungültige Adresse")
    if parts.username or parts.password:
        raise NextcloudError("Zugangsdaten gehören nicht in die Adresse")
    path = re.sub(r"/(index\.php|ocs/v[12]\.php)(/.*)?$", "", parts.path.rstrip("/"))
    return f"{parts.scheme}://{parts.netloc}{path}"


def check_uid(uid: str) -> str:
    uid = (uid or "").strip()
    if not UID_RE.match(uid):
        raise NextcloudError("Ungültige Benutzer-ID (Buchstaben, Ziffern, . _ @ -)")
    return uid


def check_group(gid: str) -> str:
    gid = (gid or "").strip()
    if not GROUP_RE.match(gid):
        raise NextcloudError(f"Ungültiger Gruppenname „{gid}“")
    return gid


def check_quota(quota: str) -> str:
    quota = (quota or "").strip()
    if quota and not QUOTA_RE.match(quota):
        raise NextcloudError("Quota z. B. 10 GB, none (unbegrenzt) oder default")
    return quota


class Nextcloud:
    def __init__(self, url: str, username: str, password: str, fingerprint: str = "", verify_ca: bool = False,
                 timeout: int = 20):
        self.base = normalize_url(url)
        if not username or not password:
            raise NextcloudError("Benutzer und App-Passwort fehlen")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.auth = (username, password)
        self.session.headers.update({"OCS-APIRequest": "true", "Accept": "application/json"})
        self.session.verify = verify_ca
        if fingerprint and self.base.startswith("https://"):
            try:
                adapter = tlspin.PinnedAdapter(fingerprint)
            except tlspin.PinError as exc:
                raise NextcloudError(str(exc)) from exc
            self.session.verify = False
            self.session.mount(f"https://{urlsplit(self.base).netloc}/", adapter)

    # ------------------------------------------------------------------ raw
    def request(self, method: str, path: str, data: Optional[dict] = None, params: Optional[dict] = None) -> Any:
        url = f"{self.base}/ocs/v2.php/{path.lstrip('/')}"
        try:
            r = self.session.request(method, url, data=data, params={"format": "json", **(params or {})},
                                     timeout=self.timeout, allow_redirects=False)
        except requests.exceptions.SSLError as exc:
            raise NextcloudError(tlspin.tls_message(self.base, exc)) from exc
        except requests.RequestException as exc:
            raise NextcloudError(f"Nextcloud nicht erreichbar ({self.base}): {exc}") from exc
        if r.status_code == 401:
            raise NextcloudError("Anmeldung fehlgeschlagen – Benutzer und App-Passwort prüfen", 401)
        if r.status_code in (301, 302, 303, 307, 308):
            raise NextcloudError(f"Nextcloud leitet um (HTTP {r.status_code} → {r.headers.get('Location', '?')}) – "
                                 "Adresse prüfen", r.status_code)
        try:
            j = r.json()
        except ValueError:
            raise NextcloudError(f"Nextcloud: keine gültige Antwort (HTTP {r.status_code}) – ist das die Adresse "
                                 "der Nextcloud?", r.status_code) from None
        ocs = j.get("ocs") if isinstance(j, dict) else None
        meta = (ocs or {}).get("meta") or {}
        if r.status_code >= 400 or meta.get("status") == "failure":
            msg = meta.get("message") or r.reason or f"HTTP {r.status_code}"
            if r.status_code == 403 or meta.get("statuscode") == 403:
                msg = f"keine Berechtigung ({msg}) – der Benutzer braucht Administratorrechte"
            elif r.status_code == 404 and "serverinfo" in path:
                msg = "App „Monitoring“ (serverinfo) ist nicht aktiviert"
            raise NextcloudError(f"Nextcloud: {msg}", r.status_code)
        return (ocs or {}).get("data")

    # ------------------------------------------------------------------ reads
    def serverinfo(self) -> dict:
        return self.request("GET", "apps/serverinfo/api/v1/info", params={"skipApps": "false",
                                                                           "skipUpdate": "false"}) or {}

    def users(self) -> list[dict]:
        """All users with details (id, displayname, email, enabled, groups, quota, lastLogin, backend)."""
        out: list[dict] = []
        offset = 0
        while True:
            data = self.request("GET", "cloud/users/details", params={"limit": PAGE, "offset": offset}) or {}
            batch = data.get("users") or {}
            items = batch.values() if isinstance(batch, dict) else batch
            rows = [u for u in items if isinstance(u, dict) and u.get("id")]
            out.extend(rows)
            if len(rows) < PAGE or len(out) > 20000:
                break
            offset += PAGE
        return sorted(out, key=lambda u: str(u.get("id")).lower())

    def groups(self) -> list[dict]:
        """[{id, displayname, usercount, disabled}]"""
        try:
            data = self.request("GET", "cloud/groups/details") or {}
            rows = [x for x in data.get("groups") or [] if isinstance(x, dict)]
        except NextcloudError as exc:
            if exc.status != 404:
                raise
            data = self.request("GET", "cloud/groups") or {}
            rows = [{"id": x, "displayname": x} for x in data.get("groups") or []]
        return sorted(rows, key=lambda x: str(x.get("id")).lower())

    def user(self, uid: str) -> dict:
        return self.request("GET", self._user(uid)) or {}

    # ------------------------------------------------------------------ writes
    def _user(self, uid: str) -> str:
        return f"cloud/users/{quote(check_uid(uid), safe='')}"

    def add_user(self, uid: str, password: str, display: str = "", email: str = "",
                 groups: Optional[list[str]] = None, quota: str = "") -> None:
        data: dict = {"userid": check_uid(uid), "password": password}
        if display:
            data["displayName"] = display[:100]
        if email:
            data["email"] = email
        if groups:
            data["groups[]"] = [check_group(x) for x in groups]
        if quota:
            data["quota"] = check_quota(quota)
        self.request("POST", "cloud/users", data)

    def set_enabled(self, uid: str, enabled: bool) -> None:
        self.request("PUT", f"{self._user(uid)}/{'enable' if enabled else 'disable'}")

    def delete_user(self, uid: str) -> None:
        self.request("DELETE", self._user(uid))

    def edit_user(self, uid: str, key: str, value: str) -> None:
        if key not in ("displayname", "email", "quota", "password"):
            raise NextcloudError("Unbekanntes Feld")
        if key == "quota":
            value = check_quota(value)
        self.request("PUT", self._user(uid), {"key": key, "value": value})

    def add_to_group(self, uid: str, gid: str) -> None:
        self.request("POST", f"{self._user(uid)}/groups", {"groupid": check_group(gid)})

    def remove_from_group(self, uid: str, gid: str) -> None:
        self.request("DELETE", f"{self._user(uid)}/groups", {"groupid": check_group(gid)})

    def add_group(self, gid: str) -> None:
        self.request("POST", "cloud/groups", {"groupid": check_group(gid)})


# ----------------------------------------------------------------------------- helpers
def quota_info(user: dict) -> dict:
    """{used, total, pct, label} of a user's files quota (total 0 = unbegrenzt)."""
    q = user.get("quota") or {}
    if not isinstance(q, dict):
        return {"used": 0, "total": 0, "pct": 0, "label": ""}
    used = int(q.get("used") or 0)
    raw = q.get("quota")
    total = int(raw) if isinstance(raw, (int, float)) and raw > 0 else 0
    return {"used": used, "total": total, "pct": round(used * 100 / total) if total else 0,
            "label": str(raw) if isinstance(raw, str) else ""}


def quota_text(user: dict) -> str:
    """The quota as Nextcloud accepts it again (``10 GB``, ``none``, ``default``)."""
    q = user.get("quota") or {}
    raw = q.get("quota") if isinstance(q, dict) else None
    if isinstance(raw, str):
        return raw
    if isinstance(raw, (int, float)) and raw > 0:
        raw = int(raw)
        for unit, size in (("TB", 1024 ** 4), ("GB", 1024 ** 3), ("MB", 1024 ** 2)):
            if raw >= size and raw % size == 0:
                return f"{raw // size} {unit}"
        return f"{raw} B"
    if isinstance(raw, (int, float)) and raw == -3:
        return "none"
    return ""


def summary(info: dict) -> dict:
    """The parts of the serverinfo answer the overview shows."""
    nc = info.get("nextcloud") or {}
    system = nc.get("system") or {}
    storage = nc.get("storage") or {}
    shares = nc.get("shares") or {}
    server = info.get("server") or {}
    apps = system.get("apps") or {}
    update = system.get("update") or {}
    active = info.get("activeUsers") or {}
    return {
        "version": str(system.get("version") or ""),
        "freespace": int(system.get("freespace") or 0) if str(system.get("freespace") or "").isdigit() else 0,
        "users": int(storage.get("num_users") or 0), "files": int(storage.get("num_files") or 0),
        "shares": int(shares.get("num_shares") or 0),
        "active_5m": int(active.get("last5minutes") or 0), "active_1h": int(active.get("last1hour") or 0),
        "active_24h": int(active.get("last24hours") or 0),
        "apps_installed": int(apps.get("num_installed") or 0),
        "app_updates": sorted((apps.get("app_updates") or {}).keys()) if isinstance(apps.get("app_updates"), dict)
        else [],
        "core_update": str(update.get("available_version") or "") if update.get("available") else "",
        "php": str((server.get("php") or {}).get("version") or ""),
        "database": " ".join(str(x) for x in ((server.get("database") or {}).get("type"),
                                             (server.get("database") or {}).get("version")) if x),
        "webserver": str(server.get("webserver") or ""),
    }
