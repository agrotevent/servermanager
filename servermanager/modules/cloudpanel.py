"""CloudPanel (v2): sites, databases, users and Let's Encrypt via its command line clpctl over SSH.

CloudPanel has no API; everything runs as root through ``clpctl``. The lists come read-only from CloudPanel's
own SQLite database (without password and MFA columns). CloudPanel has no single sign-on either: its web
interface is protected with authentik by publishing it through Pangolin with Pangolin authentication.
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Optional

from ..models import LEVEL_FULL, System, utcnow
from .base import Action, Module, parse_kv, run_module_script

DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
SITE_USER_RE = re.compile(r"^[a-z][a-z0-9-]{2,31}$")
USER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
DB_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
EMAIL_RE = re.compile(r"^[^@\s'\"]+@[^@\s'\"]+\.[^@\s'\"]+$")
NAME_RE = re.compile(r"^[^'\"`$\\\n]{1,64}$")
VHOST_RE = re.compile(r"^[A-Za-z0-9 ._()-]{1,64}$")
PROXY_RE = re.compile(r"^https?://[A-Za-z0-9.-]+(:\d{1,5})?(/[A-Za-z0-9._~/-]*)?$")
SITE_TYPES = {"php": "PHP", "static": "Statisch (HTML)", "nodejs": "Node.js", "python": "Python",
              "reverse-proxy": "Reverse-Proxy"}
PHP_VERSIONS = ("8.4", "8.3", "8.2", "8.1", "8.0", "7.4")
NODE_VERSIONS = ("22", "20", "18")
PYTHON_VERSIONS = ("3.12", "3.11", "3.10")
ROLES = {"user": "Benutzer (nur gewählte Sites)", "siteManager": "Site-Manager (alle Sites)", "admin": "Administrator"}


class CloudPanelModule(Module):
    key = "cloudpanel"
    label = "CloudPanel"
    description = "Sites, Datenbanken, Benutzer, Let's Encrypt (clpctl)"
    panel_template = "modules/cloudpanel.html"

    def build_actions(self) -> list[Action]:
        t = "cloudpanel.sh"
        return [
            Action("update", "CloudPanel aktualisieren", t, env={"SM_TASK": "update"}, group="Updates",
                   detached=True, timeout=3600, level=LEVEL_FULL, danger=True,
                   description="Führt clp-update aus (aktuelle CloudPanel-Version).",
                   confirm="CloudPanel jetzt aktualisieren?"),
            Action("cloudflare_ips", "Cloudflare-IPs aktualisieren", t, env={"SM_TASK": "cloudflare_ips"},
                   group="Wartung", description="clpctl cloudflare:update:ips (echte Besucher-IPs hinter Cloudflare)"),
        ]

    def detect(self, facts: dict) -> bool:
        return bool(facts.get("cloudpanel_version"))

    def panel(self, conn, system: System) -> dict:
        d = parse_status(cp_task(conn, system, "status", timeout=120))
        now = utcnow()
        for s in d["sites"]:
            until = (s.get("cert") or {}).get("until")
            s["days"] = (until - now).days if until else None
        d["expiring"] = [s for s in d["sites"] if s["days"] is not None and s["days"] < 21]
        d["no_cert"] = [s for s in d["sites"] if s["days"] is None]
        return d


def cp_task(conn, system: System, task: str, extra: Optional[dict] = None, timeout: int = 180) -> str:
    from . import get_module
    return run_module_script(conn, get_module("cloudpanel"), "cloudpanel.sh", dict(SM_TASK=task, **(extra or {})),
                             timeout=timeout)


def _cert_date(raw: str) -> Optional[datetime]:
    try:
        return datetime.strptime(" ".join(raw.split()), "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return None


def parse_status(text: str) -> dict:
    """Output of the status task -> version, sites (with PHP version, user, certificate), users, databases."""
    kv = parse_kv(text)
    data: dict = {}
    for line in text.splitlines():
        if line.startswith("__CLP__"):
            try:
                data = json.loads(line[len("__CLP__"):])
            except ValueError:
                data = {}
    certs = {}
    for line in kv.get("cert", []):
        domain, _, rest = line.partition("|")
        end, _, issuer = rest.partition("|")
        certs[domain] = {"until": _cert_date(end), "issuer": issuer.strip()}
    php = {r.get("id"): r.get("php_version") for r in data.get("php_settings") or [] if isinstance(r, dict)}
    sites = []
    for r in data.get("site") or []:
        if not isinstance(r, dict) or not r.get("domain_name"):
            continue
        d = str(r["domain_name"])
        sites.append({"id": r.get("id"), "domain": d, "type": str(r.get("type") or ""), "user": str(r.get("user") or ""),
                      "root": str(r.get("root_directory") or ""),
                      "php": str(php.get(r.get("php_settings_id")) or r.get("php_version") or ""),
                      "cert": certs.get(d)})
    if not data:   # no python3 on the host: sites from the nginx configuration only
        sites = [{"id": None, "domain": d, "type": "", "user": "", "root": "", "php": "", "cert": certs.get(d)}
                 for d in kv.get("site", [])]
    by_site = {s["id"]: s["domain"] for s in sites if s["id"] is not None}
    db_users: dict = {}
    for r in data.get("database_user") or []:
        if isinstance(r, dict):
            db_users.setdefault(r.get("database_id"), []).append(str(r.get("user_name") or ""))
    dbs = [{"name": str(r.get("name") or ""), "site": by_site.get(r.get("site_id"), ""),
            "users": db_users.get(r.get("id"), [])}
           for r in data.get("database") or [] if isinstance(r, dict) and r.get("name")]
    users = [{"name": str(r.get("user_name") or ""), "email": str(r.get("email") or ""),
              "first": str(r.get("first_name") or ""), "last": str(r.get("last_name") or ""),
              "role": str(r.get("role") or ""), "active": str(r.get("status") or "1") in ("1", "True", "true")}
             for r in data.get("user") or [] if isinstance(r, dict) and r.get("user_name")]
    return {"version": (kv.get("version") or [""])[0], "sites": sorted(sites, key=lambda s: s["domain"]),
            "databases": sorted(dbs, key=lambda x: x["name"]), "users": sorted(users, key=lambda u: u["name"].lower()),
            "full": bool(data)}


def _need(value: str, rx: re.Pattern, what: str) -> str:
    value = (value or "").strip()
    if not rx.match(value):
        raise ValueError(f"Ungültig: {what}")
    return value


def site_env(f: dict) -> dict:
    """Checked values of a new site (form) -> environment of the site_add task."""
    kind = f.get("type", "")
    if kind not in SITE_TYPES:
        raise ValueError("Ungültiger Site-Typ")
    env = {"SM_TYPE": kind, "SM_DOMAIN": _need(f.get("domain", "").lower(), DOMAIN_RE, "Domain"),
           "SM_SITE_USER": _need(f.get("site_user", ""), SITE_USER_RE, "Site-Benutzer (Kleinbuchstaben, Ziffern, -)")}
    if kind == "php":
        if f.get("php") not in PHP_VERSIONS:
            raise ValueError("PHP-Version wählen")
        env["SM_PHP"] = f["php"]
        env["SM_VHOST"] = _need(f.get("vhost") or "Generic", VHOST_RE, "Vhost-Vorlage")
    elif kind in ("nodejs", "python"):
        versions = NODE_VERSIONS if kind == "nodejs" else PYTHON_VERSIONS
        if f.get("runtime") not in versions:
            raise ValueError("Version wählen")
        env["SM_NODE" if kind == "nodejs" else "SM_PYTHON"] = f["runtime"]
        port = str(f.get("app_port") or "")
        if not port.isdigit() or not 1024 <= int(port) <= 65535:
            raise ValueError("App-Port 1024–65535 angeben")
        env["SM_APP_PORT"] = port
    elif kind == "reverse-proxy":
        env["SM_PROXY_URL"] = _need(f.get("proxy_url", ""), PROXY_RE, "Ziel-Adresse (http://host:port)")
    return env


def user_env(f: dict, sites: list[str], allow_admin: bool) -> dict:
    role = f.get("role", "")
    if role not in ROLES or (role == "admin" and not allow_admin):
        raise ValueError("Rolle wählen" if role not in ROLES else "Administratoren legen nur Administratoren an")
    env = {"SM_USER": _need(f.get("user", ""), USER_RE, "Benutzername"),
           "SM_EMAIL": _need(f.get("email", ""), EMAIL_RE, "E-Mail-Adresse"), "SM_ROLE": role,
           "SM_FIRST": _need(f.get("first") or f.get("user", ""), NAME_RE, "Vorname"),
           "SM_LAST": _need(f.get("last") or "-", NAME_RE, "Nachname")}
    if role == "user":
        chosen = [s for s in f.get("sites", []) if s in sites]
        if not chosen:
            raise ValueError("Mindestens eine Site wählen")
        env["SM_SITES"] = ",".join(chosen)
    return env
