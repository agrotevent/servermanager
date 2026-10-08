"""CloudPanel under Infrastruktur: sites, databases, users, Let's Encrypt (clpctl over SSH, synchronous)."""
from __future__ import annotations

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from sqlalchemy import select

from ... import access, inventory, security, settings
from ...authentik import AuthentikError
from ...core import audit
from ...models import KIND_SSO, LEVEL_FULL, LEVEL_OPERATE, LEVEL_VIEW, SsoServer, System
from ...modules.cloudpanel import (DB_RE, DOMAIN_RE, NODE_VERSIONS, PHP_VERSIONS, PYTHON_VERSIONS, ROLES, SITE_TYPES,
                                   USER_RE, cp_task, parse_status, site_env, user_env)
from ...ssh import SSHError
from ..auth import can, client_ip, get_system_or_403, login_required
from . import _integration as common

bp = Blueprint("cloudpanel", __name__, url_prefix="/cloudpanel")
TABS = {"sites": "Sites", "databases": "Datenbanken", "users": "Benutzer", "access": "Zugang & authentik"}
ACTIONS = {"site_add": LEVEL_FULL, "site_delete": LEVEL_FULL, "cert": LEVEL_OPERATE, "db_add": LEVEL_FULL,
           "user_add": LEVEL_FULL, "user_delete": LEVEL_FULL, "user_password": LEVEL_FULL,
           "user_mfa_off": LEVEL_FULL}
PANEL_PORT = 8443


def _systems() -> list[System]:
    return [s for s in access.accessible_systems(g.db, g.user) if s.has_type("cloudpanel")]


def _get(system_id: int, level: str) -> System:
    system = get_system_or_403(system_id, level)
    if not system.has_type("cloudpanel"):
        abort(404)
    return system


def _status(system: System) -> dict:
    with inventory.connect(system) as conn:
        return parse_status(cp_task(conn, system, "status", timeout=120))


def _run(system: System, task: str, env: dict) -> str:
    with inventory.connect(system) as conn:
        out = cp_task(conn, system, task, env, timeout=600)
    if "SM_OK" not in out:
        lines = [x for x in out.strip().splitlines() if x.strip()]
        raise ValueError(lines[-1][:300] if lines else "CloudPanel meldet keinen Erfolg")
    return out


@bp.get("/")
@login_required
def index():
    items = _systems()
    if not items and not g.user.is_admin:
        abort(403)
    return render_template("cloudpanel/index.html", items=items)


@bp.get("/<int:system_id>")
@login_required
def detail(system_id: int):
    system = _get(system_id, LEVEL_VIEW)
    tab = request.args.get("tab", "sites")
    if tab not in TABS:
        tab = "sites"
    data, error = {"sites": [], "databases": [], "users": [], "version": "", "full": False}, None
    if tab != "access":
        try:
            data = _status(system)
        except (SSHError, OSError) as exc:
            error = str(exc)
    ctx: dict = {"system": system, "tab": tab, "tabs": TABS, "d": data, "error": error, "site_types": SITE_TYPES,
                 "php_versions": PHP_VERSIONS, "node_versions": NODE_VERSIONS, "python_versions": PYTHON_VERSIONS,
                 "roles": ROLES, "sso_servers": [], "pangolin": None, "publish": {}}
    if tab == "users":
        ctx["sso_servers"] = [x for x in g.db.execute(select(SsoServer).order_by(SsoServer.name)).scalars()
                              if common.can(KIND_SSO, x.id, LEVEL_FULL)]
    if tab == "access":
        from .mailcow import primary_pangolin
        ctx["pangolin"] = primary_pangolin()
        ctx["publish"] = {"name": f"CloudPanel {system.name}", "ip": system.host, "port": PANEL_PORT,
                          "method": "https", "sso": "1", "subdomain": "cloudpanel"}
    return render_template("cloudpanel/detail.html", **ctx)


@bp.post("/<int:system_id>/do")
@login_required
def do(system_id: int):
    op = request.form.get("op", "")
    if op not in ACTIONS:
        abort(400)
    system = _get(system_id, ACTIONS[op])
    f = request.form
    tab = "databases" if op == "db_add" else "users" if op.startswith("user_") else "sites"
    password = ""
    try:
        if op == "site_add":
            env = site_env(f.to_dict())
            password = security.generate_password()
            env["SM_SITE_PASSWORD"] = password
            subject = env["SM_DOMAIN"]
        elif op in ("site_delete", "cert", "db_add"):
            domain = (f.get("domain") or "").strip().lower()
            if not DOMAIN_RE.match(domain):
                raise ValueError("Ungültige Domain")
            env, subject = {"SM_DOMAIN": domain}, domain
            if op == "cert":
                san = [x.strip().lower() for x in (f.get("san") or "").split(",") if x.strip()]
                if any(not DOMAIN_RE.match(x) for x in san) or len(san) > 20:
                    raise ValueError("Weitere Namen als Domains, durch Komma getrennt")
                env["SM_SAN"] = ",".join(san)
            if op == "db_add":
                name, user = (f.get("db") or "").strip(), (f.get("db_user") or "").strip()
                if not DB_RE.match(name) or not DB_RE.match(user):
                    raise ValueError("Name von Datenbank und Datenbank-Benutzer: Buchstaben, Ziffern, _ und -")
                password = security.generate_password()
                env.update(SM_DB=name, SM_DB_USER=user, SM_DB_PASSWORD=password)
                subject = f"{name} ({domain})"
        elif op == "user_add":
            sites = [s["domain"] for s in _status(system)["sites"]]
            raw = f.to_dict()
            raw["sites"] = f.getlist("sites")
            env = user_env(raw, sites, allow_admin=g.user.is_admin)
            password = security.generate_password()
            env["SM_PASSWORD"] = password
            subject = env["SM_USER"]
        else:
            user = (f.get("user") or "").strip()
            if not USER_RE.match(user):
                raise ValueError("Ungültiger Benutzername")
            if not g.user.is_admin:
                # changing or removing an administrator of the CloudPanel is for administrators only
                if any(u["name"] == user and u["role"] == "admin" for u in _status(system)["users"]):
                    raise ValueError("CloudPanel-Administratoren ändern nur Administratoren des Servermanagers")
            env, subject = {"SM_USER": user}, user
            if op == "user_password":
                password = security.generate_password()
                env["SM_PASSWORD"] = password
        _run(system, op, env)
        audit(g.db, g.user, f"cloudpanel.{op}", system.name, subject[:200], ip=client_ip())
        g.db.commit()
        msg = {"site_add": "Site angelegt", "site_delete": "Site gelöscht", "cert": "Zertifikat ausgestellt",
               "db_add": "Datenbank angelegt", "user_add": "Benutzer angelegt", "user_delete": "Benutzer gelöscht",
               "user_password": "Passwort gesetzt", "user_mfa_off": "Zwei-Faktor-Anmeldung abgeschaltet"}[op]
        label = {"site_add": "Passwort des Site-Benutzers", "db_add": "Passwort des Datenbank-Benutzers"}.get(
            op, "Passwort")
        flash(f"{subject}: {msg}." + (f" {label} (wird nur jetzt angezeigt): {password}" if password else ""),
              "success")
    except (ValueError, SSHError, OSError) as exc:
        flash(f"Fehlgeschlagen: {exc}", "danger")
    return redirect(url_for("cloudpanel.detail", system_id=system_id, tab=tab))


@bp.route("/<int:system_id>/from-authentik", methods=["GET", "POST"])
@login_required
def from_authentik(system_id: int):
    """CloudPanel users for authentik users (same user name and e-mail, random start password)."""
    from ... import integrations
    system = _get(system_id, LEVEL_FULL)
    raw = request.values.get("sso", "")
    if not raw.isdigit():
        abort(400)
    sso = common.get_or_403(KIND_SSO, int(raw), LEVEL_FULL)
    ctx: dict = {"system": system, "sso": sso, "roles": ROLES, "candidates": [], "result": None, "error": None,
                 "sites": []}
    try:
        status = _status(system)
        ctx["sites"] = [s["domain"] for s in status["sites"]]
        existing = {u["name"].lower() for u in status["users"]}
        ak_users = integrations.sso_client(sso).users()
        ctx["candidates"] = [{"username": u.get("username"), "name": u.get("name") or "", "email": u.get("email") or "",
                              "exists": str(u.get("username") or "").lower() in existing,
                              "valid": bool(USER_RE.match(str(u.get("username") or "")) and u.get("email"))}
                             for u in sorted(ak_users, key=lambda x: str(x.get("username") or "").lower())
                             if u.get("is_active", True)]
        if request.method == "POST":
            chosen = set(request.form.getlist("users"))
            result = {"created": [], "errors": []}
            for cand in ctx["candidates"]:
                if cand["username"] not in chosen or cand["exists"] or not cand["valid"]:
                    continue
                first, _, last = cand["name"].partition(" ")
                form = {"user": cand["username"], "email": cand["email"], "first": first or cand["username"],
                        "last": last or "-", "role": request.form.get("role", ""),
                        "sites": request.form.getlist("sites")}
                try:
                    env = user_env(form, ctx["sites"], allow_admin=g.user.is_admin)
                    pw = security.generate_password()
                    _run(system, "user_add", dict(env, SM_PASSWORD=pw))
                    result["created"].append((cand["username"], pw))
                    cand["exists"] = True
                except (ValueError, SSHError, OSError) as exc:
                    result["errors"].append(f"{cand['username']}: {exc}")
            audit(g.db, g.user, "cloudpanel.from_authentik", system.name,
                  f"{sso.name}: {len(result['created'])} Benutzer", ip=client_ip())
            g.db.commit()
            ctx["result"] = result
    except (AuthentikError, SSHError, OSError, ValueError) as exc:
        ctx["error"] = str(exc)
    return render_template("cloudpanel/from_authentik.html", **ctx)


@bp.app_context_processor
def _ctx():
    def nav() -> bool:
        if "cp_nav" not in g:
            user = g.get("user")
            g.cp_nav = bool(user) and g.get("db") is not None and "cloudpanel" not in settings.hidden_modules(g.db) \
                and any(s.has_type("cloudpanel") for s in access.accessible_systems(g.db, user))
        return g.cp_nav
    return {"cloudpanel_nav": nav, "cp_can": lambda system_id, level: can(system_id, level)}
