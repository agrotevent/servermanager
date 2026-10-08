"""SSO (authentik): connection, users, one-click connection of Nextcloud and Mailcow."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from sqlalchemy import select

from ... import access, integrations, security, settings, sso_login
from ... import sso as sso_lib
from ...authentik import AuthentikError
from ...core import audit
from ...jobs import enqueue
from ...mailcow import MailcowError
from ...models import (KIND_MAILCOW, KIND_PANGOLIN, KIND_PVE, KIND_SSO, KIND_ZAMMAD, LEVEL_FULL, LEVEL_OPERATE, LEVEL_VIEW, MailcowServer,
                       PangolinServer, PveServer, SsoClient, SsoServer, System, ZammadServer)
from ...pangolin import dashboard_guess
from ..auth import admin_required, can, client_ip, login_required
from . import _integration as common

bp = Blueprint("sso", __name__, url_prefix="/sso")
TABS = {"apps": "Anwendungen", "users": "Benutzer"}


def _get(sso_id: int, level: str) -> SsoServer:
    return common.get_or_403(KIND_SSO, sso_id, level)


def _client(s: SsoServer):
    try:
        return integrations.sso_client(s)
    except (AuthentikError, ValueError) as exc:
        abort(400, description=f"SSO-Verbindung unvollständig: {exc}")


@bp.get("/")
@login_required
def index():
    items = common.visible(KIND_SSO)
    if not items and not g.user.is_admin:
        abort(403)
    return render_template("sso/index.html", items=items)


def _save(s: SsoServer) -> list[str]:
    f = request.form
    errors = common.save_common(s, f, 443)
    if f.get("token"):
        s.token_enc = security.encrypt(f["token"].strip())
    elif not s.token_enc:
        errors.append("API-Token angeben (authentik → Verzeichnis → Tokens, Zweck „API“).")
    pub = (f.get("public_url") or "").strip().rstrip("/")
    if not re.match(r"^https://[A-Za-z0-9.-]+(:\d+)?$", pub):
        errors.append("Öffentliche Adresse als https://auth.example.com angeben (über Pangolin erreichbar).")
    s.public_url = pub
    raw = f.get("system_id", "")
    s.system_id = int(raw) if raw.isdigit() and g.db.get(System, int(raw)) else None
    return errors


def _form(s: SsoServer, is_new: bool):
    return render_template("sso/form.html", s=s, is_new=is_new,
                           systems=g.db.execute(select(System).order_by(System.name)).scalars().all())


@bp.route("/new", methods=["GET", "POST"])
@admin_required
def new():
    s = SsoServer(monitor=True, verify_ca=False, kind="authentik")
    if request.method == "POST":
        errors = _save(s)
        if request.form.get("fetch_fp"):
            fp, err = common.fetch_fp_from_form(443)
            flash(err or "Fingerabdruck abgerufen – bitte vergleichen und speichern.", "danger" if err else "info")
            s.fingerprint = fp or s.fingerprint
            return _form(s, True)
        if errors:
            for e in errors:
                flash(e, "danger")
            return _form(s, True)
        g.db.add(s)
        g.db.flush()
        audit(g.db, g.user, "sso.create", s.name, s.api_url, ip=client_ip())
        integrations.poll(g.db, s)
        g.db.commit()
        flash("SSO-Verbindung angelegt.", "success")
        return redirect(url_for("sso.detail", sso_id=s.id))
    return _form(s, True)


@bp.route("/<int:sso_id>/edit", methods=["GET", "POST"])
@admin_required
def edit(sso_id: int):
    s = _get(sso_id, LEVEL_FULL)
    if request.method == "POST":
        if request.form.get("fetch_fp"):
            g.db.expunge(s)
            _save(s)
            fp, err = common.fetch_fp_from_form(443)
            flash(err or "Fingerabdruck abgerufen.", "danger" if err else "info")
            s.fingerprint = fp or s.fingerprint
            return _form(s, False)
        errors = _save(s)
        if errors:
            g.db.rollback()
            for e in errors:
                flash(e, "danger")
            return redirect(url_for("sso.edit", sso_id=sso_id))
        audit(g.db, g.user, "sso.update", s.name, ip=client_ip())
        integrations.poll(g.db, s)
        g.db.commit()
        flash("Gespeichert.", "success")
        return redirect(url_for("sso.detail", sso_id=s.id))
    return _form(s, False)


@bp.post("/<int:sso_id>/delete")
@admin_required
def delete(sso_id: int):
    s = _get(sso_id, LEVEL_FULL)
    if g.db.execute(select(SsoClient).where(SsoClient.sso_id == s.id)).first():
        flash("Zuerst alle verbundenen Anwendungen trennen.", "danger")
        return redirect(url_for("sso.detail", sso_id=sso_id))
    access.remove_integration(g.db, KIND_SSO, s.id)
    audit(g.db, g.user, "sso.delete", s.name, ip=client_ip())
    g.db.delete(s)
    g.db.commit()
    flash("SSO-Verbindung entfernt.", "warning")
    return redirect(url_for("sso.index"))


@bp.get("/<int:sso_id>")
@login_required
def detail(sso_id: int):
    s = _get(sso_id, LEVEL_VIEW)
    tab = request.args.get("tab", "apps")
    if tab not in TABS:
        tab = "apps"
    ctx: dict = {"s": s, "tab": tab, "tabs": TABS, "error": None, "users": [], "groups": [], "apps": [],
                 "member_of": {}}
    try:
        au = _client(s)
        if tab == "users":
            ctx["users"] = sorted(au.users(), key=lambda u: u.get("username", ""))
            ctx["groups"] = au.groups()
            member_of: dict = {}
            for grp in ctx["groups"]:
                for upk in grp.get("users") or []:
                    member_of.setdefault(upk, []).append(str(grp.get("pk")))
            ctx["member_of"] = member_of
        else:
            ctx["apps"] = au.applications()
    except AuthentikError as exc:
        ctx["error"] = str(exc)
    clients = g.db.execute(select(SsoClient).where(SsoClient.sso_id == s.id)).scalars().all()
    ctx["clients"] = [(c, sso_lib.target_of(g.db, c.target_kind, c.target_id)) for c in clients]
    ctx["kind_labels"] = sso_lib.KIND_LABELS
    sm = g.db.execute(select(SsoClient).where(SsoClient.target_kind == sso_login.KIND)).scalars().first()
    ctx["sm_login"] = sm
    ctx["sm_login_here"] = sm is not None and sm.sso_id == s.id
    ctx["sm_base"] = settings.base_url(g.db)
    ctx["login_opts"] = {k: settings.get(g.db, f"login.{k}") for k in ("sso_group", "sso_auto_create", "sso_admins")}
    linked = {(c.target_kind, c.target_id) for c in clients}
    ctx["nextclouds"] = [x for x in g.db.execute(select(System).order_by(System.name)).scalars()
                         if x.has_type("nextcloud") and can(x.id, LEVEL_FULL) and ("nextcloud", x.id) not in linked]
    ctx["mailcows"] = [x for x in g.db.execute(select(MailcowServer).order_by(MailcowServer.name)).scalars()
                       if common.can(KIND_MAILCOW, x.id, LEVEL_FULL) and ("mailcow", x.id) not in linked]
    ctx["pves"] = [(x, _pve_gui(x))
                   for x in g.db.execute(select(PveServer).order_by(PveServer.name)).scalars()
                   if common.can(KIND_PVE, x.id, LEVEL_FULL) and ("pve", x.id) not in linked]
    ctx["pve_realm"] = sso_lib.pve_realm(s)
    ctx["zammads"] = [(x, _zammad_web(x)) for x in g.db.execute(select(ZammadServer).order_by(ZammadServer.name)).scalars()
                      if common.can(KIND_ZAMMAD, x.id, LEVEL_FULL) and ("zammad", x.id) not in linked]
    ctx["pangolins"] = [(x, dashboard_guess(x.api_url))
                        for x in g.db.execute(select(PangolinServer).order_by(PangolinServer.name)).scalars()
                        if common.can(KIND_PANGOLIN, x.id, LEVEL_FULL) and ("pangolin", x.id) not in linked]
    ctx["all_mailcows"] = [x for x in g.db.execute(select(MailcowServer).order_by(MailcowServer.name)).scalars()
                           if common.can(KIND_MAILCOW, x.id, LEVEL_FULL)]
    from .mailcow import primary_pangolin
    parts = urlsplit(s.api_url or "")
    ctx["pangolin"] = primary_pangolin()
    ctx["publish"] = {"name": f"authentik {s.name}", "ip": parts.hostname or "",
                      "port": parts.port or (443 if parts.scheme == "https" else 80), "method": parts.scheme or "https",
                      "sso": "0", "subdomain": (urlsplit(s.public_url).hostname or "").split(".")[0]}
    return render_template("sso/detail.html", **ctx)


def _pve_gui(server: PveServer) -> str:
    """Address of the Proxmox web interface derived from the API address (https://host:8006)."""
    parts = urlsplit(server.api_url or "")
    return f"https://{parts.netloc}" if parts.hostname else ""


@bp.post("/<int:sso_id>/connect")
@login_required
def connect(sso_id: int):
    s = _get(sso_id, LEVEL_FULL)
    kind = request.form.get("kind", "")
    target_id = int(request.form.get("target_id", "0") or 0)
    if kind == "nextcloud":
        target = g.db.get(System, target_id)
        if target is None or not target.has_type("nextcloud") or not can(target.id, LEVEL_FULL):
            abort(403)
    elif kind == "mailcow":
        target = common.get_or_403(KIND_MAILCOW, target_id, LEVEL_FULL)
    elif kind == "pangolin":
        target = common.get_or_403(KIND_PANGOLIN, target_id, LEVEL_FULL)
    elif kind == "pve":
        target = common.get_or_403(KIND_PVE, target_id, LEVEL_FULL)
    elif kind == "zammad":
        target = common.get_or_403(KIND_ZAMMAD, target_id, LEVEL_FULL)
    elif kind == sso_login.KIND:
        if not g.user.is_admin:
            abort(403)
        target = sso_login.TARGET
        _save_login_options()
    else:
        abort(400)
    default = {"mailcow": getattr(target, "public_url", ""), "pangolin": dashboard_guess(getattr(target, "api_url", "")),
               sso_login.KIND: settings.base_url(g.db), "pve": _pve_gui(target) if kind == "pve" else "",
               "zammad": _zammad_web(target) if kind == "zammad" else ""}
    app_url = (request.form.get("app_url") or default.get(kind) or "").strip().rstrip("/")
    if not re.match(r"^https://[A-Za-z0-9.-]+(:\d+)?(/[A-Za-z0-9._/-]*)?$", app_url):
        flash("Öffentliche Adresse der Anwendung als https://… angeben (über Pangolin erreichbar).", "danger")
        return redirect(url_for("sso.detail", sso_id=sso_id))
    if g.db.execute(select(SsoClient).where(SsoClient.target_kind == kind, SsoClient.target_id == target.id)).first():
        flash("Diese Anwendung ist bereits mit einem SSO verbunden.", "warning")
        g.db.commit()
        return redirect(url_for("sso.detail", sso_id=sso_id))
    job = enqueue(g.db, kind="sso_connect", title=f"SSO verbinden: {target.name} ↔ {s.name}", user=g.user,
                  system=target if kind == "nextcloud" else None,
                  payload={"sso_id": s.id, "kind": kind, "target_id": target.id, "app_url": app_url,
                           "options": _connect_options(kind)})
    audit(g.db, g.user, "sso.connect_start", s.name, f"{kind} {target.name}", ip=client_ip())
    g.db.commit()
    return redirect(url_for("jobs.detail", job_id=job.id))


def _connect_options(kind: str) -> dict:
    f = request.form
    if kind == "pve":
        return {"groups": f.get("groups") == "1", "default": f.get("default") == "1"}
    if kind == "zammad":
        return {"auto_link": f.get("auto_link") == "1"}
    return {}


def _zammad_web(z: ZammadServer) -> str:
    from ...zammad import ZammadError, normalize_url
    try:
        return normalize_url(z.api_url)
    except ZammadError:
        return ""


def _save_login_options() -> None:
    f = request.form
    group = f.get("sso_group", "").strip()
    if group and not re.match(r"^[^\x00-\x1f]{1,150}$", group):
        group = ""
    settings.set(g.db, "login.sso_group", group)
    settings.set(g.db, "login.sso_auto_create", f.get("sso_auto_create") == "1")
    settings.set(g.db, "login.sso_admins", f.get("sso_admins") == "1")


@bp.post("/<int:sso_id>/login-options")
@admin_required
def login_options(sso_id: int):
    s = _get(sso_id, LEVEL_FULL)
    _save_login_options()
    audit(g.db, g.user, "sso.login_options", s.name,
          f"Gruppe={settings.get(g.db, 'login.sso_group') or '-'} "
          f"auto={settings.get(g.db, 'login.sso_auto_create')} admins={settings.get(g.db, 'login.sso_admins')}",
          ip=client_ip())
    g.db.commit()
    flash("Anmelde-Optionen gespeichert.", "success")
    return redirect(url_for("sso.detail", sso_id=sso_id))


@bp.post("/<int:sso_id>/disconnect/<int:client_id>")
@login_required
def disconnect(sso_id: int, client_id: int):
    s = _get(sso_id, LEVEL_FULL)
    c = g.db.get(SsoClient, client_id)
    if c is None or c.sso_id != s.id:
        abort(404)
    if c.target_kind == sso_login.KIND and not g.user.is_admin:
        abort(403)
    target = sso_lib.target_of(g.db, c.target_kind, c.target_id)
    job = enqueue(g.db, kind="sso_disconnect", title=f"SSO trennen: {target.name if target else c.target_id}",
                  user=g.user, system=target if c.target_kind == "nextcloud" else None,
                  payload={"client_id": c.id})
    audit(g.db, g.user, "sso.disconnect_start", s.name, c.slug, ip=client_ip())
    g.db.commit()
    return redirect(url_for("jobs.detail", job_id=job.id))


def _edit_user(au, pk: int, username: str) -> str:
    """Name, e-mail and group memberships of an authentik user (administrator groups only for admins)."""
    f = request.form
    email = (f.get("email") or "").strip()
    if email and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        raise ValueError("Ungültige E-Mail-Adresse")
    name = (f.get("name") or "").strip()[:150] or username
    au.update_user(pk, name, email)
    groups = {str(x.get("pk")): x for x in au.groups()}
    wanted = {x for x in f.getlist("groups") if x in groups}
    current = {k for k, x in groups.items() if pk in [int(u) for u in (x.get("users") or []) if str(u).isdigit()]}
    changed = []
    for gpk in sorted(wanted ^ current):
        grp = groups[gpk]
        if grp.get("is_superuser") and not g.user.is_admin:
            raise ValueError(f"Die Administrator-Gruppe „{grp.get('name')}“ vergeben nur Administratoren des "
                             "Servermanagers")
        if gpk in wanted:
            au.add_to_group(gpk, pk)
            changed.append(f"+{grp.get('name')}")
        else:
            au.remove_from_group(gpk, pk)
            changed.append(f"−{grp.get('name')}")
    return f"{username} gespeichert." + (f" Gruppen: {', '.join(changed)}" if changed else "")


# a new password is an account takeover: full access, and administrator accounts only for admins
USER_ACTIONS = {"add": LEVEL_FULL, "delete": LEVEL_FULL, "active": LEVEL_OPERATE, "password": LEVEL_FULL,
                "edit": LEVEL_FULL}


@bp.post("/<int:sso_id>/users")
@login_required
def user_action(sso_id: int):
    action = request.form.get("action", "")
    if action not in USER_ACTIONS:
        abort(400)
    s = _get(sso_id, USER_ACTIONS[action])
    au = _client(s)
    f = request.form
    try:
        if action == "add":
            username = f.get("username", "").strip()
            email = f.get("email", "").strip()
            if email and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
                raise ValueError("Ungültige E-Mail-Adresse")
            pw = f.get("password") or security.generate_password()
            groups = [gp for gp in f.getlist("groups") if re.match(r"^[0-9a-f-]{8,64}$", gp)]
            au.create_user(username, f.get("name", "").strip()[:150], email, pw, groups)
            msg = f"Benutzer {username} angelegt." + ("" if f.get("password") else
                                                      f" Passwort (wird nur jetzt angezeigt): {pw}")
            mcid = f.get("mailbox_mailcow", "")
            if mcid.isdigit() and email:
                mc = common.get_or_403(KIND_MAILCOW, int(mcid), LEVEL_FULL)
                local, _, domain = email.partition("@")
                mpw = security.generate_password()
                integrations.mailcow_client(mc).add_mailbox(local, domain, f.get("name", "").strip() or username,
                                                           mpw, int(f.get("quota") or 3072))
                msg += f" Postfach {email} auf {mc.name} angelegt (Passwort für E-Mail-Programme: {mpw})."
            target = username
        else:
            pk = int(f.get("pk", "0") or 0)
            target = f.get("username", str(pk))
            if not g.user.is_admin and au.is_admin_user(pk):
                raise ValueError("Administrator-Konten von authentik können nur Administratoren des Servermanagers "
                                 "ändern")
            if action == "edit":
                msg = _edit_user(au, pk, target)
            elif action == "active":
                au.set_active(pk, f.get("active") == "1")
                msg = f"{target} {'aktiviert' if f.get('active') == '1' else 'deaktiviert'}."
            elif action == "password":
                pw = security.generate_password()
                au.set_password(pk, pw)
                msg = f"Neues Passwort für {target} (wird nur jetzt angezeigt): {pw}"
            else:
                au.delete_user(pk)
                msg = f"{target} gelöscht."
        audit(g.db, g.user, f"sso.user_{action}", s.name, target, ip=client_ip())
        g.db.commit()
        flash(msg, "success")
    except (AuthentikError, MailcowError, ValueError) as exc:
        flash(f"Fehlgeschlagen: {exc}", "danger")
    return redirect(url_for("sso.detail", sso_id=sso_id, tab="users"))


# --------------------------------------------------------------------------
# take over users and groups of a Nextcloud
# --------------------------------------------------------------------------
def nc_sources() -> list[tuple[str, str]]:
    """(source, label) of the Nextclouds the user may read the users of: API connections and SSH systems."""
    from ...models import KIND_NEXTCLOUD, NextcloudServer
    out = [(f"api:{n.id}", f"{n.name} (Schnittstelle)")
           for n in g.db.execute(select(NextcloudServer).order_by(NextcloudServer.name)).scalars()
           if common.can(KIND_NEXTCLOUD, n.id, LEVEL_VIEW)]
    out += [(f"ssh:{x.id}", f"{x.name} (SSH)") for x in g.db.execute(select(System).order_by(System.name)).scalars()
            if x.has_type("nextcloud") and can(x.id, LEVEL_VIEW)]
    return out


def _nc_source(source: str) -> tuple[str, list[dict], list[str], object]:
    """(label, users, groups, linked system) of a source; checks the right to read it."""
    from ... import inventory
    from ... import nc_import
    from ...models import KIND_NEXTCLOUD
    from ...modules.nextcloud import occ_task, parse_users
    from ...nextcloud_api import NextcloudError
    from ...ssh import SSHError
    kind, _, raw = (source or "").partition(":")
    if kind not in ("api", "ssh") or not raw.isdigit():
        abort(400)
    try:
        if kind == "api":
            n = common.get_or_403(KIND_NEXTCLOUD, int(raw), LEVEL_VIEW)
            nc = integrations.nextcloud_client(n)
            users, groups = nc.users(), [x["id"] for x in nc.groups()]
            system = g.db.get(System, n.system_id) if n.system_id else None
            return n.name, nc_import.normalize_users(users), groups, system
        system = g.db.get(System, int(raw))
        if system is None or not system.has_type("nextcloud"):
            abort(404)
        if not can(system.id, LEVEL_VIEW):
            abort(403)
        with inventory.connect(system) as conn:
            users, groups = parse_users(occ_task(conn, system, "user_list", timeout=120))
        return system.name, nc_import.normalize_users(users), groups, system
    except (NextcloudError, SSHError, OSError, ValueError) as exc:
        raise AuthentikError(f"Nextcloud-Benutzer nicht lesbar: {exc}") from exc


@bp.route("/<int:sso_id>/import", methods=["GET", "POST"])
@login_required
def nc_import(sso_id: int):
    from ... import nc_import as imp
    s = _get(sso_id, LEVEL_FULL)
    source = request.values.get("source", "")
    sources = nc_sources()
    ctx: dict = {"s": s, "source": source, "sources": sources, "plan": None, "result": None, "error": None,
                 "label": "", "sso_active": False, "admin_group": imp.ADMIN_GROUP}
    if not source:
        return render_template("sso/nc_import.html", **ctx)
    try:
        label, users, groups, system = _nc_source(source)
        ctx["label"] = label
        ctx["sso_active"] = system is not None and g.db.execute(select(SsoClient).where(
            SsoClient.target_kind == "nextcloud", SsoClient.target_id == system.id)).first() is not None
        au = _client(s)
        if request.method == "POST":
            chosen_users = set(request.form.getlist("users"))
            chosen_groups = set(request.form.getlist("groups"))
            if not g.user.is_admin:
                # SSO into a Nextcloud administrator account is an account takeover: only for admins
                admins = {u["uid"] for u in users if imp.ADMIN_GROUP in u["groups"]}
                if chosen_users & admins or imp.ADMIN_GROUP in chosen_groups:
                    raise AuthentikError("Nextcloud-Administratoren und die Gruppe „admin“ können nur Administratoren "
                                         "des Servermanagers übernehmen")
            result = imp.apply(au, users, groups, chosen_groups, chosen_users,
                               passwords=request.form.get("passwords") == "random",
                               existing_members=bool(request.form.get("existing_members")))
            audit(g.db, g.user, "sso.nextcloud_import", s.name,
                  f"{label}: {len(result['groups_created'])} Gruppen, {len(result['users_created'])} Benutzer, "
                  f"{result['memberships']} Mitgliedschaften", ip=client_ip())
            g.db.commit()
            ctx["result"] = result
        ctx["plan"] = imp.plan(users, groups, au.users(), au.groups())
    except AuthentikError as exc:
        ctx["error"] = str(exc)
    return render_template("sso/nc_import.html", **ctx)
