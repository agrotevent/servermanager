"""Nextcloud via its OCS API: overview (serverinfo), users and groups."""
from __future__ import annotations

import re

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from sqlalchemy import select

from ... import access, integrations, security
from ...core import audit
from ...models import (KIND_NEXTCLOUD, KIND_SSO, LEVEL_FULL, LEVEL_OPERATE, LEVEL_VIEW, NextcloudServer, SsoClient,
                       SsoServer, System)
from ...nextcloud_api import (NextcloudError, check_group, check_quota, check_uid, normalize_url, quota_info,
                              quota_text)
from ..auth import admin_required, client_ip, login_required
from . import _integration as common

bp = Blueprint("nextcloud", __name__, url_prefix="/nextcloud")
TABS = {"overview": "Übersicht", "users": "Benutzer", "groups": "Gruppen"}
ADMIN_GROUP = "admin"
# disabling is "operate"; everything that changes accounts or could take one over needs full access
USER_ACTIONS = {"add": LEVEL_FULL, "edit": LEVEL_FULL, "password": LEVEL_FULL, "delete": LEVEL_FULL,
                "enable": LEVEL_OPERATE, "disable": LEVEL_OPERATE}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _get(nid: int, level: str) -> NextcloudServer:
    return common.get_or_403(KIND_NEXTCLOUD, nid, level)


def _client(n: NextcloudServer):
    try:
        return integrations.nextcloud_client(n)
    except (NextcloudError, ValueError) as exc:
        abort(400, description=f"Nextcloud-Verbindung unvollständig: {exc}")


def sso_of(n: NextcloudServer):
    """(SsoClient, SsoServer) when the linked Nextcloud system is connected to the SSO."""
    if not n.system_id:
        return None, None
    c = g.db.execute(select(SsoClient).where(SsoClient.target_kind == "nextcloud",
                                             SsoClient.target_id == n.system_id)).scalars().first()
    return (c, g.db.get(SsoServer, c.sso_id)) if c else (None, None)


@bp.get("/")
@login_required
def index():
    items = common.visible(KIND_NEXTCLOUD)
    if not items and not g.user.is_admin:
        abort(403)
    return render_template("nextcloud/index.html", items=items)


def _save(n: NextcloudServer) -> list[str]:
    f = request.form
    errors = common.save_common(n, f, 443)
    try:
        n.api_url = normalize_url(f.get("api_url", ""))
    except NextcloudError as exc:
        errors.append(str(exc))
    n.username = (f.get("username") or "").strip()[:64]
    if not n.username:
        errors.append("Benutzername des Administrator-Kontos angeben.")
    if f.get("password"):
        n.password_enc = security.encrypt(f["password"].strip())
    elif not n.password_enc:
        errors.append("App-Passwort angeben (Nextcloud → Persönliche Einstellungen → Sicherheit → "
                      "Neues App-Passwort erstellen).")
    raw = f.get("system_id", "")
    system = g.db.get(System, int(raw)) if raw.isdigit() else None
    n.system_id = system.id if system is not None and system.has_type("nextcloud") else None
    return errors


def _form(n: NextcloudServer, is_new: bool):
    systems = [s for s in g.db.execute(select(System).order_by(System.name)).scalars() if s.has_type("nextcloud")]
    return render_template("nextcloud/form.html", n=n, is_new=is_new, systems=systems)


@bp.route("/new", methods=["GET", "POST"])
@admin_required
def new():
    n = NextcloudServer(monitor=True, verify_ca=True)
    if request.method == "POST":
        errors = _save(n)
        if request.form.get("fetch_fp"):
            fp, err = common.fetch_fp_from_form(443)
            flash(err or "Fingerabdruck abgerufen – bitte vergleichen und speichern.", "danger" if err else "info")
            n.fingerprint = fp or n.fingerprint
            return _form(n, True)
        if errors:
            for e in errors:
                flash(e, "danger")
            return _form(n, True)
        g.db.add(n)
        g.db.flush()
        audit(g.db, g.user, "nextcloud.create", n.name, n.api_url, ip=client_ip())
        integrations.poll(g.db, n)
        g.db.commit()
        if n.status_message:
            flash(f"Gespeichert, aber die Verbindung schlägt fehl: {n.status_message}", "warning")
        else:
            flash("Nextcloud angebunden.", "success")
        return redirect(url_for("nextcloud.detail", nid=n.id))
    return _form(n, True)


@bp.route("/<int:nid>/edit", methods=["GET", "POST"])
@admin_required
def edit(nid: int):
    n = _get(nid, LEVEL_FULL)
    if request.method == "POST":
        if request.form.get("fetch_fp"):
            g.db.expunge(n)
            _save(n)
            fp, err = common.fetch_fp_from_form(443)
            flash(err or "Fingerabdruck abgerufen.", "danger" if err else "info")
            n.fingerprint = fp or n.fingerprint
            return _form(n, False)
        errors = _save(n)
        if errors:
            g.db.rollback()
            for e in errors:
                flash(e, "danger")
            return redirect(url_for("nextcloud.edit", nid=nid))
        audit(g.db, g.user, "nextcloud.update", n.name, ip=client_ip())
        integrations.poll(g.db, n)
        g.db.commit()
        flash("Gespeichert." + (f" Verbindung: {n.status_message}" if n.status_message else ""),
              "warning" if n.status_message else "success")
        return redirect(url_for("nextcloud.detail", nid=n.id))
    return _form(n, False)


@bp.post("/<int:nid>/delete")
@admin_required
def delete(nid: int):
    n = _get(nid, LEVEL_FULL)
    access.remove_integration(g.db, KIND_NEXTCLOUD, n.id)
    audit(g.db, g.user, "nextcloud.delete", n.name, ip=client_ip())
    g.db.delete(n)
    g.db.commit()
    flash("Nextcloud-Verbindung entfernt (in der Nextcloud ändert sich nichts).", "warning")
    return redirect(url_for("nextcloud.index"))


@bp.post("/<int:nid>/sync")
@login_required
def sync(nid: int):
    n = _get(nid, LEVEL_OPERATE)
    integrations.poll(g.db, n)
    g.db.commit()
    flash(n.status_message or "Aktualisiert.", "danger" if n.status_message else "success")
    return redirect(common.safe_next(url_for("nextcloud.detail", nid=nid)))


@bp.get("/<int:nid>")
@login_required
def detail(nid: int):
    n = _get(nid, LEVEL_VIEW)
    tab = request.args.get("tab", "overview")
    if tab not in TABS:
        tab = "overview"
    users, groups, error = [], [], None
    if tab in ("users", "groups"):
        try:
            nc = _client(n)
            groups = nc.groups()
            if tab == "users":
                users = nc.users()
                for u in users:
                    u["_quota"], u["_quota_text"] = quota_info(u), quota_text(u)
        except NextcloudError as exc:
            error = str(exc)
    system = g.db.get(System, n.system_id) if n.system_id else None
    sso_client, sso_server = sso_of(n)
    sso_servers = [s for s in g.db.execute(select(SsoServer).order_by(SsoServer.name)).scalars()
                   if common.can(KIND_SSO, s.id, LEVEL_FULL)]
    return render_template("nextcloud/detail.html", n=n, tab=tab, tabs=TABS, users=users, groups=groups,
                           error=error, system=system, sso_client=sso_client, sso_server=sso_server,
                           sso_servers=sso_servers, admin_group=ADMIN_GROUP)


def _guard_admin_account(nc, uid: str) -> dict:
    """Details of ``uid``; accounts of Nextcloud administrators only for administrators of the servermanager."""
    try:
        info = nc.user(uid)
    except NextcloudError as exc:
        if exc.status == 404:
            raise NextcloudError(f"Benutzer {uid} gibt es nicht") from None
        raise
    if ADMIN_GROUP in (info.get("groups") or []) and not g.user.is_admin:
        raise NextcloudError("Konten von Nextcloud-Administratoren können nur Administratoren des Servermanagers "
                             "ändern")
    return info


def _groups_from_form(allowed: set[str]) -> list[str]:
    chosen = [check_group(x) for x in request.form.getlist("groups") if x.strip()]
    unknown = [x for x in chosen if x not in allowed]
    if unknown:
        raise NextcloudError(f"Unbekannte Gruppe: {', '.join(unknown)}")
    if ADMIN_GROUP in chosen and not g.user.is_admin:
        raise NextcloudError("Nur Administratoren des Servermanagers dürfen die Gruppe „admin“ vergeben")
    return chosen


@bp.post("/<int:nid>/users")
@login_required
def user_action(nid: int):
    action = request.form.get("action", "")
    if action not in USER_ACTIONS:
        abort(400)
    n = _get(nid, USER_ACTIONS[action])
    nc = _client(n)
    f = request.form
    uid = (f.get("uid") or "").strip()
    try:
        check_uid(uid)
        email = (f.get("email") or "").strip()
        if email and not EMAIL_RE.match(email):
            raise NextcloudError("Ungültige E-Mail-Adresse")
        if action == "add":
            allowed = {x["id"] for x in nc.groups()}
            groups = _groups_from_form(allowed)
            pw = f.get("password") or security.generate_password()
            if len(pw) < 10:
                raise NextcloudError("Passwort mindestens 10 Zeichen")
            nc.add_user(uid, pw, (f.get("display") or "").strip(), email, groups, check_quota(f.get("quota", "")))
            msg = f"{uid} angelegt." + ("" if f.get("password") else f" Passwort (wird nur jetzt angezeigt): {pw}")
        else:
            if uid.lower() == (n.username or "").lower() and action in ("disable", "delete"):
                raise NextcloudError("Das Konto der Schnittstelle selbst kann hier nicht gesperrt oder gelöscht "
                                     "werden")
            info = _guard_admin_account(nc, uid)
            if action in ("enable", "disable"):
                nc.set_enabled(uid, action == "enable")
                msg = f"{uid} {'entsperrt' if action == 'enable' else 'gesperrt'}."
            elif action == "password":
                pw = security.generate_password()
                nc.edit_user(uid, "password", pw)
                msg = f"Neues Passwort für {uid} (wird nur jetzt angezeigt): {pw}"
            elif action == "delete":
                nc.delete_user(uid)
                msg = f"{uid} mit allen Dateien gelöscht."
            else:
                changes = []
                display = (f.get("display") or "").strip()[:100]
                if display != (info.get("displayname") or ""):
                    nc.edit_user(uid, "displayname", display)
                    changes.append("Anzeigename")
                if email != (info.get("email") or ""):
                    nc.edit_user(uid, "email", email)
                    changes.append("E-Mail")
                quota = check_quota(f.get("quota", ""))
                if quota and quota != quota_text(info):
                    nc.edit_user(uid, "quota", quota)
                    changes.append("Quota")
                allowed = {x["id"] for x in nc.groups()}
                wanted = set(_groups_from_form(allowed))
                current = set(info.get("groups") or [])
                if ADMIN_GROUP in current and ADMIN_GROUP not in wanted and not g.user.is_admin:
                    wanted.add(ADMIN_GROUP)
                to_add, to_remove = sorted(wanted - current), sorted((current - wanted) & allowed)
                for gid in to_add:
                    nc.add_to_group(uid, gid)
                for gid in to_remove:
                    nc.remove_from_group(uid, gid)
                if to_add or to_remove:
                    changes.append("Gruppen")
                msg = f"{uid}: " + (", ".join(changes) + " geändert." if changes else "keine Änderung.")
        audit(g.db, g.user, f"nextcloud.user_{action}", n.name, uid, ip=client_ip())
        g.db.commit()
        flash(msg, "success")
    except NextcloudError as exc:
        flash(f"Fehlgeschlagen: {exc}", "danger")
    return redirect(url_for("nextcloud.detail", nid=nid, tab="users"))


@bp.post("/<int:nid>/groups")
@login_required
def group_add(nid: int):
    n = _get(nid, LEVEL_FULL)
    nc = _client(n)
    try:
        gid = check_group(request.form.get("gid", ""))
        nc.add_group(gid)
        audit(g.db, g.user, "nextcloud.group_add", n.name, gid, ip=client_ip())
        g.db.commit()
        flash(f"Gruppe {gid} angelegt.", "success")
    except NextcloudError as exc:
        flash(f"Fehlgeschlagen: {exc}", "danger")
    return redirect(url_for("nextcloud.detail", nid=nid, tab="groups"))
