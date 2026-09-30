"""SSO (authentik): connection, users, one-click connection of Nextcloud and Mailcow."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from sqlalchemy import select

from ... import access, integrations, security
from ...authentik import AuthentikError
from ...core import audit
from ...jobs import enqueue
from ...mailcow import MailcowError
from ...models import (KIND_MAILCOW, KIND_SSO, LEVEL_FULL, LEVEL_OPERATE, LEVEL_VIEW, MailcowServer, SsoClient,
                       SsoServer, System)
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
    ctx: dict = {"s": s, "tab": tab, "tabs": TABS, "error": None, "users": [], "groups": [], "apps": []}
    try:
        au = _client(s)
        if tab == "users":
            ctx["users"] = sorted(au.users(), key=lambda u: u.get("username", ""))
            ctx["groups"] = au.groups()
        else:
            ctx["apps"] = au.applications()
    except AuthentikError as exc:
        ctx["error"] = str(exc)
    clients = g.db.execute(select(SsoClient).where(SsoClient.sso_id == s.id)).scalars().all()
    ctx["clients"] = [(c, g.db.get(System if c.target_kind == "nextcloud" else MailcowServer, c.target_id))
                      for c in clients]
    linked = {(c.target_kind, c.target_id) for c in clients}
    ctx["nextclouds"] = [x for x in g.db.execute(select(System).order_by(System.name)).scalars()
                         if x.has_type("nextcloud") and can(x.id, LEVEL_FULL) and ("nextcloud", x.id) not in linked]
    ctx["mailcows"] = [x for x in g.db.execute(select(MailcowServer).order_by(MailcowServer.name)).scalars()
                       if common.can(KIND_MAILCOW, x.id, LEVEL_FULL) and ("mailcow", x.id) not in linked]
    ctx["all_mailcows"] = [x for x in g.db.execute(select(MailcowServer).order_by(MailcowServer.name)).scalars()
                           if common.can(KIND_MAILCOW, x.id, LEVEL_FULL)]
    from .mailcow import primary_pangolin
    parts = urlsplit(s.api_url or "")
    ctx["pangolin"] = primary_pangolin()
    ctx["publish"] = {"name": f"authentik {s.name}", "ip": parts.hostname or "",
                      "port": parts.port or (443 if parts.scheme == "https" else 80), "method": parts.scheme or "https",
                      "sso": "0", "subdomain": (urlsplit(s.public_url).hostname or "").split(".")[0]}
    return render_template("sso/detail.html", **ctx)


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
    else:
        abort(400)
    app_url = (request.form.get("app_url") or (target.public_url if kind == "mailcow" else "")).strip().rstrip("/")
    if not re.match(r"^https://[A-Za-z0-9.-]+(:\d+)?(/[A-Za-z0-9._/-]*)?$", app_url):
        flash("Öffentliche Adresse der Anwendung als https://… angeben (über Pangolin erreichbar).", "danger")
        return redirect(url_for("sso.detail", sso_id=sso_id))
    if g.db.execute(select(SsoClient).where(SsoClient.target_kind == kind, SsoClient.target_id == target.id)).first():
        flash("Diese Anwendung ist bereits mit einem SSO verbunden.", "warning")
        return redirect(url_for("sso.detail", sso_id=sso_id))
    job = enqueue(g.db, kind="sso_connect", title=f"SSO verbinden: {target.name} ↔ {s.name}", user=g.user,
                  system=target if kind == "nextcloud" else None,
                  payload={"sso_id": s.id, "kind": kind, "target_id": target.id, "app_url": app_url})
    audit(g.db, g.user, "sso.connect_start", s.name, f"{kind} {target.name}", ip=client_ip())
    g.db.commit()
    return redirect(url_for("jobs.detail", job_id=job.id))


@bp.post("/<int:sso_id>/disconnect/<int:client_id>")
@login_required
def disconnect(sso_id: int, client_id: int):
    s = _get(sso_id, LEVEL_FULL)
    c = g.db.get(SsoClient, client_id)
    if c is None or c.sso_id != s.id:
        abort(404)
    target = g.db.get(System if c.target_kind == "nextcloud" else MailcowServer, c.target_id)
    job = enqueue(g.db, kind="sso_disconnect", title=f"SSO trennen: {target.name if target else c.target_id}",
                  user=g.user, system=target if c.target_kind == "nextcloud" else None,
                  payload={"client_id": c.id})
    audit(g.db, g.user, "sso.disconnect_start", s.name, c.slug, ip=client_ip())
    g.db.commit()
    return redirect(url_for("jobs.detail", job_id=job.id))


# a new password is an account takeover: full access, and administrator accounts only for admins
USER_ACTIONS = {"add": LEVEL_FULL, "delete": LEVEL_FULL, "active": LEVEL_OPERATE, "password": LEVEL_FULL}


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
            if action == "active":
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
