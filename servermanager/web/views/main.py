"""Dashboard, profile (password / 2FA) and audit log."""
from __future__ import annotations

import io
from datetime import datetime, timedelta

import segno
from flask import Blueprint, abort, flash, g, redirect, render_template, request, session, url_for
from sqlalchemy import select

from ... import access, inventory, security, settings
from ...core import audit
from ...models import (JOB_FAILED, JOB_QUEUED, JOB_RUNNING, STATUS_ERROR, STATUS_OFFLINE, STATUS_ONLINE,
                       STATUS_PENDING, AuditLog, Job, MaintenanceSchedule, utcnow)
from ..auth import admin_required, client_ip, login_required

bp = Blueprint("main", __name__)


def visible_jobs_query(limit: int = 20):
    q = select(Job).order_by(Job.id.desc()).limit(limit)
    ids = access.accessible_system_ids(g.db, g.user)
    if ids is not None:
        q = q.where((Job.system_id.in_(ids)) | ((Job.system_id.is_(None)) & (Job.user_id == g.user.id)))
    return q


@bp.get("/")
@login_required
def dashboard():
    systems = access.accessible_systems(g.db, g.user)
    stats = {"total": len(systems), "online": 0, "offline": 0, "pending": 0, "updates": 0, "security": 0,
             "reboot": 0, "release": 0, "packages": 0}
    problems = []
    for s in systems:
        if s.status == STATUS_ONLINE:
            stats["online"] += 1
        elif s.status in (STATUS_OFFLINE, STATUS_ERROR):
            stats["offline"] += 1
            problems.append(s)
        elif s.status == STATUS_PENDING:
            stats["pending"] += 1
        summ = inventory.update_summary(s)
        if summ["total"]:
            stats["updates"] += 1
        stats["packages"] += int((s.upd.get("apt") or {}).get("count") or 0)
        stats["security"] += summ["security"]
        stats["reboot"] += 1 if summ["reboot"] else 0
        stats["release"] += 1 if summ["release"] else 0
    jobs = g.db.execute(visible_jobs_query(12)).scalars().all()
    running = [j for j in g.db.execute(visible_jobs_query(200)).scalars().all()
               if j.status in (JOB_RUNNING, JOB_QUEUED)]
    since = utcnow() - timedelta(hours=24)
    failed = [j for j in g.db.execute(visible_jobs_query(200)).scalars().all()
              if j.status == JOB_FAILED and j.created_at > since]
    sq = select(MaintenanceSchedule).where(MaintenanceSchedule.enabled.is_(True),
                                           MaintenanceSchedule.next_run_at.is_not(None))
    if not g.user.is_admin:
        sq = sq.where(MaintenanceSchedule.created_by == g.user.id)
    upcoming = g.db.execute(sq.order_by(MaintenanceSchedule.next_run_at).limit(5)).scalars().all()

    warnings = []
    if g.user.is_admin:
        hb = settings.get(g.db, "state.worker_heartbeat")
        try:
            stale = not hb or utcnow() - datetime.fromisoformat(hb) > timedelta(minutes=3)
        except ValueError:
            stale = True
        if stale:
            warnings.append("Der Hintergrund-Worker (servermanager-worker) meldet sich nicht - Jobs und "
                            "Zeitpläne werden nicht ausgeführt. 'systemctl status servermanager-worker' prüfen.")
        if not settings.get(g.db, "general.base_url"):
            warnings.append("Die öffentliche URL ist nicht gesetzt (Einstellungen → Allgemein). Sie wird für "
                            "die Enrollment-Befehle benötigt.")
        if not settings.get(g.db, "wg.enabled"):
            warnings.append("Das WireGuard-Management-Netz ist noch nicht eingerichtet (Menü WireGuard). "
                            "Systeme können bis dahin nur direkt per SSH verwaltet werden.")
    int_alerts = []
    from ... import integrations
    endpoints = {"pve": "pve.server", "router": "routers.detail", "pangolin": "pangolin.detail",
                 "mailcow": "mailcow.detail", "sso": "sso.detail", "pbx": "pbx.detail",
                 "zabbix": "zabbix.detail", "ispconfig": "ispc.detail"}
    params = {"pve": "pve_id", "router": "router_id", "pangolin": "pg_id", "mailcow": "mc_id", "sso": "sso_id",
              "pbx": "pbx_id", "zabbix": "zid", "ispconfig": "isp_id"}
    for kind, model in integrations.MODELS.items():
        levels = access.integration_levels(g.db, g.user, kind)
        for obj in g.db.execute(select(model).order_by(model.name)).scalars():
            if levels is not None and obj.id not in levels:
                continue
            for a in obj.alert_list:
                int_alerts.append({"name": obj.name, "text": a["text"], "severity": a["severity"],
                                   "since": a.get("since"),
                                   "url": url_for(endpoints[kind], **{params[kind]: obj.id})})
    return render_template("dashboard.html", stats=stats, problems=problems, jobs=jobs, running=running,
                           failed=failed, upcoming=upcoming, warnings=warnings, int_alerts=int_alerts)


# --------------------------------------------------------------------------
# profile
# --------------------------------------------------------------------------
@bp.get("/profile")
@login_required
def profile():
    totp_svg = None
    secret = session.get("totp_setup")
    if secret and not g.user.totp_enabled:
        buf = io.BytesIO()
        segno.make(security.totp_uri(secret, g.user.username, settings.get(g.db, "general.site_name")),
                   micro=False).save(buf, kind="svg", scale=5, border=2)
        totp_svg = buf.getvalue().decode()
    return render_template("profile.html", totp_svg=totp_svg, totp_secret=secret)


@bp.post("/profile/password")
@login_required
def change_password():
    user = g.user
    current = request.form.get("current", "")
    new = request.form.get("new", "")
    if not security.verify_password(user.password_hash, current):
        flash("Das aktuelle Passwort ist falsch.", "danger")
        return redirect(url_for("main.profile"))
    if new != request.form.get("confirm", ""):
        flash("Die neuen Passwörter stimmen nicht überein.", "danger")
        return redirect(url_for("main.profile"))
    problems = security.password_problems(new)
    if problems:
        for p in problems:
            flash(p, "danger")
        return redirect(url_for("main.profile"))
    user.password_hash = security.hash_password(new)
    user.must_change_password = False
    user.auth_version += 1
    session["av"] = user.auth_version
    audit(g.db, user, "user.password_changed", user.username, ip=client_ip())
    g.db.commit()
    flash("Passwort geändert.", "success")
    return redirect(url_for("main.profile"))


@bp.post("/profile/2fa/setup")
@login_required
def totp_setup():
    if g.user.totp_enabled:
        abort(400)
    session["totp_setup"] = security.new_totp_secret()
    return redirect(url_for("main.profile") + "#2fa")


@bp.post("/profile/2fa/enable")
@login_required
def totp_enable():
    secret = session.get("totp_setup")
    if not secret:
        return redirect(url_for("main.profile"))
    if not security.verify_totp(secret, request.form.get("code", "")):
        flash("Der Code ist ungültig - bitte erneut versuchen.", "danger")
        return redirect(url_for("main.profile") + "#2fa")
    g.user.totp_secret_enc = security.encrypt(secret)
    g.user.totp_enabled = True
    session.pop("totp_setup", None)
    audit(g.db, g.user, "user.2fa_enabled", g.user.username, ip=client_ip())
    g.db.commit()
    flash("Zwei-Faktor-Anmeldung aktiviert.", "success")
    return redirect(url_for("main.profile"))


@bp.post("/profile/2fa/disable")
@login_required
def totp_disable():
    if not security.verify_password(g.user.password_hash, request.form.get("password", "")):
        flash("Passwort falsch.", "danger")
        return redirect(url_for("main.profile"))
    g.user.totp_enabled = False
    g.user.totp_secret_enc = None
    audit(g.db, g.user, "user.2fa_disabled", g.user.username, ip=client_ip())
    g.db.commit()
    flash("Zwei-Faktor-Anmeldung deaktiviert.", "warning")
    return redirect(url_for("main.profile"))


# --------------------------------------------------------------------------
# audit
# --------------------------------------------------------------------------
@bp.get("/audit")
@admin_required
def audit_log():
    q = select(AuditLog).order_by(AuditLog.id.desc())
    term = request.args.get("q", "").strip()
    if term:
        like = f"%{term}%"
        q = q.where(AuditLog.action.like(like) | AuditLog.username.like(like) | AuditLog.target.like(like)
                    | AuditLog.details.like(like))
    entries = g.db.execute(q.limit(500)).scalars().all()
    return render_template("audit.html", entries=entries, q=term)
