"""Enrollment: token management (UI) and the public client API."""
from __future__ import annotations

from flask import Blueprint, Response, abort, flash, g, redirect, render_template, request, session, url_for
from sqlalchemy import select

from ... import access, enrollment, settings
from ...core import audit
from ...models import CONN_WIREGUARD, LEVELS, EnrollmentToken, System, User
from ..auth import client_ip, manager_required, record_failure, throttled

bp = Blueprint("enroll", __name__)


@bp.get("/enrollment")
@manager_required
def index():
    q = select(EnrollmentToken).order_by(EnrollmentToken.id.desc())
    if not g.user.is_admin:
        q = q.where(EnrollmentToken.created_by == g.user.id)
    tokens = g.db.execute(q.limit(100)).scalars().all()
    created = session.pop("new_token", None)
    command = enrollment.install_command(g.db, created["token"]) if created else None
    users = g.db.execute(select(User).where(User.active.is_(True)).order_by(User.username)).scalars().all() \
        if g.user.is_admin else []
    systems = g.db.execute(select(System).order_by(System.name)).scalars().all() if g.user.is_admin else []
    pq = select(System).where(System.status == "pending").order_by(System.id.desc())
    if not g.user.is_admin:
        # only systems the manager may see (e.g. enrolled with his own tokens)
        ids = access.accessible_system_ids(g.db, g.user) or set()
        pq = pq.where(System.id.in_(ids))
    pending = g.db.execute(pq).scalars().all()
    return render_template("enroll/index.html", tokens=tokens, created=created, command=command, users=users,
                           systems=systems, pending=pending, wg_enabled=settings.get(g.db, "wg.enabled"),
                           base_url=settings.base_url(g.db),
                           default_hours=settings.get(g.db, "enroll.default_valid_hours"))


@bp.post("/enrollment")
@manager_required
def create():
    f = request.form
    connection = f.get("connection", CONN_WIREGUARD)
    if connection == CONN_WIREGUARD and not settings.get(g.db, "wg.enabled"):
        flash("WireGuard ist noch nicht eingerichtet - bitte zuerst das Management-Netz konfigurieren "
              "oder 'Direkt (SSH)' wählen.", "danger")
        return redirect(url_for("enroll.index"))
    assign = []
    if g.user.is_admin:
        for u in g.db.execute(select(User)).scalars():
            lv = f.get(f"level_{u.id}", "")
            if lv in LEVELS:
                assign.append({"user_id": u.id, "level": lv})
    bind = None
    if g.user.is_admin and f.get("bind_system_id", "").isdigit():
        bind = int(f["bind_system_id"])
    try:
        token, row = enrollment.create_token(
            g.db, g.user, name=f.get("name", ""), connection=connection,
            ssh_user_mode=f.get("ssh_user_mode", "root"), types=f.getlist("types"),
            routed=f.get("routed_subnets", "") if g.user.is_admin else "", tags=f.get("tags", ""),
            assign=assign, valid_hours=int(f.get("valid_hours", "24") or 24),
            max_uses=int(f.get("max_uses", "1") or 1), bind_system_id=bind)
    except ValueError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("enroll.index"))
    audit(g.db, g.user, "enroll.token_create", row.name or row.token_hint,
          f"{row.connection}, max {row.max_uses}, bis {row.expires_at}", ip=client_ip())
    g.db.commit()
    session["new_token"] = {"token": token, "id": row.id, "name": row.name}
    return redirect(url_for("enroll.index") + "#new")


@bp.post("/enrollment/<int:token_id>/revoke")
@manager_required
def revoke(token_id: int):
    row = g.db.get(EnrollmentToken, token_id)
    if row is None:
        abort(404)
    if not g.user.is_admin and row.created_by != g.user.id:
        abort(403)
    row.revoked = True
    audit(g.db, g.user, "enroll.token_revoke", row.name or row.token_hint, ip=client_ip())
    g.db.commit()
    flash("Token widerrufen.", "success")
    return redirect(url_for("enroll.index"))


# --------------------------------------------------------------------------
# public endpoints (called by the client script)
# --------------------------------------------------------------------------
def _text(body: str, status: int = 200) -> Response:
    return Response(body, status=status, mimetype="text/plain")


@bp.get("/enroll/<token>.sh")
def script(token: str):
    ip = client_ip()
    if throttled(ip, limit=30):
        return _text("echo 'Zu viele Anfragen' >&2; exit 1\n", 429)
    row = enrollment.find_token(g.db, token)
    if row is None or not row.is_valid:
        record_failure(ip)
    body = enrollment.render_script(g.db, token, row)
    return Response(body, mimetype="text/x-shellscript",
                    headers={"Content-Disposition": "inline; filename=servermanager-enroll.sh"})


@bp.post("/api/enroll")
def api_enroll():
    ip = client_ip()
    if throttled(ip, limit=30):
        return _text("Zu viele Anfragen", 429)
    try:
        resp = enrollment.enroll(g.db, request.form.get("token", ""), request.form.to_dict(), ip)
    except enrollment.EnrollError as exc:
        g.db.rollback()
        if exc.status in (403,):
            record_failure(ip)
        audit(g.db, None, "enroll.failed", request.form.get("hostname", "")[:100], str(exc), ip=ip)
        g.db.commit()
        return _text(f"FEHLER: {exc}\n", exc.status)
    audit(g.db, None, "enroll.register", resp.get("SM_SYSTEM_NAME", ""),
          f"{resp.get('SM_CONNECTION')} {resp.get('SM_WG_ADDRESS', '')}", ip=ip)
    g.db.commit()
    return _text("".join(f"{k}={v}\n" for k, v in resp.items()))


@bp.post("/api/enroll/confirm")
def api_confirm():
    ip = client_ip()
    if throttled(ip, limit=30):
        return _text("Zu viele Anfragen", 429)
    try:
        sid = int(request.form.get("system_id", "0"))
        system = enrollment.confirm(g.db, sid, request.form.get("secret", ""), request.form.get("status", ""),
                                    request.form.get("message", ""))
    except (ValueError, enrollment.EnrollError) as exc:
        record_failure(ip)
        return _text(f"FEHLER: {exc}\n", getattr(exc, "status", 400))
    audit(g.db, None, "enroll.confirm", system.name, request.form.get("status", ""), ip=ip)
    g.db.commit()
    return _text("OK\n")
