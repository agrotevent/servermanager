"""Nextcloud user management (occ via SSH, synchronous)."""
from __future__ import annotations

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from sqlalchemy import select

from ... import inventory, security
from ...core import audit
from ...models import LEVEL_FULL, LEVEL_OPERATE, LEVEL_VIEW, SsoClient
from ...modules.nextcloud import occ_task, parse_users, validate_user
from ...ssh import SSHError
from ..auth import can, client_ip, get_system_or_403, login_required

bp = Blueprint("ncusers", __name__, url_prefix="/systems")

ACTIONS = {"add": LEVEL_FULL, "delete": LEVEL_FULL, "disable": LEVEL_OPERATE, "enable": LEVEL_OPERATE,
           "resetpw": LEVEL_FULL, "quota": LEVEL_OPERATE}


@bp.get("/<int:system_id>/nextcloud/users")
@login_required
def users(system_id: int):
    system = get_system_or_403(system_id, LEVEL_VIEW)
    if not system.has_type("nextcloud"):
        abort(404)
    users_, groups, error = [], [], None
    try:
        with inventory.connect(system) as conn:
            users_, groups = parse_users(occ_task(conn, system, "user_list", timeout=120))
    except (SSHError, OSError) as exc:
        error = str(exc)
    sso = g.db.execute(select(SsoClient).where(SsoClient.target_kind == "nextcloud",
                                               SsoClient.target_id == system.id)).scalars().first()
    from ...models import KIND_SSO, SsoServer
    from . import _integration as common
    sso_servers = [x for x in g.db.execute(select(SsoServer).order_by(SsoServer.name)).scalars()
                   if common.can(KIND_SSO, x.id, LEVEL_FULL)]
    return render_template("nextcloud/users.html", system=system, users=users_, groups=groups, error=error,
                           sso=sso, sso_servers=sso_servers)


@bp.post("/<int:system_id>/nextcloud/users")
@login_required
def action(system_id: int):
    op = request.form.get("op", "")
    if op not in ACTIONS:
        abort(400)
    system = get_system_or_403(system_id, ACTIONS[op])
    if not system.has_type("nextcloud"):
        abort(404)
    f = request.form
    password = ""
    try:
        env = validate_user(f.get("uid", "").strip(), f.get("email", "").strip(), f.get("groups", ""),
                            f.get("quota", ""))
        if op in ("add", "resetpw"):
            password = f.get("password") or security.generate_password()
            if len(password) < 10:
                raise ValueError("Passwort mindestens 10 Zeichen")
            env["SM_NC_PASSWORD"] = password
        if op == "add":
            env["SM_DISPLAY"] = f.get("display", "").strip()[:100]
        task = {"add": "user_add", "delete": "user_delete", "disable": "user_disable", "enable": "user_enable",
                "resetpw": "user_resetpw", "quota": "user_quota"}[op]
        with inventory.connect(system) as conn:
            out = occ_task(conn, system, task, env, timeout=120)
        if "SM_OK" not in out:
            raise ValueError(out.strip()[-300:] or "Nextcloud meldet keinen Erfolg")
        audit(g.db, g.user, f"nextcloud.user_{op}", system.name, env["SM_UID"], ip=client_ip())
        g.db.commit()
        msg = {"add": "angelegt", "delete": "gelöscht", "disable": "gesperrt", "enable": "entsperrt",
               "resetpw": "Passwort gesetzt", "quota": "Quota gesetzt"}[op]
        flash(f"{env['SM_UID']}: {msg}." + (f" Passwort (wird nur jetzt angezeigt): {password}"
                                            if password and not f.get("password") else ""), "success")
    except (ValueError, SSHError, OSError) as exc:
        flash(f"Fehlgeschlagen: {exc}", "danger")
    return redirect(url_for("ncusers.users", system_id=system_id))


@bp.app_context_processor
def _ctx():
    return {"nc_can_users": lambda s: s.has_type("nextcloud") and can(s.id, LEVEL_VIEW)}
