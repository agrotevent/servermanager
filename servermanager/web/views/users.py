"""User management (admins only)."""
from __future__ import annotations

import re

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from sqlalchemy import func, select

from ... import security
from ...core import audit
from ...models import LEVELS, ROLE_ADMIN, ROLES, System, SystemAccess, User
from ..auth import admin_required, client_ip

bp = Blueprint("users", __name__, url_prefix="/users")
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{1,63}$")


@bp.get("/")
@admin_required
def index():
    users = g.db.execute(select(User).order_by(User.username)).scalars().all()
    counts = dict(g.db.execute(select(SystemAccess.user_id, func.count()).group_by(SystemAccess.user_id)).all())
    return render_template("users/index.html", users=users, counts=counts)


def _admins_left(exclude_id: int) -> int:
    return g.db.execute(select(func.count()).select_from(User).where(
        User.role == ROLE_ADMIN, User.active.is_(True), User.id != exclude_id)).scalar_one()


def _save(user: User, is_new: bool):
    f = request.form
    errors = []
    username = f.get("username", "").strip()
    if is_new:
        if not USERNAME_RE.match(username):
            errors.append("Ungültiger Benutzername (2-64 Zeichen: Buchstaben, Ziffern, . _ @ -).")
        elif g.db.execute(select(User.id).where(func.lower(User.username) == username.lower())).first():
            errors.append("Der Benutzername ist bereits vergeben.")
        user.username = username
    user.display_name = f.get("display_name", "").strip()[:128]
    user.email = f.get("email", "").strip()[:255]
    role = f.get("role", "user")
    new_role = role if role in ROLES else "user"
    active = bool(f.get("active"))
    if not is_new and user.id == g.user.id and (new_role != ROLE_ADMIN or not active):
        errors.append("Sie können sich nicht selbst die Administratorrechte entziehen oder sich deaktivieren.")
    if not is_new and user.role == ROLE_ADMIN and (new_role != ROLE_ADMIN or not active) and _admins_left(user.id) == 0:
        errors.append("Es muss mindestens ein aktiver Administrator bestehen bleiben.")
    user.role = new_role
    user.active = active
    pw = f.get("password", "")
    if pw:
        problems = security.password_problems(pw)
        errors.extend(problems)
        if not problems:
            user.password_hash = security.hash_password(pw)
            user.auth_version = (user.auth_version or 1) + 1
            user.must_change_password = bool(f.get("must_change"))
    elif is_new:
        errors.append("Bitte ein Passwort vergeben.")
    return errors


def _save_access(user: User) -> None:
    rows = {a.system_id: a for a in g.db.execute(select(SystemAccess).where(SystemAccess.user_id == user.id)).scalars()}
    for system in g.db.execute(select(System)).scalars():
        level = request.form.get(f"sys_{system.id}", "")
        if level in LEVELS:
            if system.id in rows:
                rows[system.id].level = level
            else:
                g.db.add(SystemAccess(user_id=user.id, system_id=system.id, level=level))
        elif system.id in rows:
            g.db.delete(rows[system.id])


@bp.route("/new", methods=["GET", "POST"])
@admin_required
def new():
    user = User(role="user", active=True, must_change_password=True)
    systems = g.db.execute(select(System).order_by(System.name)).scalars().all()
    if request.method == "POST":
        errors = _save(user, True)
        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("users/form.html", u=user, is_new=True, systems=systems, levels_by_system={})
        g.db.add(user)
        g.db.flush()
        _save_access(user)
        audit(g.db, g.user, "user.create", user.username, user.role, ip=client_ip())
        g.db.commit()
        flash(f"Benutzer '{user.username}' angelegt.", "success")
        return redirect(url_for("users.index"))
    return render_template("users/form.html", u=user, is_new=True, systems=systems, levels_by_system={})


@bp.route("/<int:user_id>", methods=["GET", "POST"])
@admin_required
def edit(user_id: int):
    user = g.db.get(User, user_id)
    if user is None:
        abort(404)
    systems = g.db.execute(select(System).order_by(System.name)).scalars().all()
    levels_by_system = {a.system_id: a.level for a in user.access}
    if request.method == "POST":
        errors = _save(user, False)
        if errors:
            g.db.rollback()
            for e in errors:
                flash(e, "danger")
            return redirect(url_for("users.edit", user_id=user_id))
        _save_access(user)
        audit(g.db, g.user, "user.update", user.username, user.role, ip=client_ip())
        g.db.commit()
        flash("Benutzer gespeichert.", "success")
        return redirect(url_for("users.index"))
    return render_template("users/form.html", u=user, is_new=False, systems=systems,
                           levels_by_system=levels_by_system)


@bp.post("/<int:user_id>/reset-2fa")
@admin_required
def reset_2fa(user_id: int):
    user = g.db.get(User, user_id)
    if user is None:
        abort(404)
    user.totp_enabled = False
    user.totp_secret_enc = None
    user.auth_version += 1
    audit(g.db, g.user, "user.2fa_reset", user.username, ip=client_ip())
    g.db.commit()
    flash(f"Zwei-Faktor-Anmeldung für '{user.username}' zurückgesetzt.", "warning")
    return redirect(url_for("users.edit", user_id=user.id))


@bp.post("/<int:user_id>/unlock")
@admin_required
def unlock(user_id: int):
    user = g.db.get(User, user_id)
    if user is None:
        abort(404)
    user.locked_until = None
    user.failed_logins = 0
    g.db.commit()
    flash("Konto entsperrt.", "success")
    return redirect(url_for("users.edit", user_id=user.id))


@bp.post("/<int:user_id>/delete")
@admin_required
def delete(user_id: int):
    user = g.db.get(User, user_id)
    if user is None:
        abort(404)
    if user.id == g.user.id:
        flash("Sie können sich nicht selbst löschen.", "danger")
        return redirect(url_for("users.index"))
    if user.role == ROLE_ADMIN and _admins_left(user.id) == 0:
        flash("Der letzte Administrator kann nicht gelöscht werden.", "danger")
        return redirect(url_for("users.index"))
    name = user.username
    g.db.delete(user)
    audit(g.db, g.user, "user.delete", name, ip=client_ip())
    g.db.commit()
    flash(f"Benutzer '{name}' gelöscht.", "success")
    return redirect(url_for("users.index"))
