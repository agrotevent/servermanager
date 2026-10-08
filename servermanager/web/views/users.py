"""User management (admins only)."""
from __future__ import annotations

import re

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from sqlalchemy import func, select

from ... import security
from ...core import audit
from ...integrations import ACCESS_MODELS as INTEGRATION_MODELS
from ...models import (ALL_OBJECTS, INTEGRATION_KINDS, KIND_SYSTEM, LEVELS, ROLE_ADMIN, ROLES, GroupRight,
                       IntegrationAccess, System, SystemAccess, User, UserGroup, UserGroupMember)
from ..auth import admin_required, client_ip

bp = Blueprint("users", __name__, url_prefix="/users")
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{1,63}$")
GROUP_NAME_RE = re.compile(r"^[^\x00-\x1f]{1,128}$")


@bp.get("/")
@admin_required
def index():
    users = g.db.execute(select(User).order_by(User.username)).scalars().all()
    counts = dict(g.db.execute(select(SystemAccess.user_id, func.count()).group_by(SystemAccess.user_id)).all())
    groups = g.db.execute(select(UserGroup).order_by(UserGroup.name)).scalars().all()
    members = dict(g.db.execute(select(UserGroupMember.group_id, func.count()).group_by(UserGroupMember.group_id)).all())
    rights = dict(g.db.execute(select(GroupRight.group_id, func.count()).group_by(GroupRight.group_id)).all())
    by_user: dict[int, list[str]] = {}
    names = {grp.id: grp.name for grp in groups}
    for uid, gid in g.db.execute(select(UserGroupMember.user_id, UserGroupMember.group_id)).all():
        by_user.setdefault(uid, []).append(names.get(gid, "?"))
    for u in users:
        sso = {x.lower() for x in (u.sso_groups or [])}
        by_user.setdefault(u.id, []).extend(f"{grp.name} (authentik)" for grp in groups
                                            if grp.sso_group and grp.sso_group.lower() in sso)
    return render_template("users/index.html", users=users, counts=counts, groups=groups, members=members,
                           rights=rights, by_user=by_user, ak_groups=_ak_groups(), mapped={
                               (grp.sso_group or "").lower() for grp in groups})


def _ak_groups() -> list[str]:
    """Group names of the authentik used for the login (suggestions; empty if not reachable)."""
    from ... import integrations, sso_login
    from ...authentik import AuthentikError
    try:
        conf = sso_login.active(g.db)
        if conf is None:
            return []
        return sorted({str(x.get("name") or "") for x in integrations.sso_client(conf[0], timeout=5).groups()} - {""},
                      key=str.lower)
    except (AuthentikError, ValueError):
        return []


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


def _integration_objects() -> list[tuple[str, str, list]]:
    """Kinds with their objects; hidden modules only while they still have objects (rights stay editable)."""
    from ... import settings
    hidden = settings.hidden_kinds(g.db)
    out = []
    for kind, model in INTEGRATION_MODELS.items():
        objs = g.db.execute(select(model).order_by(model.name)).scalars().all()
        if kind not in hidden or objs:
            out.append((kind, INTEGRATION_KINDS[kind], objs))
    return out


def _integration_levels(user: User) -> dict[str, str]:
    if user.id is None:
        return {}
    return {f"{a.kind}_{a.obj_id}": a.level for a in g.db.execute(
        select(IntegrationAccess).where(IntegrationAccess.user_id == user.id)).scalars()}


def _save_integration_access(user: User) -> None:
    rows = {(a.kind, a.obj_id): a for a in g.db.execute(
        select(IntegrationAccess).where(IntegrationAccess.user_id == user.id)).scalars()}
    for kind, _label, objs in _integration_objects():
        for obj in objs:
            level = request.form.get(f"int_{kind}_{obj.id}", "")
            row = rows.get((kind, obj.id))
            if level in LEVELS:
                if row:
                    row.level = level
                else:
                    g.db.add(IntegrationAccess(user_id=user.id, kind=kind, obj_id=obj.id, level=level))
            elif row:
                g.db.delete(row)


def _save_user_groups(user: User) -> None:
    if "groups_shown" not in request.form:
        return
    wanted = {int(x) for x in request.form.getlist("groups") if x.isdigit()}
    current = {m.group_id: m for m in g.db.execute(select(UserGroupMember).where(
        UserGroupMember.user_id == user.id)).scalars()}
    valid = {r[0] for r in g.db.execute(select(UserGroup.id)).all()}
    for gid in (wanted & valid) - set(current):
        g.db.add(UserGroupMember(user_id=user.id, group_id=gid))
    for gid, row in current.items():
        if gid not in wanted:
            g.db.delete(row)


def _user_groups_ctx(user: User) -> dict:
    groups = g.db.execute(select(UserGroup).order_by(UserGroup.name)).scalars().all()
    member = set() if user.id is None else {r[0] for r in g.db.execute(select(UserGroupMember.group_id).where(
        UserGroupMember.user_id == user.id)).all()}
    sso = {x.lower() for x in (user.sso_groups or [])}
    return {"all_groups": groups, "member_of": member,
            "sso_member_of": {grp.id for grp in groups if grp.sso_group and grp.sso_group.lower() in sso}}


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
            return render_template("users/form.html", u=user, is_new=True, systems=systems, levels_by_system={},
                                   integrations=_integration_objects(), int_levels={}, **_user_groups_ctx(user))
        g.db.add(user)
        g.db.flush()
        _save_access(user)
        _save_integration_access(user)
        _save_user_groups(user)
        audit(g.db, g.user, "user.create", user.username, user.role, ip=client_ip())
        g.db.commit()
        flash(f"Benutzer '{user.username}' angelegt.", "success")
        return redirect(url_for("users.index"))
    return render_template("users/form.html", u=user, is_new=True, systems=systems, levels_by_system={},
                           integrations=_integration_objects(), int_levels={}, **_user_groups_ctx(user))


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
        _save_integration_access(user)
        _save_user_groups(user)
        audit(g.db, g.user, "user.update", user.username, user.role, ip=client_ip())
        g.db.commit()
        flash("Benutzer gespeichert.", "success")
        return redirect(url_for("users.index"))
    return render_template("users/form.html", u=user, is_new=False, systems=systems,
                           levels_by_system=levels_by_system, integrations=_integration_objects(),
                           int_levels=_integration_levels(user), **_user_groups_ctx(user))


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



# --------------------------------------------------------------------------
# groups
# --------------------------------------------------------------------------
def _group_targets() -> list[tuple[str, str, list]]:
    """(kind, label, objects) – systems first, then the modules."""
    systems = g.db.execute(select(System).order_by(System.name)).scalars().all()
    return [(KIND_SYSTEM, "Systeme", systems)] + _integration_objects()


def _save_group(grp: UserGroup) -> list[str]:
    f = request.form
    errors = []
    name = (f.get("name") or "").strip()
    if not GROUP_NAME_RE.match(name):
        errors.append("Bitte einen Namen angeben.")
    elif g.db.execute(select(UserGroup.id).where(func.lower(UserGroup.name) == name.lower(),
                                                 UserGroup.id != (grp.id or 0))).first():
        errors.append("Eine Gruppe mit diesem Namen gibt es schon.")
    grp.name = name[:128]
    grp.description = (f.get("description") or "").strip()[:2000]
    sso = (f.get("sso_group") or "").strip()
    if sso and not GROUP_NAME_RE.match(sso):
        errors.append("Ungültiger Name der authentik-Gruppe.")
    elif sso and g.db.execute(select(UserGroup.id).where(func.lower(UserGroup.sso_group) == sso.lower(),
                                                         UserGroup.id != (grp.id or 0))).first():
        errors.append("Diese authentik-Gruppe ist schon einer anderen Gruppe zugeordnet.")
    grp.sso_group = sso[:150]
    return errors


def _save_group_members(grp: UserGroup) -> None:
    wanted = {int(x) for x in request.form.getlist("members") if x.isdigit()}
    current = {m.user_id: m for m in g.db.execute(select(UserGroupMember).where(
        UserGroupMember.group_id == grp.id)).scalars()}
    valid = {r[0] for r in g.db.execute(select(User.id)).all()}
    for uid in wanted - set(current):
        if uid in valid:
            g.db.add(UserGroupMember(user_id=uid, group_id=grp.id))
    for uid, row in current.items():
        if uid not in wanted:
            g.db.delete(row)


def _save_group_rights(grp: UserGroup) -> None:
    rows = {(r.kind, r.obj_id): r for r in g.db.execute(select(GroupRight).where(GroupRight.group_id == grp.id)).scalars()}
    for kind, _label, objs in _group_targets():
        for obj_id in [ALL_OBJECTS] + [o.id for o in objs]:
            level = request.form.get(f"r_{kind}_{obj_id}", "")
            row = rows.get((kind, obj_id))
            if level in LEVELS:
                if row:
                    row.level = level
                else:
                    g.db.add(GroupRight(group_id=grp.id, kind=kind, obj_id=obj_id, level=level))
            elif row:
                g.db.delete(row)


def _group_form(grp: UserGroup, is_new: bool):
    users = g.db.execute(select(User).order_by(User.username)).scalars().all()
    members = set() if is_new else {r[0] for r in g.db.execute(select(UserGroupMember.user_id).where(
        UserGroupMember.group_id == grp.id)).all()}
    levels = {} if is_new else {f"{r.kind}_{r.obj_id}": r.level for r in g.db.execute(
        select(GroupRight).where(GroupRight.group_id == grp.id)).scalars()}
    via_sso = [u for u in users if grp.sso_group and grp.sso_group.lower() in {x.lower() for x in (u.sso_groups or [])}]
    return render_template("users/group_form.html", grp=grp, is_new=is_new, users=users, members=members,
                           levels=levels, targets=_group_targets(), ak_groups=_ak_groups(), via_sso=via_sso)


@bp.route("/groups/new", methods=["GET", "POST"])
@admin_required
def group_new():
    grp = UserGroup(name=request.args.get("sso_group", ""), sso_group=request.args.get("sso_group", ""))
    if request.method == "POST":
        errors = _save_group(grp)
        if errors:
            for e in errors:
                flash(e, "danger")
            return _group_form(grp, True)
        g.db.add(grp)
        g.db.flush()
        _save_group_members(grp)
        _save_group_rights(grp)
        audit(g.db, g.user, "group.create", grp.name, grp.sso_group, ip=client_ip())
        g.db.commit()
        flash(f"Gruppe „{grp.name}“ angelegt.", "success")
        return redirect(url_for("users.index") + "#groups")
    return _group_form(grp, True)


@bp.route("/groups/<int:group_id>", methods=["GET", "POST"])
@admin_required
def group_edit(group_id: int):
    grp = g.db.get(UserGroup, group_id)
    if grp is None:
        abort(404)
    if request.method == "POST":
        errors = _save_group(grp)
        if errors:
            g.db.rollback()
            for e in errors:
                flash(e, "danger")
            return redirect(url_for("users.group_edit", group_id=group_id))
        _save_group_members(grp)
        _save_group_rights(grp)
        audit(g.db, g.user, "group.update", grp.name, grp.sso_group, ip=client_ip())
        g.db.commit()
        flash("Gruppe gespeichert.", "success")
        return redirect(url_for("users.index") + "#groups")
    return _group_form(grp, False)


@bp.post("/groups/<int:group_id>/delete")
@admin_required
def group_delete(group_id: int):
    grp = g.db.get(UserGroup, group_id)
    if grp is None:
        abort(404)
    name = grp.name
    for model in (GroupRight, UserGroupMember):
        for row in g.db.execute(select(model).where(model.group_id == grp.id)).scalars():
            g.db.delete(row)
    g.db.delete(grp)
    audit(g.db, g.user, "group.delete", name, ip=client_ip())
    g.db.commit()
    flash(f"Gruppe „{name}“ gelöscht.", "warning")
    return redirect(url_for("users.index") + "#groups")
