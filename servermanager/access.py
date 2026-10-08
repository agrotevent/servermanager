"""Permission logic: global roles + per system access levels."""
from __future__ import annotations

from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import (ALL_OBJECTS, INTEGRATION_KINDS, KIND_PVE, KIND_SYSTEM, LEVEL_FULL, LEVEL_ORDER, GroupRight,
                     IntegrationAccess, Job, System, SystemAccess, User, UserGroup, UserGroupMember)


def _higher(a: Optional[str], b: Optional[str]) -> Optional[str]:
    if not a or not b:
        return a or b
    return a if LEVEL_ORDER[a] >= LEVEL_ORDER[b] else b


# --------------------------------------------------------------------------
# groups: members by hand or through the authentik group of the last SSO login
# --------------------------------------------------------------------------
def user_groups(user: User) -> list[str]:
    """authentik groups of the user's last SSO login (lower case)."""
    return sorted({str(x).lower() for x in (user.sso_groups or []) if str(x).strip()})


def group_ids(db: Session, user: Optional[User]) -> set[int]:
    if user is None or not user.id:
        return set()
    cache = _request_cache()
    key = ("groups", user.id)
    if cache is not None and key in cache:
        return cache[key]
    ids = {r[0] for r in db.execute(select(UserGroupMember.group_id).where(UserGroupMember.user_id == user.id)).all()}
    sso = user_groups(user)
    if sso:
        ids |= {r[0] for r in db.execute(select(UserGroup.id).where(UserGroup.sso_group != "",
                                                                    func.lower(UserGroup.sso_group).in_(sso))).all()}
    if cache is not None:
        cache[key] = ids
    return ids


def _request_cache() -> Optional[dict]:
    try:
        from flask import g, has_request_context
    except ImportError:  # pragma: no cover
        return None
    if not has_request_context():
        return None
    return g.setdefault("_access_cache", {})


def _all_ids(db: Session, kind: str) -> list[int]:
    if kind == KIND_SYSTEM:
        return [r[0] for r in db.execute(select(System.id)).all()]
    from .integrations import ACCESS_MODELS
    model = ACCESS_MODELS.get(kind)
    return [r[0] for r in db.execute(select(model.id)).all()] if model is not None else []


def group_levels(db: Session, user: User, kind: str) -> dict[int, str]:
    """obj_id -> highest level the user's groups give on objects of ``kind`` ("all" expanded)."""
    ids = group_ids(db, user)
    if not ids:
        return {}
    out: dict[int, str] = {}
    rows = db.execute(select(GroupRight.obj_id, GroupRight.level).where(GroupRight.group_id.in_(ids),
                                                                        GroupRight.kind == kind)).all()
    for oid, lv in rows:
        targets = _all_ids(db, kind) if oid == ALL_OBJECTS else [oid]
        for t in targets:
            out[t] = _higher(out.get(t), lv)
    return out


def group_level(db: Session, user: User, kind: str, obj_id: int) -> Optional[str]:
    ids = group_ids(db, user)
    if not ids:
        return None
    best = None
    for (lv,) in db.execute(select(GroupRight.level).where(GroupRight.group_id.in_(ids), GroupRight.kind == kind,
                                                            GroupRight.obj_id.in_([obj_id, ALL_OBJECTS]))).all():
        best = _higher(best, lv)
    return best


def remove_rights(db: Session, kind: str, obj_id: int) -> None:
    """Group rights on an object that is deleted."""
    for row in db.execute(select(GroupRight).where(GroupRight.kind == kind, GroupRight.obj_id == obj_id)).scalars():
        db.delete(row)


# --------------------------------------------------------------------------
# systems
# --------------------------------------------------------------------------
def system_level(db: Session, user: Optional[User], system_id: int) -> Optional[str]:
    if user is None or not user.active:
        return None
    if user.is_admin:
        return LEVEL_FULL
    row = db.execute(select(SystemAccess.level).where(SystemAccess.user_id == user.id,
                                                      SystemAccess.system_id == system_id)).first()
    return _higher(row[0] if row else None, group_level(db, user, KIND_SYSTEM, system_id))


def has_level(db: Session, user: Optional[User], system_id: int, level: str) -> bool:
    current = system_level(db, user, system_id)
    return bool(current) and LEVEL_ORDER[current] >= LEVEL_ORDER[level]


def accessible_system_ids(db: Session, user: User) -> Optional[set[int]]:
    """None means: all systems (admin)."""
    if user.is_admin:
        return None
    return set(levels_map(db, user))


def accessible_systems(db: Session, user: User, min_level: Optional[str] = None) -> list[System]:
    q = select(System).order_by(System.name)
    if not user.is_admin:
        levels = levels_map(db, user)
        if min_level:
            levels = {sid: lv for sid, lv in levels.items() if LEVEL_ORDER[lv] >= LEVEL_ORDER[min_level]}
        if not levels:
            return []
        q = q.where(System.id.in_(list(levels)))
    return list(db.execute(q).scalars().all())


def levels_map(db: Session, user: User) -> dict[int, str]:
    if user.is_admin:
        return {sid: LEVEL_FULL for (sid,) in db.execute(select(System.id)).all()}
    rows = db.execute(select(SystemAccess.system_id, SystemAccess.level)
                      .where(SystemAccess.user_id == user.id)).all()
    out = {sid: lv for sid, lv in rows}
    for sid, lv in group_levels(db, user, KIND_SYSTEM).items():
        out[sid] = _higher(out.get(sid), lv)
    return out


def can_view_job(db: Session, user: User, job: Job) -> bool:
    if user.is_admin:
        return True
    if job.pve_id is not None and integration_level(db, user, KIND_PVE, job.pve_id) is not None:
        return True
    if job.system_id is None:
        return job.user_id == user.id
    return system_level(db, user, job.system_id) is not None


def grant(db: Session, user_id: int, system_id: int, level: str) -> None:
    row = db.execute(select(SystemAccess).where(SystemAccess.user_id == user_id,
                                                SystemAccess.system_id == system_id)).scalar_one_or_none()
    if row is None:
        db.add(SystemAccess(user_id=user_id, system_id=system_id, level=level))
    elif LEVEL_ORDER[level] > LEVEL_ORDER[row.level]:
        row.level = level


# --------------------------------------------------------------------------
# integrations (Proxmox API, RouterOS, Pangolin)
# --------------------------------------------------------------------------
def integration_level(db: Session, user: Optional[User], kind: str, obj_id: int) -> Optional[str]:
    """Own right or right through a group – the higher one counts."""
    if user is None or not user.active or kind not in INTEGRATION_KINDS:
        return None
    if user.is_admin:
        return LEVEL_FULL
    row = db.execute(select(IntegrationAccess.level).where(
        IntegrationAccess.user_id == user.id, IntegrationAccess.kind == kind,
        IntegrationAccess.obj_id == obj_id)).first()
    return _higher(row[0] if row else None, group_level(db, user, kind, obj_id))


def has_integration_level(db: Session, user: Optional[User], kind: str, obj_id: int, level: str) -> bool:
    current = integration_level(db, user, kind, obj_id)
    return bool(current) and LEVEL_ORDER[current] >= LEVEL_ORDER[level]


def integration_levels(db: Session, user: User, kind: str) -> Optional[dict[int, str]]:
    """obj_id -> level of the user; None means: all (admin)."""
    if user.is_admin:
        return None
    rows = db.execute(select(IntegrationAccess.obj_id, IntegrationAccess.level).where(
        IntegrationAccess.user_id == user.id, IntegrationAccess.kind == kind)).all()
    out = {oid: lv for oid, lv in rows}
    for oid, lv in group_levels(db, user, kind).items():
        out[oid] = _higher(out.get(oid), lv)
    return out


def any_integration_access(db: Session, user: User) -> set[str]:
    """Kinds of integrations the user can see at all (for the navigation)."""
    if user.is_admin:
        return set(INTEGRATION_KINDS)
    rows = db.execute(select(IntegrationAccess.kind).where(IntegrationAccess.user_id == user.id).distinct()).all()
    kinds = {r[0] for r in rows}
    ids = group_ids(db, user)
    if ids:
        kinds |= {r[0] for r in db.execute(select(GroupRight.kind).where(GroupRight.group_id.in_(ids)).distinct()).all()
                  if r[0] in INTEGRATION_KINDS}
    return kinds


def remove_integration(db: Session, kind: str, obj_id: int) -> None:
    for row in db.execute(select(IntegrationAccess).where(IntegrationAccess.kind == kind,
                                                          IntegrationAccess.obj_id == obj_id)).scalars():
        db.delete(row)
    remove_rights(db, kind, obj_id)


# --------------------------------------------------------------------------
# Hetzner: rights on the whole Robot account or on single root servers (the higher one counts)
# --------------------------------------------------------------------------
def hetzner_server_level(db: Session, user: Optional[User], server) -> Optional[str]:
    from .models import KIND_HETZNER, KIND_HETZNER_SRV
    levels = [lv for lv in (integration_level(db, user, KIND_HETZNER, server.account_id),
                            integration_level(db, user, KIND_HETZNER_SRV, server.id)) if lv]
    return max(levels, key=lambda lv: LEVEL_ORDER[lv]) if levels else None


def has_hetzner_level(db: Session, user: Optional[User], server, level: str) -> bool:
    current = hetzner_server_level(db, user, server)
    return bool(current) and LEVEL_ORDER[current] >= LEVEL_ORDER[level]


def hcloud_server_level(db: Session, user: Optional[User], server) -> Optional[str]:
    """Hetzner Cloud: rights on the project or on the single server (the higher one counts)."""
    from .models import KIND_HCLOUD, KIND_HCLOUD_SRV
    levels = [lv for lv in (integration_level(db, user, KIND_HCLOUD, server.project_id),
                            integration_level(db, user, KIND_HCLOUD_SRV, server.id)) if lv]
    return max(levels, key=lambda lv: LEVEL_ORDER[lv]) if levels else None


def has_hcloud_level(db: Session, user: Optional[User], server, level: str) -> bool:
    current = hcloud_server_level(db, user, server)
    return bool(current) and LEVEL_ORDER[current] >= LEVEL_ORDER[level]
