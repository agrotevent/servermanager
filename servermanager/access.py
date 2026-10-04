"""Permission logic: global roles + per system access levels."""
from __future__ import annotations

from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import (INTEGRATION_KINDS, KIND_PVE, LEVEL_FULL, LEVEL_ORDER, IntegrationAccess, Job, System,
                     SystemAccess, User)


def system_level(db: Session, user: Optional[User], system_id: int) -> Optional[str]:
    if user is None or not user.active:
        return None
    if user.is_admin:
        return LEVEL_FULL
    row = db.execute(select(SystemAccess.level).where(SystemAccess.user_id == user.id,
                                                      SystemAccess.system_id == system_id)).first()
    return row[0] if row else None


def has_level(db: Session, user: Optional[User], system_id: int, level: str) -> bool:
    current = system_level(db, user, system_id)
    return bool(current) and LEVEL_ORDER[current] >= LEVEL_ORDER[level]


def accessible_system_ids(db: Session, user: User) -> Optional[set[int]]:
    """None means: all systems (admin)."""
    if user.is_admin:
        return None
    rows = db.execute(select(SystemAccess.system_id).where(SystemAccess.user_id == user.id)).all()
    return {r[0] for r in rows}


def accessible_systems(db: Session, user: User, min_level: Optional[str] = None) -> list[System]:
    q = select(System).order_by(System.name)
    if not user.is_admin:
        q = q.join(SystemAccess, SystemAccess.system_id == System.id).where(SystemAccess.user_id == user.id)
        if min_level:
            allowed = [lv for lv, order in LEVEL_ORDER.items() if order >= LEVEL_ORDER[min_level]]
            q = q.where(SystemAccess.level.in_(allowed))
    return list(db.execute(q).scalars().all())


def levels_map(db: Session, user: User) -> dict[int, str]:
    if user.is_admin:
        return {sid: LEVEL_FULL for (sid,) in db.execute(select(System.id)).all()}
    rows = db.execute(select(SystemAccess.system_id, SystemAccess.level)
                      .where(SystemAccess.user_id == user.id)).all()
    return {sid: lv for sid, lv in rows}


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
    if user is None or not user.active or kind not in INTEGRATION_KINDS:
        return None
    if user.is_admin:
        return LEVEL_FULL
    row = db.execute(select(IntegrationAccess.level).where(
        IntegrationAccess.user_id == user.id, IntegrationAccess.kind == kind,
        IntegrationAccess.obj_id == obj_id)).first()
    return row[0] if row else None


def has_integration_level(db: Session, user: Optional[User], kind: str, obj_id: int, level: str) -> bool:
    current = integration_level(db, user, kind, obj_id)
    return bool(current) and LEVEL_ORDER[current] >= LEVEL_ORDER[level]


def integration_levels(db: Session, user: User, kind: str) -> Optional[dict[int, str]]:
    """obj_id -> level of the user; None means: all (admin)."""
    if user.is_admin:
        return None
    rows = db.execute(select(IntegrationAccess.obj_id, IntegrationAccess.level).where(
        IntegrationAccess.user_id == user.id, IntegrationAccess.kind == kind)).all()
    return {oid: lv for oid, lv in rows}


def any_integration_access(db: Session, user: User) -> set[str]:
    """Kinds of integrations the user can see at all (for the navigation)."""
    if user.is_admin:
        return set(INTEGRATION_KINDS)
    rows = db.execute(select(IntegrationAccess.kind).where(IntegrationAccess.user_id == user.id).distinct()).all()
    return {r[0] for r in rows}


def remove_integration(db: Session, kind: str, obj_id: int) -> None:
    for row in db.execute(select(IntegrationAccess).where(IntegrationAccess.kind == kind,
                                                          IntegrationAccess.obj_id == obj_id)).scalars():
        db.delete(row)


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
