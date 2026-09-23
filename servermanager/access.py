"""Permission logic: global roles + per system access levels."""
from __future__ import annotations

from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import LEVEL_FULL, LEVEL_ORDER, Job, System, SystemAccess, User


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
