"""Job queue helpers used by the web app (enqueue, logs, cancel)."""
from __future__ import annotations

import codecs
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from sqlalchemy import update
from sqlalchemy.orm import Session

from .config import get_config
from .models import JOB_QUEUED, JOB_CANCELLED, Job, System, User, utcnow

KIND_LABELS = {
    "action": "Aktion",
    "maintenance": "Wartung",
    "command": "Befehl",
    "check": "Update-Prüfung",
    "backup": "Konfig-Backup",
    "restore": "Konfig-Restore",
    "deploy_key": "SSH-Schlüssel installieren",
    "enroll_verify": "Enrollment-Prüfung",
    "sm_backup": "Servermanager-Backup",
    "pve": "Proxmox",
    "pve_create": "Container anlegen",
    "pve_token": "Proxmox-Token einrichten",
    "pve_import": "Bestand übernehmen",
    "optimize_scan": "Optimierungs-Scan",
    "optimize": "Optimierungen umsetzen",
    "newt_setup": "Newt einrichten",
    "sso_connect": "SSO verbinden",
    "sso_disconnect": "SSO trennen",
}


def log_path(job_id: int) -> Path:
    return get_config().jobs_dir / f"{job_id}.log"


def new_batch_id() -> str:
    return uuid.uuid4().hex[:12]


def enqueue(db: Session, *, kind: str, title: str, system: Optional[System] = None, user: Optional[User] = None,
            payload: Optional[dict] = None, batch_id: str = "", run_id: Optional[int] = None,
            not_after: Optional[datetime] = None, pve_id: Optional[int] = None) -> Job:
    job = Job(kind=kind, title=title[:255], system_id=system.id if system else None, pve_id=pve_id,
              user_id=user.id if user else None, payload=payload or {}, batch_id=batch_id,
              run_id=run_id, not_after=not_after, status=JOB_QUEUED, created_at=utcnow())
    db.add(job)
    db.flush()
    return job


def read_log(job_id: int, offset: int = 0, limit: int = 256 * 1024) -> tuple[str, int]:
    p = log_path(job_id)
    if not p.exists():
        return "", offset
    with p.open("rb") as fh:
        fh.seek(max(0, offset))
        data = fh.read(limit)
    # do not cut an UTF-8 sequence in half: keep incomplete trailing bytes for the next read
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    text = decoder.decode(data, final=False)
    pending = len(decoder.getstate()[0])
    return text, offset + len(data) - pending


def request_cancel(db: Session, job: Job) -> None:
    # conditional update: the worker may claim the job at the same moment
    res = db.execute(update(Job).where(Job.id == job.id, Job.status == JOB_QUEUED)
                     .values(status=JOB_CANCELLED, finished_at=utcnow(), summary="Vor dem Start abgebrochen"))
    if res.rowcount != 1:
        db.execute(update(Job).where(Job.id == job.id).values(cancel_requested=True))
    db.expire(job)
