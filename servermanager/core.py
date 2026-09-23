"""Application bootstrap shared by the web app, the worker and the CLI."""
from __future__ import annotations

import logging
import os

from sqlalchemy.orm import Session

from . import security, sshkeys
from .config import get_config
from .db import get_engine, init_engine
from .migrations import migrate
from .models import AuditLog

log = logging.getLogger(__name__)
_booted = False


def setup_logging() -> None:
    level = os.environ.get("SM_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("paramiko").setLevel(logging.WARNING)


def bootstrap(run_migrations: bool = True) -> None:
    global _booted
    if _booted:
        return
    cfg = get_config()
    cfg.ensure_dirs()
    security.master_key()
    init_engine(cfg.database_url)
    if run_migrations:
        migrate(get_engine())
    try:
        sshkeys.ensure_keypair()
    except PermissionError:
        log.warning("cannot create SSH key in %s", cfg.ssh_dir)
    _booted = True


def audit(db: Session, user, action: str, target: str = "", details: str = "", ip: str = "") -> None:
    db.add(AuditLog(user_id=getattr(user, "id", None),
                    username=getattr(user, "username", "") or ("system" if user is None else str(user)),
                    ip=ip or "", action=action, target=(target or "")[:255], details=details or ""))
