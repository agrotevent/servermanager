"""Configuration backups of managed systems (tar.gz of selected paths)."""
from __future__ import annotations

import re
import shlex
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import settings
from .config import get_config
from .models import System, SystemBackup
from .ssh import CancelledError, Connection, SSHError

PATH_RE = re.compile(r"^/[A-Za-z0-9._/@+-]*$")
EXCLUDES = ["/proc", "/sys", "/dev", "/run", "/tmp", "/var/lib/docker", "/var/lib/vz", "/var/lib/mysql"]


def parse_paths(text: str) -> list[str]:
    paths = []
    for p in re.split(r"[\s,]+", text or ""):
        p = p.strip().rstrip("/") or ("/" if p.strip() == "/" else "")
        if not p:
            continue
        # no ".." and no component starting with "-" (would be read as a tar option)
        if not PATH_RE.match(p) or ".." in p.split("/") or p == "/" or any(c.startswith("-") for c in p.split("/")):
            raise ValueError(f"Ungültiger Pfad für das Backup: {p}")
        paths.append(p)
    return paths or ["/etc"]


def backup_dir(system_id: int) -> Path:
    d = get_config().system_backups_dir / str(system_id)
    d.mkdir(parents=True, exist_ok=True)
    return d


def create_backup(conn: Connection, db: Session, system: System, paths: list[str], note: str,
                  job_id: Optional[int], say: Callable[[str], None],
                  cancel: Optional[Callable[[], bool]] = None) -> SystemBackup:
    rel = " ".join(shlex.quote(p.lstrip("/")) for p in paths)
    excludes = " ".join(f"--exclude={shlex.quote(e.lstrip('/'))}" for e in EXCLUDES)
    cmd = (f"cd / && tar czf - --ignore-failed-read --warning=no-file-changed --warning=no-file-removed "
           f"{excludes} -- {rel}; rc=$?; [ $rc -le 1 ] && exit 0 || exit $rc")
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", system.name)[:40]
    fname = f"{safe_name}-{ts}.tar.gz"
    target = backup_dir(system.id) / fname
    say(f"Sichere {', '.join(paths)} nach {fname} ...\n")
    try:
        with target.open("wb") as fh:
            size = conn.stream_cmd(f"bash -c {shlex.quote(cmd)}", fh, root=True,
                                   on_progress=lambda n: say(f"  {n // (1024 * 1024)} MB ...\n"), cancel=cancel)
    except (SSHError, CancelledError):
        target.unlink(missing_ok=True)
        raise
    target.chmod(0o600)
    say(f"Backup erstellt: {size / 1024 / 1024:.1f} MB\n")
    b = SystemBackup(system_id=system.id, job_id=job_id, filename=fname, size=size, paths=" ".join(paths), note=note)
    db.add(b)
    db.flush()
    prune(db, system.id, int(settings.get(db, "system_backup.keep") or 10))
    return b


def prune(db: Session, system_id: int, keep: int) -> None:
    rows = db.execute(select(SystemBackup).where(SystemBackup.system_id == system_id)
                      .order_by(SystemBackup.created_at.desc(), SystemBackup.id.desc())).scalars().all()
    for b in rows[keep:]:
        (backup_dir(system_id) / b.filename).unlink(missing_ok=True)
        db.delete(b)


def file_path(b: SystemBackup) -> Path:
    return backup_dir(b.system_id) / b.filename


def restore_backup(conn: Connection, b: SystemBackup, mode: str, say: Callable[[str], None]) -> str:
    """mode 'extract' -> /root/servermanager-restore-<ts>/ ; mode 'inplace' -> overwrite files below /"""
    src = file_path(b)
    if not src.exists():
        raise SSHError("Backup-Datei nicht gefunden")
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    remote_archive = f"/root/servermanager-restore-{ts}.tar.gz"
    say(f"Übertrage {b.filename} ({b.size / 1024 / 1024:.1f} MB) ...\n")
    with src.open("rb") as fh:
        conn.upload_root(fh, remote_archive)
    if mode == "inplace":
        say("Stelle Dateien am Originalort wieder her (überschreibt bestehende Dateien) ...\n")
        out = conn.check(f"tar xzf {remote_archive} -C / && rm -f {remote_archive} && echo OK", root=True, timeout=1800)
        return out.strip()
    dest = f"/root/servermanager-restore-{ts}"
    say(f"Entpacke nach {dest} ...\n")
    conn.check(f"mkdir -p {dest} && tar xzf {remote_archive} -C {dest} && rm -f {remote_archive}", root=True,
               timeout=1800)
    return dest
