"""Backup and restore of the servermanager itself.

A backup is a tar.gz archive containing the database (consistent SQLite
snapshot), the master key, the configuration, the SSH key pair and the local
WireGuard configuration. Optionally it is encrypted with a passphrase
(scrypt + AES-256-GCM, chunked so large archives can be streamed).
"""
from __future__ import annotations

import io
import json
import os
import re
import shutil
import socket
import sqlite3
import struct
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path
from typing import BinaryIO, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from sqlalchemy.orm import Session

from . import __version__, settings
from .config import get_config
from .migrations import current_version
from .db import get_engine

MAGIC = b"SMBACKUP1\n"
CHUNK = 1 << 20
NAME_RE = re.compile(r"^servermanager-backup-[A-Za-z0-9_.-]+\.tar\.gz(\.enc)?$")


class BackupError(Exception):
    pass


# --------------------------------------------------------------------------
# encryption
# --------------------------------------------------------------------------
def _derive(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(passphrase.encode())


def encrypt_stream(src: BinaryIO, dst: BinaryIO, passphrase: str) -> None:
    salt, prefix = os.urandom(16), os.urandom(8)
    aes = AESGCM(_derive(passphrase, salt))
    dst.write(MAGIC + salt + prefix)
    counter = 0
    chunk = src.read(CHUNK)
    while True:
        nxt = src.read(CHUNK)
        last = not nxt
        flag = b"\x01" if last else b"\x00"
        ct = aes.encrypt(prefix + struct.pack(">I", counter), chunk, flag + struct.pack(">I", counter))
        dst.write(flag + struct.pack(">I", len(ct)) + ct)
        counter += 1
        if last:
            break
        chunk = nxt


def decrypt_stream(src: BinaryIO, dst: BinaryIO, passphrase: str) -> None:
    if src.read(len(MAGIC)) != MAGIC:
        raise BackupError("Keine verschlüsselte Servermanager-Sicherung")
    salt, prefix = src.read(16), src.read(8)
    aes = AESGCM(_derive(passphrase, salt))
    counter = 0
    while True:
        head = src.read(5)
        if len(head) < 5:
            raise BackupError("Sicherung ist unvollständig (abgeschnitten)")
        flag, length = head[:1], struct.unpack(">I", head[1:])[0]
        ct = src.read(length)
        try:
            dst.write(aes.decrypt(prefix + struct.pack(">I", counter), ct, flag + struct.pack(">I", counter)))
        except InvalidTag as exc:
            raise BackupError("Entschlüsselung fehlgeschlagen - falsche Passphrase oder beschädigte Datei") from exc
        counter += 1
        if flag == b"\x01":
            if src.read(1):
                raise BackupError("Unerwartete Daten am Ende der Sicherung")
            return


def is_encrypted(path: Path) -> bool:
    with path.open("rb") as fh:
        return fh.read(len(MAGIC)) == MAGIC


# --------------------------------------------------------------------------
# create
# --------------------------------------------------------------------------
def _sqlite_path() -> Optional[Path]:
    url = get_config().database_url
    if url.startswith("sqlite:///"):
        return Path(url[len("sqlite:///"):])
    return None


def git_commit() -> str:
    head = Path(get_config().repo_dir) / ".git" / "HEAD"
    try:
        ref = head.read_text().strip()
        if ref.startswith("ref:"):
            p = head.parent / ref.split(" ", 1)[1]
            if p.exists():
                return p.read_text().strip()[:12]
            packed = head.parent / "packed-refs"
            for line in packed.read_text().splitlines():
                if line.endswith(ref.split(" ", 1)[1]):
                    return line.split()[0][:12]
            return ""
        return ref[:12]
    except OSError:
        return ""


def create_backup(db: Session, note: str = "", passphrase: Optional[str] = None,
                  include_system_backups: Optional[bool] = None, auto: bool = False) -> Path:
    cfg = get_config()
    cfg.backups_dir.mkdir(parents=True, exist_ok=True)
    if passphrase is None:
        passphrase = settings.get(db, "backup.passphrase") or ""
    if include_system_backups is None:
        include_system_backups = bool(settings.get(db, "backup.include_system_backups"))
    db_path = _sqlite_path()
    if db_path is None:
        raise BackupError("Backups werden nur für SQLite-Datenbanken unterstützt")
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    name = f"servermanager-backup-{'auto-' if auto else ''}{ts}.tar.gz"
    manifest = {
        "format": 1, "version": __version__, "commit": git_commit(), "created": datetime.now().isoformat(),
        "hostname": socket.gethostname(), "schema_version": current_version(get_engine()), "note": note,
        "includes_system_backups": include_system_backups,
    }
    with tempfile.TemporaryDirectory(dir=str(cfg.data_path)) as tmp:
        snap = Path(tmp) / "servermanager.db"
        src = sqlite3.connect(str(db_path))
        dst = sqlite3.connect(str(snap))
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
        tar_path = Path(tmp) / name
        with tarfile.open(tar_path, "w:gz") as tar:
            data = json.dumps(manifest, indent=2).encode()
            info = tarfile.TarInfo("manifest.json")
            info.size = len(data)
            info.mtime = int(datetime.now().timestamp())
            tar.addfile(info, io.BytesIO(data))
            tar.add(snap, "servermanager.db")
            tar.add(cfg.secret_key_file, "secret.key")
            if os.path.exists(cfg.config_path) and os.access(cfg.config_path, os.R_OK):
                tar.add(cfg.config_path, "servermanager.conf")
            for sub in ("ssh", "wireguard"):
                p = cfg.data_path / sub
                if p.exists():
                    tar.add(p, sub)
            if include_system_backups and cfg.system_backups_dir.exists():
                tar.add(cfg.system_backups_dir, "system-backups")
        if passphrase:
            target = cfg.backups_dir / (name + ".enc")
            with tar_path.open("rb") as fin, _private_open(target) as fout:
                encrypt_stream(fin, fout, passphrase)
        else:
            target = cfg.backups_dir / name
            shutil.move(str(tar_path), str(target))
            os.chmod(target, 0o600)
    return target


def _private_open(path: Path):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    return os.fdopen(fd, "wb")


def list_backups() -> list[dict]:
    d = get_config().backups_dir
    if not d.exists():
        return []
    out = []
    for p in sorted(d.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
        if p.is_file() and NAME_RE.match(p.name):
            st = p.stat()
            out.append({"name": p.name, "size": st.st_size, "mtime": datetime.fromtimestamp(st.st_mtime),
                        "encrypted": p.name.endswith(".enc"), "auto": "-auto-" in p.name})
    return out


def backup_path(name: str) -> Path:
    if not NAME_RE.match(name or ""):
        raise BackupError("Ungültiger Dateiname")
    p = get_config().backups_dir / name
    if not p.exists():
        raise BackupError("Sicherung nicht gefunden")
    return p


def prune_backups(keep: int) -> int:
    autos = [b for b in list_backups() if b["auto"]]
    removed = 0
    for b in autos[max(1, keep):]:
        (get_config().backups_dir / b["name"]).unlink(missing_ok=True)
        removed += 1
    return removed


# --------------------------------------------------------------------------
# restore
# --------------------------------------------------------------------------
def _plain_tar(path: Path, passphrase: str, workdir: Path) -> Path:
    if is_encrypted(path):
        if not passphrase:
            raise BackupError("Diese Sicherung ist verschlüsselt - bitte Passphrase angeben")
        plain = workdir / "backup.tar.gz"
        with path.open("rb") as fin, _private_open(plain) as fout:
            decrypt_stream(fin, fout, passphrase)
        return plain
    return path


def inspect_backup(path: Path, passphrase: str = "") -> dict:
    with tempfile.TemporaryDirectory(dir=str(get_config().data_path)) as tmp:
        plain = _plain_tar(path, passphrase, Path(tmp))
        try:
            with tarfile.open(plain, "r:gz") as tar:
                names = tar.getnames()
                member = tar.extractfile("manifest.json")
                if member is None:
                    raise BackupError("manifest.json fehlt")
                manifest = json.loads(member.read())
        except (tarfile.TarError, KeyError, ValueError) as exc:
            raise BackupError(f"Ungültige Sicherung: {exc}") from exc
    for required in ("servermanager.db", "secret.key"):
        if required not in names:
            raise BackupError(f"Ungültige Sicherung: {required} fehlt")
    manifest["files"] = len(names)
    return manifest


def stage_restore(path: Path, passphrase: str = "") -> Path:
    """Extract a backup into the staging directory for the privileged restore helper."""
    cfg = get_config()
    staging = cfg.staging_dir
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    os.chmod(staging, 0o700)
    with tempfile.TemporaryDirectory(dir=str(cfg.data_path)) as tmp:
        plain = _plain_tar(path, passphrase, Path(tmp))
        with tarfile.open(plain, "r:gz") as tar:
            for m in tar.getmembers():
                if m.name.startswith(("/", "..")) or ".." in Path(m.name).parts or not (m.isfile() or m.isdir()):
                    raise BackupError(f"Unzulässiger Eintrag in der Sicherung: {m.name}")
            tar.extractall(staging, filter="data")
    if not (staging / "servermanager.db").exists() or not (staging / "secret.key").exists():
        shutil.rmtree(staging)
        raise BackupError("Sicherung unvollständig")
    return staging
