"""ORM models."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import (Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class JSONText(TypeDecorator):
    """JSON stored as TEXT (portable for SQLite / PostgreSQL / MariaDB)."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return json.dumps(value, ensure_ascii=False, default=str)

    def process_result_value(self, value, dialect):
        if value is None or value == "":
            return None
        try:
            return json.loads(value)
        except ValueError:
            return None


# --------------------------------------------------------------------------
# Users & access
# --------------------------------------------------------------------------
ROLE_ADMIN = "admin"
ROLE_MANAGER = "manager"
ROLE_USER = "user"
ROLES = {
    ROLE_ADMIN: "Administrator",
    ROLE_MANAGER: "Manager",
    ROLE_USER: "Benutzer",
}

LEVEL_VIEW = "view"
LEVEL_OPERATE = "operate"
LEVEL_FULL = "full"
LEVELS = {
    LEVEL_VIEW: "Lesen",
    LEVEL_OPERATE: "Bedienen",
    LEVEL_FULL: "Vollzugriff",
}
LEVEL_ORDER = {LEVEL_VIEW: 1, LEVEL_OPERATE: 2, LEVEL_FULL: 3}


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(128), default="")
    email: Mapped[str] = mapped_column(String(255), default="")
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default=ROLE_USER)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    totp_secret_enc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    auth_version: Mapped[int] = mapped_column(Integer, default=1)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    access: Mapped[list["SystemAccess"]] = relationship(
        back_populates="user", cascade="all, delete-orphan")

    @property
    def is_admin(self) -> bool:
        return self.role == ROLE_ADMIN

    @property
    def can_add_systems(self) -> bool:
        return self.role in (ROLE_ADMIN, ROLE_MANAGER)

    @property
    def label(self) -> str:
        return self.display_name or self.username


class SystemAccess(Base):
    __tablename__ = "system_access"
    __table_args__ = (UniqueConstraint("user_id", "system_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    system_id: Mapped[int] = mapped_column(ForeignKey("systems.id", ondelete="CASCADE"), index=True)
    level: Mapped[str] = mapped_column(String(16), default=LEVEL_VIEW)

    user: Mapped[User] = relationship(back_populates="access")
    system: Mapped["System"] = relationship(back_populates="access")


# --------------------------------------------------------------------------
# Systems
# --------------------------------------------------------------------------
CONN_WIREGUARD = "wireguard"
CONN_DIRECT = "direct"
CONNECTIONS = {CONN_WIREGUARD: "WireGuard-Tunnel", CONN_DIRECT: "Direkt (SSH)"}

AUTH_KEY = "key"
AUTH_PASSWORD = "password"
AUTH_METHODS = {AUTH_KEY: "SSH-Schlüssel", AUTH_PASSWORD: "Passwort"}

SUDO_NONE = "none"          # user is root
SUDO_NOPASSWD = "nopasswd"  # sudo without password
SUDO_PASSWORD = "password"  # sudo with password
SUDO_MODES = {SUDO_NONE: "Kein sudo (root)", SUDO_NOPASSWD: "sudo ohne Passwort",
              SUDO_PASSWORD: "sudo mit Passwort"}

STATUS_UNKNOWN = "unknown"
STATUS_ONLINE = "online"
STATUS_OFFLINE = "offline"
STATUS_ERROR = "error"
STATUS_PENDING = "pending"
STATUSES = {STATUS_UNKNOWN: "Unbekannt", STATUS_ONLINE: "Online", STATUS_OFFLINE: "Offline",
            STATUS_ERROR: "Fehler", STATUS_PENDING: "Enrollment ausstehend"}


class System(Base):
    __tablename__ = "systems"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    tags: Mapped[str] = mapped_column(String(255), default="")
    hostname: Mapped[str] = mapped_column(String(255), default="")

    connection: Mapped[str] = mapped_column(String(16), default=CONN_DIRECT)
    host: Mapped[str] = mapped_column(String(255), default="")
    port: Mapped[int] = mapped_column(Integer, default=22)
    username: Mapped[str] = mapped_column(String(64), default="root")
    auth_method: Mapped[str] = mapped_column(String(16), default=AUTH_KEY)
    password_enc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    private_key_enc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    key_passphrase_enc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    sudo_mode: Mapped[str] = mapped_column(String(16), default=SUDO_NONE)
    sudo_password_enc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    host_keys: Mapped[str] = mapped_column(Text, default="")

    types: Mapped[Optional[list]] = mapped_column(JSONText, default=list)
    nextcloud_path: Mapped[str] = mapped_column(String(255), default="")
    occ_command: Mapped[str] = mapped_column(String(255), default="")
    backup_paths: Mapped[str] = mapped_column(Text, default="/etc")

    # WireGuard / MikroTik
    wg_ip: Mapped[str] = mapped_column(String(64), default="")
    wg_public_key: Mapped[str] = mapped_column(String(64), default="")
    routed_subnets: Mapped[str] = mapped_column(Text, default="")
    mt_refs: Mapped[Optional[dict]] = mapped_column(JSONText, default=dict)

    # state
    status: Mapped[str] = mapped_column(String(16), default=STATUS_UNKNOWN)
    status_message: Mapped[str] = mapped_column(Text, default="")
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_check: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_deep_check: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    facts: Mapped[Optional[dict]] = mapped_column(JSONText, default=dict)
    updates: Mapped[Optional[dict]] = mapped_column(JSONText, default=dict)
    maintenance_mode: Mapped[bool] = mapped_column(Boolean, default=False)
    enroll_secret_hash: Mapped[str] = mapped_column(String(128), default="")
    enrolled_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    notes: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    # Proxmox guest this system runs in (optional, for power control via the Proxmox API)
    # no FK constraint: pve_servers.system_id already references systems (cycle); cleared on delete
    pve_server_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    pve_vmid: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    access: Mapped[list[SystemAccess]] = relationship(back_populates="system", cascade="all, delete-orphan")

    @property
    def type_list(self) -> list[str]:
        return list(self.types or [])

    def has_type(self, key: str) -> bool:
        return key in (self.types or [])

    @property
    def tag_list(self) -> list[str]:
        return [t.strip() for t in (self.tags or "").split(",") if t.strip()]

    @property
    def routed_subnet_list(self) -> list[str]:
        return [s.strip() for s in (self.routed_subnets or "").replace(",", " ").split() if s.strip()]

    @property
    def fact(self) -> dict:
        return self.facts or {}

    @property
    def upd(self) -> dict:
        return self.updates or {}


# --------------------------------------------------------------------------
# Enrollment
# --------------------------------------------------------------------------
class EnrollmentToken(Base):
    __tablename__ = "enrollment_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), default="")
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    token_hint: Mapped[str] = mapped_column(String(16), default="")
    connection: Mapped[str] = mapped_column(String(16), default=CONN_WIREGUARD)
    ssh_user_mode: Mapped[str] = mapped_column(String(16), default="root")
    system_types: Mapped[Optional[list]] = mapped_column(JSONText, default=list)
    routed_subnets: Mapped[str] = mapped_column(Text, default="")
    tags: Mapped[str] = mapped_column(String(255), default="")
    assign: Mapped[Optional[list]] = mapped_column(JSONText, default=list)
    bind_system_id: Mapped[Optional[int]] = mapped_column(ForeignKey("systems.id", ondelete="SET NULL"), nullable=True)
    max_uses: Mapped[int] = mapped_column(Integer, default=1)
    uses: Mapped[int] = mapped_column(Integer, default=0)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    created_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    @property
    def is_valid(self) -> bool:
        return (not self.revoked) and self.uses < self.max_uses and self.expires_at > utcnow()


# --------------------------------------------------------------------------
# Jobs
# --------------------------------------------------------------------------
JOB_QUEUED = "queued"
JOB_RUNNING = "running"
JOB_SUCCESS = "success"
JOB_FAILED = "failed"
JOB_CANCELLED = "cancelled"
JOB_SKIPPED = "skipped"
JOB_STATUSES = {JOB_QUEUED: "Wartend", JOB_RUNNING: "Läuft", JOB_SUCCESS: "Erfolgreich",
                JOB_FAILED: "Fehlgeschlagen", JOB_CANCELLED: "Abgebrochen", JOB_SKIPPED: "Übersprungen"}
JOB_FINAL = (JOB_SUCCESS, JOB_FAILED, JOB_CANCELLED, JOB_SKIPPED)


class Job(Base):
    __tablename__ = "jobs"
    # never reuse ids - job logs are stored in files named after the id
    __table_args__ = {"sqlite_autoincrement": True}

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    batch_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    run_id: Mapped[Optional[int]] = mapped_column(ForeignKey("schedule_runs.id", ondelete="SET NULL"),
                                                  nullable=True, index=True)
    system_id: Mapped[Optional[int]] = mapped_column(ForeignKey("systems.id", ondelete="CASCADE"),
                                                     nullable=True, index=True)
    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    pve_id: Mapped[Optional[int]] = mapped_column(ForeignKey("pve_servers.id", ondelete="CASCADE"),
                                                  nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(255), default="")
    payload: Mapped[Optional[dict]] = mapped_column(JSONText, default=dict)
    status: Mapped[str] = mapped_column(String(16), default=JOB_QUEUED, index=True)
    exit_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    result: Mapped[Optional[dict]] = mapped_column(JSONText, default=dict)
    remote: Mapped[Optional[dict]] = mapped_column(JSONText, default=dict)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    not_after: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    system: Mapped[Optional[System]] = relationship()
    user: Mapped[Optional[User]] = relationship()

    @property
    def is_final(self) -> bool:
        return self.status in JOB_FINAL

    @property
    def duration(self) -> Optional[float]:
        if not self.started_at:
            return None
        end = self.finished_at or utcnow()
        return (end - self.started_at).total_seconds()


# --------------------------------------------------------------------------
# Maintenance scheduler
# --------------------------------------------------------------------------
RECURRENCES = {"once": "Einmalig", "daily": "Täglich", "weekly": "Wöchentlich", "monthly": "Monatlich"}
REBOOT_POLICIES = {"never": "Nie neu starten", "if_required": "Neustart falls erforderlich",
                   "always": "Immer neu starten"}


class MaintenanceSchedule(Base):
    __tablename__ = "schedules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    recurrence: Mapped[str] = mapped_column(String(16), default="once")
    run_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)  # local time (once)
    time_of_day: Mapped[str] = mapped_column(String(5), default="03:00")
    weekdays: Mapped[Optional[list]] = mapped_column(JSONText, default=list)
    day_of_month: Mapped[int] = mapped_column(Integer, default=1)
    system_ids: Mapped[Optional[list]] = mapped_column(JSONText, default=list)
    tag: Mapped[str] = mapped_column(String(64), default="")
    steps: Mapped[Optional[list]] = mapped_column(JSONText, default=list)
    only_if_updates: Mapped[bool] = mapped_column(Boolean, default=False)
    reboot_policy: Mapped[str] = mapped_column(String(16), default="if_required")
    pre_backup: Mapped[bool] = mapped_column(Boolean, default=False)
    stop_on_error: Mapped[bool] = mapped_column(Boolean, default=True)
    max_parallel: Mapped[int] = mapped_column(Integer, default=3)
    window_minutes: Mapped[int] = mapped_column(Integer, default=180)
    notify_email: Mapped[str] = mapped_column(String(255), default="")
    next_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True, index=True)  # UTC
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_status: Mapped[str] = mapped_column(String(16), default="")
    created_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    creator: Mapped[Optional[User]] = relationship()


class ScheduleRun(Base):
    __tablename__ = "schedule_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    schedule_id: Mapped[Optional[int]] = mapped_column(ForeignKey("schedules.id", ondelete="CASCADE"),
                                                       nullable=True, index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default=JOB_RUNNING)
    summary: Mapped[str] = mapped_column(Text, default="")
    max_parallel: Mapped[int] = mapped_column(Integer, default=3)

    schedule: Mapped[Optional[MaintenanceSchedule]] = relationship()


# --------------------------------------------------------------------------
# Integrations: Proxmox VE API, RouterOS API, Pangolin
# --------------------------------------------------------------------------
KIND_PVE = "pve"
KIND_ROUTER = "router"
KIND_PANGOLIN = "pangolin"
INTEGRATION_KINDS = {KIND_PVE: "Proxmox VE", KIND_ROUTER: "RouterOS", KIND_PANGOLIN: "Pangolin"}


class IntegrationMixin:
    """Common state of an API connection (status, cached data, alerts)."""

    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(Text, default="")
    fingerprint: Mapped[str] = mapped_column(String(128), default="")
    verify_ca: Mapped[bool] = mapped_column(Boolean, default=False)
    monitor: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(16), default=STATUS_UNKNOWN)
    status_message: Mapped[str] = mapped_column(Text, default="")
    last_poll: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_ok: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    cache: Mapped[Optional[dict]] = mapped_column(JSONText, default=dict)
    alerts: Mapped[Optional[list]] = mapped_column(JSONText, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    @property
    def data(self) -> dict:
        return self.cache or {}

    @property
    def alert_list(self) -> list:
        return list(self.alerts or [])


class PveServer(IntegrationMixin, Base):
    __tablename__ = "pve_servers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    api_url: Mapped[str] = mapped_column(String(255), default="")
    token_id: Mapped[str] = mapped_column(String(128), default="")
    token_secret_enc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    system_id: Mapped[Optional[int]] = mapped_column(ForeignKey("systems.id", ondelete="SET NULL"), nullable=True)
    watch: Mapped[Optional[list]] = mapped_column(JSONText, default=list)   # vmids that must be running
    router_id: Mapped[Optional[int]] = mapped_column(ForeignKey("router_devices.id", ondelete="SET NULL"),
                                                     nullable=True)          # DHCP for new containers
    pangolin_id: Mapped[Optional[int]] = mapped_column(ForeignKey("pangolin_servers.id", ondelete="SET NULL"),
                                                       nullable=True)        # publishing of services

    system: Mapped[Optional[System]] = relationship(foreign_keys=[system_id])

    @property
    def watch_list(self) -> list[int]:
        return [int(v) for v in (self.watch or [])]


class RouterDevice(IntegrationMixin, Base):
    __tablename__ = "router_devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    api_url: Mapped[str] = mapped_column(String(255), default="")
    username: Mapped[str] = mapped_column(String(64), default="")
    password_enc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    target: Mapped[Optional[dict]] = mapped_column(JSONText, default=dict)     # desired setup (analysis)
    snapshot: Mapped[Optional[dict]] = mapped_column(JSONText, default=dict)   # imported configuration
    snapshot_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    snapshot_source: Mapped[str] = mapped_column(String(16), default="")

    @property
    def target_cfg(self) -> dict:
        return self.target or {}


class PangolinServer(IntegrationMixin, Base):
    __tablename__ = "pangolin_servers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    api_url: Mapped[str] = mapped_column(String(255), default="")
    org_id: Mapped[str] = mapped_column(String(64), default="")
    api_key_enc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    default_site_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    default_domain_id: Mapped[str] = mapped_column(String(64), default="")


class IntegrationAccess(Base):
    """Per user access level to a Proxmox server, router or Pangolin instance."""

    __tablename__ = "integration_access"
    __table_args__ = (UniqueConstraint("user_id", "kind", "obj_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(16))
    obj_id: Mapped[int] = mapped_column(Integer, index=True)
    level: Mapped[str] = mapped_column(String(16), default=LEVEL_VIEW)


# --------------------------------------------------------------------------
# Misc
# --------------------------------------------------------------------------
class SystemBackup(Base):
    __tablename__ = "system_backups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    system_id: Mapped[int] = mapped_column(ForeignKey("systems.id", ondelete="CASCADE"), index=True)
    job_id: Mapped[Optional[int]] = mapped_column(ForeignKey("jobs.id", ondelete="SET NULL"), nullable=True)
    filename: Mapped[str] = mapped_column(String(255))
    size: Mapped[int] = mapped_column(Integer, default=0)
    paths: Mapped[str] = mapped_column(Text, default="")
    note: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    system: Mapped[System] = relationship()


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    user_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    username: Mapped[str] = mapped_column(String(64), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(255), default="")
    details: Mapped[str] = mapped_column(Text, default="")


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[Any] = mapped_column(JSONText, nullable=True)


class Meta(Base):
    __tablename__ = "meta"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")
