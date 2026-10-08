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
    totp_last_step: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)   # last used TOTP time step
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    # authentik groups of the last login through the SSO (rights via groups); emptied by a password login
    sso_groups: Mapped[Optional[list]] = mapped_column(JSONText, default=list)
    sso_groups_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

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
KIND_MAILCOW = "mailcow"
KIND_SSO = "sso"
KIND_PBX = "pbx"
KIND_ZABBIX = "zabbix"
KIND_ISPC = "ispconfig"
KIND_ZAMMAD = "zammad"
KIND_EASYBELL = "easybell"
KIND_HETZNER = "hetzner"            # Robot account: all its root servers
KIND_HETZNER_SRV = "hetzner_srv"    # a single root server
KIND_HCLOUD = "hcloud"              # Hetzner Cloud project: all its servers
KIND_HCLOUD_SRV = "hcloud_srv"      # a single cloud server
KIND_NEXTCLOUD = "nextcloud"        # Nextcloud via its OCS API (systems of type nextcloud use SSH/occ)
KIND_DNS = "dns"                    # registrar / DNS provider account (hosting.de platform, INWX)
INTEGRATION_KINDS = {KIND_PVE: "Proxmox VE", KIND_ROUTER: "RouterOS", KIND_PANGOLIN: "Pangolin",
                     KIND_MAILCOW: "Mailcow", KIND_SSO: "SSO (authentik)", KIND_PBX: "Telefonie (Asterisk/FreePBX)",
                     KIND_ZABBIX: "Zabbix & Tickets", KIND_ISPC: "ISPConfig", KIND_ZAMMAD: "Zammad",
                     KIND_EASYBELL: "easybell Cloud Telefonanlage", KIND_HETZNER: "Hetzner (alle Server des Kontos)",
                     KIND_HETZNER_SRV: "Hetzner Root-Server", KIND_HCLOUD: "Hetzner Cloud (alle Server des Projekts)",
                     KIND_HCLOUD_SRV: "Hetzner Cloud-Server", KIND_NEXTCLOUD: "Nextcloud (API)",
                     KIND_DNS: "DNS & Domains"}
# access levels named after what they allow, where the general names would be misleading
# (each level includes the ones before: Ändern may also restart and evaluate)
KIND_LEVEL_LABELS = {k: {"view": "Auswerten", "operate": "Neustarten", "full": "Ändern"}
                     for k in (KIND_HETZNER, KIND_HETZNER_SRV, KIND_HCLOUD, KIND_HCLOUD_SRV)}
MAIL_PORTS_DEFAULT = "25,465,587,143,993,110,995,4190,80"
PANGOLIN_ROLES = {"primary": "Primär", "backup": "Backup-Weg"}
PVE_HOSTING = {"local": "Lokal (gemeinsames Netz)", "hetzner": "Hetzner (vSwitch)"}


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
    hosting: Mapped[str] = mapped_column(String(16), default="local")        # local | hetzner
    vswitch_vlan: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # Hetzner vSwitch VLAN id

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
    role: Mapped[str] = mapped_column(String(16), default="primary")          # primary | backup
    tunnel_system_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # system running Newt
    # backup role: primary base domain -> {"domain_id": backup domain, "template": "{sub}"}
    domain_map: Mapped[Optional[dict]] = mapped_column(JSONText, default=dict)
    dns_target: Mapped[str] = mapped_column(String(255), default="")   # DNS target of published hosts (host or IP)

    @property
    def role_label(self) -> str:
        return PANGOLIN_ROLES.get(self.role, self.role)


class MailcowServer(IntegrationMixin, Base):
    """Mailcow: API reachable internally, web UI via Pangolin, mail protocols on an own public IP."""

    __tablename__ = "mailcow_servers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    api_url: Mapped[str] = mapped_column(String(255), default="")        # internal, e.g. https://10.20.0.30
    api_key_enc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    public_url: Mapped[str] = mapped_column(String(255), default="")     # web UI via Pangolin
    system_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    mail_hostname: Mapped[str] = mapped_column(String(255), default="")  # MX / IMAP / SMTP name
    mail_public_ip: Mapped[str] = mapped_column(String(64), default="")
    mail_internal_ip: Mapped[str] = mapped_column(String(64), default="")
    mail_ports: Mapped[str] = mapped_column(String(128), default=MAIL_PORTS_DEFAULT)
    router_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    @property
    def port_list(self) -> list[int]:
        return [int(p) for p in (self.mail_ports or "").replace(" ", "").split(",") if p.isdigit()]


class PbxServer(IntegrationMixin, Base):
    """Asterisk/FreePBX on a managed system (SSH). Web UI via Pangolin, SIP/RTP via port forwarding."""

    __tablename__ = "pbx_servers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    system_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    web_url: Mapped[str] = mapped_column(String(255), default="")        # internal, e.g. https://10.20.0.40
    public_url: Mapped[str] = mapped_column(String(255), default="")     # web UI via Pangolin
    sip_public_ip: Mapped[str] = mapped_column(String(64), default="")   # empty: WAN address of the router
    sip_internal_ip: Mapped[str] = mapped_column(String(64), default="")
    sip_port: Mapped[int] = mapped_column(Integer, default=5060)         # public UDP/TCP port
    sip_tls_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    rtp_start: Mapped[int] = mapped_column(Integer, default=10000)
    rtp_end: Mapped[int] = mapped_column(Integer, default=20000)
    sip_sources: Mapped[str] = mapped_column(Text, default="")           # allowed SIP peers (provider), empty = all
    router_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    @property
    def source_list(self) -> list[str]:
        import re as _re
        return [x for x in _re.split(r"[,\s]+", self.sip_sources or "") if x]


class IspServer(IntegrationMixin, Base):
    """ISPConfig 3 panel: remote API (set up via SSH), panel UI via Pangolin."""

    __tablename__ = "ispconfig_servers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    api_url: Mapped[str] = mapped_column(String(255), default="")        # https://10.20.0.70:8080/remote/json.php
    username: Mapped[str] = mapped_column(String(64), default="")
    password_enc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    system_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    public_url: Mapped[str] = mapped_column(String(255), default="")     # panel via Pangolin
    setup: Mapped[Optional[dict]] = mapped_column(JSONText, default=dict)

    @property
    def panel_url(self) -> str:
        from urllib.parse import urlsplit
        p = urlsplit(self.api_url or "")
        return f"{p.scheme}://{p.netloc}/" if p.netloc else ""


class DnsAccount(IntegrationMixin, Base):
    """Account at a registrar / DNS provider: domains, zones and records (hosting.de platform or INWX)."""

    __tablename__ = "dns_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider: Mapped[str] = mapped_column(String(16), default="hostingde")   # hostingde | inwx
    api_url: Mapped[str] = mapped_column(String(255), default="")
    username: Mapped[str] = mapped_column(String(128), default="")            # INWX
    secret_enc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)    # API key (hosting.de) / password
    totp_enc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)      # INWX two-factor shared secret
    default_ttl: Mapped[int] = mapped_column(Integer, default=3600)
    auto_pangolin: Mapped[bool] = mapped_column(Boolean, default=True)        # records for Pangolin publications
    expiry_days: Mapped[int] = mapped_column(Integer, default=30)             # warn before a domain runs out


class NextcloudServer(IntegrationMixin, Base):
    """Nextcloud via its OCS API: server info, users and groups (admin account with app password)."""

    __tablename__ = "nextcloud_servers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    api_url: Mapped[str] = mapped_column(String(255), default="")        # https://cloud.example.com
    username: Mapped[str] = mapped_column(String(64), default="")
    password_enc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # app password
    system_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # same Nextcloud as SSH system (occ, SSO)


class ZabbixServer(IntegrationMixin, Base):
    """Zabbix: monitoring of the managed systems (agent 2 with PSK), problems become tickets."""

    __tablename__ = "zabbix_servers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    api_url: Mapped[str] = mapped_column(String(255), default="")        # https://zabbix.example.com
    token_enc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    agent_server: Mapped[str] = mapped_column(String(255), default="")   # address the agents talk to
    host_group: Mapped[str] = mapped_column(String(128), default="Servermanager")
    min_severity: Mapped[int] = mapped_column(Integer, default=2)        # tickets from this severity on
    tickets: Mapped[bool] = mapped_column(Boolean, default=True)
    ticket_mail: Mapped[str] = mapped_column(String(255), default="")    # external ticket system (e-mail)
    webhook_hash: Mapped[str] = mapped_column(String(128), default="")   # sha256 of the webhook token
    setup: Mapped[Optional[dict]] = mapped_column(JSONText, default=dict)
    zammad_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # tickets go to this Zammad


class ZammadServer(IntegrationMixin, Base):
    """Zammad helpdesk: tickets of the servermanager are created and kept in sync there."""

    __tablename__ = "zammad_servers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    api_url: Mapped[str] = mapped_column(String(255), default="")        # https://support.example.com
    token_enc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    group_name: Mapped[str] = mapped_column(String(128), default="Users")
    customer: Mapped[str] = mapped_column(String(255), default="")       # e-mail of the ticket customer
    close_on_resolve: Mapped[bool] = mapped_column(Boolean, default=False)
    webhook_secret_enc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    agent_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # Zammad user of the API token
    setup: Mapped[Optional[dict]] = mapped_column(JSONText, default=dict)


class EasybellAccount(IntegrationMixin, Base):
    """easybell Cloud Telefonanlage via AMI: devices, active calls, call journal, calls to Zammad (CTI)."""

    __tablename__ = "easybell_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host: Mapped[str] = mapped_column(String(255), default="jarvis.easybell.de")
    port: Mapped[int] = mapped_column(Integer, default=5039)
    username: Mapped[str] = mapped_column(String(128), default="")
    secret_enc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    allow_plain: Mapped[bool] = mapped_column(Boolean, default=False)       # login without MD5 challenge
    transport: Mapped[str] = mapped_column(String(8), default="auto")       # auto | tls | plain
    country_code: Mapped[str] = mapped_column(String(4), default="49")
    device_pattern: Mapped[str] = mapped_column(String(128), default=r"^PJSIP/CPBX-")
    listen: Mapped[bool] = mapped_column(Boolean, default=True)             # permanent connection for events
    journal_days: Mapped[int] = mapped_column(Integer, default=30)
    watch_devices: Mapped[bool] = mapped_column(Boolean, default=False)     # alert on unreachable devices
    zammad_id: Mapped[Optional[int]] = mapped_column(ForeignKey("zammad_servers.id", ondelete="SET NULL"),
                                                     nullable=True)
    cti_token_enc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # token of Zammad's CTI (generic)
    listener: Mapped[Optional[dict]] = mapped_column(JSONText, default=dict)  # state of the event connection


class HetznerAccount(IntegrationMixin, Base):
    """Hetzner Robot webservice user: the root servers of this customer account."""

    __tablename__ = "hetzner_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    api_url: Mapped[str] = mapped_column(String(255), default="https://robot-ws.your-server.de")
    username: Mapped[str] = mapped_column(String(128), default="")
    password_enc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    traffic_alert_pct: Mapped[int] = mapped_column(Integer, default=90)   # of the included traffic


class HetznerServer(Base):
    """A root server of a Hetzner account (synchronised on every poll)."""

    __tablename__ = "hetzner_servers"
    __table_args__ = (UniqueConstraint("account_id", "number"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    account_id: Mapped[int] = mapped_column(ForeignKey("hetzner_accounts.id", ondelete="CASCADE"), index=True)
    number: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(128), default="")        # server name in Robot (or #number)
    server_ip: Mapped[str] = mapped_column(String(64), default="")
    product: Mapped[str] = mapped_column(String(128), default="")
    dc: Mapped[str] = mapped_column(String(32), default="")
    status: Mapped[str] = mapped_column(String(32), default="")
    cancelled: Mapped[bool] = mapped_column(Boolean, default=False)
    system_id: Mapped[Optional[int]] = mapped_column(ForeignKey("systems.id", ondelete="SET NULL"), nullable=True)
    data: Mapped[Optional[dict]] = mapped_column(JSONText, default=dict)  # raw server, ips, subnets, traffic
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    @property
    def info(self) -> dict:
        return self.data or {}


class HcloudProject(IntegrationMixin, Base):
    """Hetzner Cloud project (one API token): its servers."""

    __tablename__ = "hcloud_projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    api_url: Mapped[str] = mapped_column(String(255), default="https://api.hetzner.cloud/v1")
    token_enc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    traffic_alert_pct: Mapped[int] = mapped_column(Integer, default=90)   # of the included traffic


class HcloudServer(Base):
    """A server of a Hetzner Cloud project (synchronised on every poll)."""

    __tablename__ = "hcloud_servers"
    __table_args__ = (UniqueConstraint("project_id", "cloud_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("hcloud_projects.id", ondelete="CASCADE"), index=True)
    cloud_id: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(128), default="")
    status: Mapped[str] = mapped_column(String(32), default="")
    ipv4: Mapped[str] = mapped_column(String(64), default="")
    ipv6_net: Mapped[str] = mapped_column(String(64), default="")
    server_type: Mapped[str] = mapped_column(String(64), default="")
    location: Mapped[str] = mapped_column(String(64), default="")
    system_id: Mapped[Optional[int]] = mapped_column(ForeignKey("systems.id", ondelete="SET NULL"), nullable=True)
    data: Mapped[Optional[dict]] = mapped_column(JSONText, default=dict)  # raw server, addresses, traffic
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    @property
    def info(self) -> dict:
        return self.data or {}


class EasybellCall(Base):
    """Call journal from the AMI events."""

    __tablename__ = "easybell_calls"
    __table_args__ = (UniqueConstraint("account_id", "call_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    account_id: Mapped[int] = mapped_column(ForeignKey("easybell_accounts.id", ondelete="CASCADE"), index=True)
    call_id: Mapped[str] = mapped_column(String(64))
    direction: Mapped[str] = mapped_column(String(4))                     # in | out
    from_number: Mapped[str] = mapped_column(String(64), default="")
    to_number: Mapped[str] = mapped_column(String(64), default="")
    extension: Mapped[str] = mapped_column(String(64), default="")
    answered_by: Mapped[str] = mapped_column(String(64), default="")
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    answered_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    ended_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    cause: Mapped[str] = mapped_column(String(32), default="")
    zammad_ok: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)


class ZabbixHost(Base):
    """A managed system as a host in Zabbix (agent 2, PSK encrypted)."""

    __tablename__ = "zabbix_hosts"
    __table_args__ = (UniqueConstraint("zabbix_id", "system_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    zabbix_id: Mapped[int] = mapped_column(ForeignKey("zabbix_servers.id", ondelete="CASCADE"), index=True)
    system_id: Mapped[int] = mapped_column(ForeignKey("systems.id", ondelete="CASCADE"), index=True)
    hostid: Mapped[str] = mapped_column(String(32), default="")
    host: Mapped[str] = mapped_column(String(128), default="")
    psk_identity: Mapped[str] = mapped_column(String(128), default="")
    psk_enc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


TICKET_OPEN = "open"
TICKET_PROGRESS = "progress"
TICKET_RESOLVED = "resolved"
TICKET_CLOSED = "closed"
TICKET_STATUSES = {TICKET_OPEN: "Offen", TICKET_PROGRESS: "In Bearbeitung", TICKET_RESOLVED: "Behoben",
                   TICKET_CLOSED: "Geschlossen"}


class Ticket(Base):
    __tablename__ = "tickets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(16), default="zabbix")    # zabbix | manual
    zabbix_id: Mapped[Optional[int]] = mapped_column(ForeignKey("zabbix_servers.id", ondelete="SET NULL"),
                                                     nullable=True, index=True)
    event_id: Mapped[str] = mapped_column(String(32), default="", index=True)
    trigger_id: Mapped[str] = mapped_column(String(32), default="")
    title: Mapped[str] = mapped_column(String(500), default="")
    severity: Mapped[int] = mapped_column(Integer, default=0)
    host: Mapped[str] = mapped_column(String(255), default="")
    host_ip: Mapped[str] = mapped_column(String(64), default="")
    opdata: Mapped[str] = mapped_column(Text, default="")
    system_id: Mapped[Optional[int]] = mapped_column(ForeignKey("systems.id", ondelete="SET NULL"), nullable=True,
                                                     index=True)
    status: Mapped[str] = mapped_column(String(16), default=TICKET_OPEN, index=True)
    manual_close: Mapped[bool] = mapped_column(Boolean, default=False)
    assignee_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    opened_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
    zammad_server_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    zammad_ticket_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    zammad_number: Mapped[str] = mapped_column(String(32), default="")
    zammad_error: Mapped[str] = mapped_column(Text, default="")

    system: Mapped[Optional[System]] = relationship()
    assignee: Mapped[Optional[User]] = relationship()
    comments: Mapped[list["TicketComment"]] = relationship(back_populates="ticket", cascade="all, delete-orphan",
                                                           order_by="TicketComment.id")

    @property
    def is_active(self) -> bool:
        return self.status in (TICKET_OPEN, TICKET_PROGRESS)


class TicketComment(Base):
    __tablename__ = "ticket_comments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ticket_id: Mapped[int] = mapped_column(ForeignKey("tickets.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    kind: Mapped[str] = mapped_column(String(16), default="comment")     # comment | event | zabbix
    text: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    ticket: Mapped[Ticket] = relationship(back_populates="comments")
    user: Mapped[Optional[User]] = relationship()


class SsoServer(IntegrationMixin, Base):
    """authentik: API reachable internally, login pages via Pangolin (public_url)."""

    __tablename__ = "sso_servers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), default="authentik")
    api_url: Mapped[str] = mapped_column(String(255), default="")        # internal, e.g. https://10.20.0.20:9443
    public_url: Mapped[str] = mapped_column(String(255), default="")     # e.g. https://auth.example.com
    token_enc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    system_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)


class SsoClient(Base):
    """An application connected to the SSO (OIDC provider + application in authentik)."""

    __tablename__ = "sso_clients"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sso_id: Mapped[int] = mapped_column(ForeignKey("sso_servers.id", ondelete="CASCADE"), index=True)
    target_kind: Mapped[str] = mapped_column(String(16))   # nextcloud | mailcow | pangolin | servermanager
    target_id: Mapped[int] = mapped_column(Integer)
    target_ref: Mapped[str] = mapped_column(String(64), default="")       # id inside the target (Pangolin IdP)
    secret_enc: Mapped[str] = mapped_column(Text, default="")             # client secret (servermanager login only)
    slug: Mapped[str] = mapped_column(String(64), default="")
    provider_pk: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    client_id: Mapped[str] = mapped_column(String(255), default="")
    app_url: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(16), default="pending")   # pending | active | error
    message: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


# rights that can be granted to authentik groups (applied to users logged in through the SSO)
GROUP_ACCESS_KINDS = (KIND_HETZNER, KIND_HETZNER_SRV, KIND_HCLOUD, KIND_HCLOUD_SRV)


class GroupAccess(Base):
    """Access level of an authentik group on an integration object (e.g. a Hetzner account or server)."""

    __tablename__ = "group_access"
    __table_args__ = (UniqueConstraint("group_name", "kind", "obj_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_name: Mapped[str] = mapped_column(String(150), index=True)
    kind: Mapped[str] = mapped_column(String(16))
    obj_id: Mapped[int] = mapped_column(Integer, index=True)
    level: Mapped[str] = mapped_column(String(16), default=LEVEL_VIEW)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


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
