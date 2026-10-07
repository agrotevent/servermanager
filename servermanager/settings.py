"""Runtime settings stored in the database (editable in the web UI)."""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from . import security
from .models import Setting

DEFAULTS: dict[str, Any] = {
    # general
    "general.site_name": "Servermanager",
    "general.base_url": "",
    "general.timezone": "Europe/Berlin",
    "general.session_hours": 12,
    "general.require_2fa_admin": False,
    # appearance (corporate design)
    "brand.primary": "",
    "brand.sidebar": "",
    "brand.accent": "",
    "brand.font": "setnetz",
    "brand.default_logo": True,        # Setnetz logos as long as no own logo is uploaded
    "brand.logo_only": False,
    "brand.logo_data": "",
    "brand.logo_type": "",
    "brand.logo_light_data": "",       # optional logo for light backgrounds (login card)
    "brand.logo_light_type": "",
    "brand.font_data": "",
    "brand.font_type": "",
    # login through the SSO (authentik)
    "login.sso_auto_create": False,      # unknown SSO users are created (role user, no rights)
    "login.sso_group": "",               # only members of this authentik group may log in
    "login.sso_admins": False,           # administrators may log in through the SSO too
    # periodic checks
    "checks.status_interval_min": 15,
    "checks.deep_interval_hours": 6,
    "checks.apt_refresh": True,
    "checks.docker_image_check": False,
    "checks.parallel": 8,
    # ssh / jobs
    "ssh.connect_timeout": 15,
    "jobs.max_parallel": 8,
    "jobs.log_retention_days": 90,
    # wireguard / mikrotik
    "wg.enabled": False,
    "wg.mikrotik_url": "",
    "wg.mikrotik_user": "servermanager",
    "wg.mikrotik_password": "",
    "wg.mikrotik_verify_tls": False,
    "wg.mikrotik_fingerprint": "",       # pinned certificate of the router's REST API
    "wg.mikrotik_interface": "wg-mgmt",
    "wg.network": "10.66.0.0/24",
    "wg.router_ip": "10.66.0.1",
    "wg.sm_ip": "10.66.0.2",
    "wg.pool_start": 10,
    "wg.listen_port": 13231,
    "wg.endpoint": "",
    "wg.sm_endpoint": "",
    "wg.router_public_key": "",
    "wg.sm_private_key": "",
    "wg.sm_public_key": "",
    "wg.local_iface": "wg-sm",
    "wg.client_iface": "wg-mgmt",
    "wg.keepalive": 25,
    "wg.mtu": 1420,
    "wg.address_list": "servermanager-clients",
    # enrollment
    "enroll.tls_pin": "",
    "enroll.insecure_tls": False,
    "enroll.restrict_ssh_source": True,
    "enroll.direct_source": "",
    "enroll.default_valid_hours": 24,
    # servermanager backups
    "backup.auto_enabled": True,
    "backup.hour": 2,
    "backup.keep": 14,
    "backup.passphrase": "",
    "backup.include_system_backups": False,
    "backup.before_update": True,
    "system_backup.keep": 10,
    # mail notifications
    "mail.enabled": False,
    "mail.host": "",
    "mail.port": 587,
    "mail.security": "starttls",
    "mail.user": "",
    "mail.password": "",
    "mail.sender": "",
    "mail.admin_recipients": "",
    "mail.notify_failures": True,
    # API connections (Proxmox, RouterOS, Pangolin)
    "integrations.poll_min": 5,
    "integrations.disk_alert_pct": 90,
    "integrations.notify": True,
    "ispconfig.auto_setup": True,        # set up the remote API when an ISPConfig system is detected
    # cached state
    "state.ispconfig_latest": "",
    "state.ispconfig_checked": "",
    "state.update_remote_sha": "",
    "state.update_checked": "",
    "state.update_log": "",
    "state.last_auto_backup": "",
}

SECRET_KEYS = {"wg.mikrotik_password", "wg.sm_private_key", "backup.passphrase", "mail.password"}


def _row(db: Session, key: str) -> Setting | None:
    row = db.get(Setting, key)
    if row is None:
        # autoflush is disabled - also look at settings added in this session but not flushed yet
        row = next((o for o in db.new if isinstance(o, Setting) and o.key == key), None)
    return row


def get(db: Session, key: str, default: Any = None) -> Any:
    row = _row(db, key)
    if row is None or row.value is None:
        return DEFAULTS.get(key, default) if default is None else default
    value = row.value
    if key in SECRET_KEYS:
        try:
            return security.decrypt(value) if value else ""
        except RuntimeError:
            return ""
    return value


def set(db: Session, key: str, value: Any) -> None:  # noqa: A001 - mirrors dict API
    if key in SECRET_KEYS:
        value = security.encrypt(value) if value else ""
    row = _row(db, key)
    if row is None:
        db.add(Setting(key=key, value=value))
    else:
        row.value = value


def get_many(db: Session, prefix: str) -> dict[str, Any]:
    out = {k: v for k, v in DEFAULTS.items() if k.startswith(prefix)}
    for row in db.query(Setting).filter(Setting.key.like(prefix + "%")).all():
        out[row.key] = get(db, row.key)
    return out


def coerce(key: str, raw: Any) -> Any:
    """Convert a form value to the type of the default."""
    default = DEFAULTS.get(key)
    if isinstance(default, bool):
        return str(raw).lower() in ("1", "true", "on", "yes", "ja")
    if isinstance(default, int):
        try:
            return int(str(raw).strip())
        except ValueError:
            return default
    return "" if raw is None else str(raw).strip()


def base_url(db: Session) -> str:
    from .config import get_config
    return (get(db, "general.base_url") or get_config().base_url).rstrip("/")
