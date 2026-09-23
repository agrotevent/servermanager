"""Enrollment of new systems via a one-time token and the client script."""
from __future__ import annotations

import logging
import re
import secrets
from datetime import timedelta
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import access, security, settings, sshkeys, wireguard
from .jobs import enqueue
from .mikrotik import MikroTikError
from .models import (AUTH_KEY, CONN_DIRECT, CONN_WIREGUARD, LEVEL_FULL, LEVELS, STATUS_PENDING, SUDO_NONE,
                     SUDO_NOPASSWD, EnrollmentToken, System, User, utcnow)
from .modules import MODULES
from .ssh import parse_host_keys

log = logging.getLogger(__name__)

HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
DEDICATED_USER = "smadmin"
# bash uses "${#var}" - move Jinja's comment syntax out of the way
_env = Environment(loader=FileSystemLoader(str(Path(__file__).parent / "web" / "templates" / "enroll")),
                   autoescape=False, keep_trailing_newline=True,
                   comment_start_string="<#jinja#", comment_end_string="#jinja#>")


class EnrollError(Exception):
    def __init__(self, msg: str, status: int = 400):
        super().__init__(msg)
        self.status = status


def create_token(db: Session, user: User, *, name: str, connection: str, ssh_user_mode: str, types: list[str],
                 routed: str, tags: str, assign: list[dict], valid_hours: int, max_uses: int,
                 bind_system_id: Optional[int] = None) -> tuple[str, EnrollmentToken]:
    token = security.new_token(24)
    row = EnrollmentToken(
        name=name.strip()[:128], token_hash=security.token_hash(token), token_hint=token[:6],
        connection=connection if connection in (CONN_WIREGUARD, CONN_DIRECT) else CONN_WIREGUARD,
        ssh_user_mode=ssh_user_mode if ssh_user_mode in ("root", "dedicated") else "root",
        system_types=[t for t in types if t in MODULES],
        routed_subnets=" ".join(wireguard.validate_routed(db, wireguard.parse_subnets(routed))),
        tags=tags.strip()[:255], assign=assign, bind_system_id=bind_system_id,
        max_uses=max(1, min(max_uses, 1000)), expires_at=utcnow() + timedelta(hours=max(1, min(valid_hours, 24 * 90))),
        created_by=user.id,
    )
    db.add(row)
    db.flush()
    return token, row


def find_token(db: Session, token: str) -> Optional[EnrollmentToken]:
    if not token or len(token) > 100:
        return None
    return db.execute(select(EnrollmentToken).where(
        EnrollmentToken.token_hash == security.token_hash(token))).scalar_one_or_none()


def curl_opts(db: Session) -> str:
    pin = settings.get(db, "enroll.tls_pin")
    if pin:
        return f"-k --pinnedpubkey 'sha256//{pin}'"
    if settings.get(db, "enroll.insecure_tls"):
        return "-k"
    return ""


def install_command(db: Session, token: str) -> dict:
    base = settings.base_url(db)
    opts = curl_opts(db)
    url = f"{base}/enroll/{token}.sh"
    curl = f"curl -fsSL {opts + ' ' if opts else ''}{url} | bash"
    wget_opts = "--no-check-certificate " if opts else ""
    wget = f"wget -qO- {wget_opts}{url} | bash"
    return {"url": url, "curl": curl, "wget": wget}


def render_script(db: Session, token: str, row: Optional[EnrollmentToken]) -> str:
    if row is None or not row.is_valid:
        return ("#!/bin/sh\necho 'Servermanager: Enrollment-Token ungültig oder abgelaufen.' >&2\nexit 1\n")
    tpl = _env.get_template("client.sh.j2")
    return tpl.render(
        base_url=settings.base_url(db), token=token, connection=row.connection,
        curl_opts=curl_opts(db), wg_iface=settings.get(db, "wg.client_iface") or "wg-mgmt",
        ssh_user_mode=row.ssh_user_mode, dedicated_user=DEDICATED_USER,
    )


def _clean(value: Optional[str], maxlen: int = 255) -> str:
    return re.sub(r"[\x00-\x1f]", "", (value or "").strip())[:maxlen]


def _unique_name(db: Session, name: str) -> str:
    base = name or "system"
    candidate = base
    i = 2
    while db.execute(select(System.id).where(System.name == candidate)).first():
        candidate = f"{base}-{i}"
        i += 1
    return candidate


def enroll(db: Session, token: str, form: dict, remote_addr: str) -> dict:
    row = find_token(db, token)
    if row is None or not row.is_valid:
        raise EnrollError("Token ungültig, abgelaufen oder bereits verwendet", 403)
    hostname = _clean(form.get("hostname"), 253)
    if not HOST_RE.match(hostname):
        raise EnrollError("Ungültiger Hostname")
    host_keys = "\n".join(f"{t} {k}" for t, k in parse_host_keys(
        (form.get("host_keys") or "").replace("|", "\n")))
    if not host_keys:
        raise EnrollError("Keine gültigen SSH-Hostkeys übermittelt")
    try:
        ssh_port = int(form.get("ssh_port") or 22)
        if not 0 < ssh_port < 65536:
            raise ValueError
    except ValueError as exc:
        raise EnrollError("Ungültiger SSH-Port") from exc

    connection = row.connection
    creator = db.get(User, row.created_by) if row.created_by else None
    trusted = bool(creator and creator.is_admin)
    if form.get("mode") == CONN_DIRECT:
        connection = CONN_DIRECT
    wg_pub = _clean(form.get("wg_public_key"), 64)
    if connection == CONN_WIREGUARD:
        if not settings.get(db, "wg.enabled"):
            raise EnrollError("WireGuard ist im Servermanager nicht aktiviert", 409)
        if not wireguard.valid_key(wg_pub):
            raise EnrollError("Ungültiger WireGuard-Public-Key")
        if db.execute(select(System.id).where(System.wg_public_key == wg_pub)).first():
            raise EnrollError("Dieser WireGuard-Schlüssel ist bereits registriert")

    root_login = _clean(form.get("root_login"), 32).lower()
    user_mode = row.ssh_user_mode
    if user_mode == "root" and root_login == "no":
        user_mode = "dedicated"
    ssh_user = "root" if user_mode == "root" else DEDICATED_USER

    system: Optional[System] = db.get(System, row.bind_system_id) if row.bind_system_id else None
    new = system is None
    if new:
        name = _clean(row.name if row.max_uses == 1 and row.name else "", 128) or \
            _clean(form.get("name"), 128) or hostname.split(".")[0]
        system = System(name=_unique_name(db, name), tags=row.tags, created_by=row.created_by)
        db.add(system)
        db.flush()
    assert system is not None
    old_refs = dict(system.mt_refs or {}) if not new else {}

    system.hostname = hostname
    system.connection = connection
    system.port = ssh_port
    system.username = ssh_user
    system.auth_method = AUTH_KEY
    system.password_enc = None
    system.private_key_enc = None
    system.sudo_mode = SUDO_NONE if ssh_user == "root" else SUDO_NOPASSWD
    system.host_keys = host_keys
    types = list(row.system_types or [])
    detected = [t for t in _clean(form.get("detected"), 200).split(",") if t in MODULES]
    system.types = sorted(set(["debian"] + types + detected), key=lambda t: list(MODULES).index(t))
    nc_path = _clean(form.get("nextcloud_path"), 255)
    if nc_path.startswith("/") and not system.nextcloud_path:
        system.nextcloud_path = nc_path
    system.status = STATUS_PENDING
    system.status_message = "Warte auf Bestätigung des Client-Skripts"
    secret = secrets.token_urlsafe(24)
    system.enroll_secret_hash = security.token_hash(secret)
    system.facts = dict(system.facts or {}, os_name=_clean(form.get("os_name"), 128))

    response = {"SM_STATUS": "ok", "SM_SYSTEM_ID": str(system.id), "SM_SYSTEM_NAME": system.name,
                "SM_CONFIRM_SECRET": secret, "SM_SSH_USER": ssh_user, "SM_SSH_PUBKEY": sshkeys.public_key(),
                "SM_CONNECTION": connection}
    if connection == CONN_WIREGUARD:
        routed = wireguard.parse_subnets(row.routed_subnets)
        try:
            mt = wireguard.api(db)
            if not system.wg_ip:
                system.wg_ip = wireguard.allocate_ip(db, extra_used=wireguard.peer_ips(db, mt))
            if old_refs:
                wireguard.remove_refs(mt, old_refs)  # re-enrollment: replace the old peer
            wireguard.provision_peer(db, system, wg_pub, routed, mt)
            router_key = wireguard.router_public_key(db)
        except (MikroTikError, ValueError) as exc:
            raise EnrollError(f"WireGuard-Zugang konnte nicht angelegt werden: {exc}", 502) from exc
        system.routed_subnets = " ".join(routed)
        system.host = system.wg_ip
        net = wireguard.mgmt_network(db)
        response.update({
            "SM_WG_IFACE": settings.get(db, "wg.client_iface") or "wg-mgmt",
            "SM_WG_ADDRESS": f"{system.wg_ip}/32",
            "SM_WG_PEER_PUBKEY": router_key,
            "SM_WG_ENDPOINT": settings.get(db, "wg.endpoint"),
            "SM_WG_ALLOWED_IPS": str(net),
            "SM_WG_KEEPALIVE": str(int(settings.get(db, "wg.keepalive") or 25)),
            "SM_WG_MTU": str(int(settings.get(db, "wg.mtu") or 1420)),
            "SM_ROUTED_SUBNETS": " ".join(routed),
            "SM_MGMT_NET": str(net),
            "SM_SSH_FROM": settings.get(db, "wg.sm_ip") if settings.get(db, "enroll.restrict_ssh_source") else "",
        })
    else:
        # Only tokens of administrators may register an arbitrary address. Otherwise the system is
        # registered with the address the request came from: the servermanager key must never be
        # pointed at a host the token holder does not control.
        address = (_clean(form.get("address"), 255) if trusted else "") or remote_addr
        if not address or not re.match(r"^[A-Za-z0-9.:-]+$", address):
            raise EnrollError("Keine gültige Adresse für die direkte Verbindung")
        dup = db.execute(select(System.id).where(System.host == address, System.port == ssh_port,
                                                 System.id != system.id)).first()
        if dup and not trusted:
            raise EnrollError("Unter dieser Adresse ist bereits ein System registriert - bitte einen Administrator "
                              "ein erneutes Enrollment für dieses System erstellen lassen.", 409)
        if old_refs:
            try:
                wireguard.remove_refs(wireguard.api(db), old_refs)
            except MikroTikError as exc:
                log.warning("cleanup of old peer failed: %s", exc)
            system.mt_refs = {}
            system.wg_ip = ""
            system.wg_public_key = ""
        system.host = address
        src = settings.get(db, "enroll.direct_source") if settings.get(db, "enroll.restrict_ssh_source") else ""
        response["SM_SSH_FROM"] = src or ""

    for a in row.assign or []:
        try:
            uid = int(a.get("user_id"))
        except (TypeError, ValueError):
            continue
        level = a.get("level") if a.get("level") in LEVELS else "view"
        if db.get(User, uid):
            access.grant(db, uid, system.id, level)
    if row.created_by and new:
        creator = db.get(User, row.created_by)
        if creator and not creator.is_admin:
            access.grant(db, creator.id, system.id, LEVEL_FULL)
    row.uses += 1
    row.last_used_at = utcnow()
    if connection == CONN_WIREGUARD and system.routed_subnet_list:
        wireguard.refresh_local_routes(db)
    return response


def confirm(db: Session, system_id: int, secret: str, status: str, message: str) -> System:
    system = db.get(System, system_id)
    if system is None or not system.enroll_secret_hash or \
            not security.const_eq(system.enroll_secret_hash, security.token_hash(secret or "")):
        raise EnrollError("Ungültige Bestätigung", 403)
    system.enroll_secret_hash = ""
    if status != "ok":
        system.status = "error"
        system.status_message = f"Client-Skript meldet Fehler: {_clean(message, 500)}"
        return system
    system.status_message = "Client eingerichtet - Verbindungsprüfung läuft"
    enqueue(db, kind="enroll_verify", title=f"Enrollment prüfen: {system.name}", system=system)
    return system
