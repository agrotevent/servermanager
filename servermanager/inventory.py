"""Connecting to systems, collecting facts and detecting pending updates."""
from __future__ import annotations

import logging
import time
from typing import Callable, Optional

from sqlalchemy.orm import Session

from . import settings
from .db import session_scope
from .models import (STATUS_ERROR, STATUS_OFFLINE, STATUS_ONLINE, System, utcnow)
from .modules import MODULES
from .modules.base import load_script
from .modules.debian import detect_types, parse_facts, release_upgrade_info
from .ssh import Connection, HostKeyError, SSHError, target_from_system

log = logging.getLogger(__name__)
Logger = Callable[[str], None]


def store_host_key(system_id: int, key_line: str) -> None:
    with session_scope() as db:
        s = db.get(System, system_id)
        if s is not None and not s.host_keys:
            s.host_keys = key_line
            log.info("stored host key for system %s: %s", system_id, key_line.split()[0])


def connect(system: System, timeout: Optional[int] = None) -> Connection:
    if timeout is None:
        with session_scope() as db:
            timeout = int(settings.get(db, "ssh.connect_timeout"))
    target = target_from_system(system, connect_timeout=timeout)
    sid = system.id
    conn = Connection(target, on_new_host_key=lambda line: store_host_key(sid, line))
    return conn.connect()


def run_facts(conn: Connection, system: System) -> tuple[dict, Optional[dict]]:
    body = load_script("facts.sh")
    env = {"SM_NC_PATH": system.nextcloud_path or ""}
    out: list[str] = []
    code = conn.run_script(body, env=env, root=True, on_output=out.append, timeout=180)
    text = "".join(out)
    if code != 0:
        raise SSHError(f"Inventur fehlgeschlagen ({code}): {text[-300:]}")
    return parse_facts(text)


def apply_facts(system: System, facts: dict, apt: Optional[dict]) -> None:
    system.facts = facts
    if facts.get("hostname"):
        system.hostname = facts["hostname"]
    upd = dict(system.updates or {})
    if apt is not None:
        upd["apt"] = apt
    else:
        upd.pop("apt", None)
    upd["reboot"] = {"required": bool(facts.get("reboot_required")), "reason": facts.get("reboot_reason", "")}
    rel = release_upgrade_info(system)
    if rel:
        upd["release"] = rel
    else:
        upd.pop("release", None)
    system.updates = upd
    system.status = STATUS_ONLINE
    system.status_message = ""
    system.last_seen = utcnow()
    system.last_check = utcnow()


def mark_unreachable(system: System, exc: Exception) -> None:
    system.status = STATUS_ERROR if isinstance(exc, HostKeyError) else STATUS_OFFLINE
    system.status_message = str(exc)[:1000]
    system.last_check = utcnow()


def quick_check(system_id: int) -> bool:
    """Connect, collect facts (incl. pending apt updates from the local cache)."""
    with session_scope() as db:
        system = db.get(System, system_id)
        if system is None:
            return False
        try:
            with connect(system) as conn:
                facts, apt = run_facts(conn, system)
        except Exception as exc:  # noqa: BLE001
            mark_unreachable(system, exc)
            return False
        apply_facts(system, facts, apt)
        return True


def deep_check(conn: Connection, db: Session, system: System, logger: Optional[Logger] = None,
               manual: bool = False, detect: bool = False) -> None:
    """Refresh package lists (if due), facts and module specific update checks.

    ``manual`` forces an ``apt-get update`` and the (pull based) Docker image check.
    """
    say = logger or (lambda s: None)
    apt_refresh = settings.get(db, "checks.apt_refresh")
    deep_hours = int(settings.get(db, "checks.deep_interval_hours") or 6)
    ctx = {
        "ispconfig_latest": settings.get(db, "state.ispconfig_latest"),
        "docker_image_check": bool(settings.get(db, "checks.docker_image_check") or manual),
    }
    lists_age = time.time() - int((system.fact or {}).get("apt_updated") or 0)
    if manual or (apt_refresh and lists_age > deep_hours * 3600 * 0.9):
        say("Paketlisten aktualisieren (apt-get update) ...\n")
        out: list[str] = []
        code = conn.run_script("apt-get -q -o DPkg::Lock::Timeout=300 update", root=True, on_output=out.append,
                               timeout=900)
        if code != 0:
            errors = [line for line in "".join(out).splitlines() if line.startswith(("E:", "W:", "Err"))]
            say("\n".join(errors[-10:]) + "\n[WARNUNG] apt-get update meldete Fehler (siehe oben)\n")
    say("Inventur / ausstehende Updates ermitteln ...\n")
    facts, apt = run_facts(conn, system)
    apply_facts(system, facts, apt)
    if detect:
        types = set(system.type_list) | set(detect_types(facts))
        new_types = types - set(system.type_list)
        system.types = sorted(types, key=lambda t: list(MODULES).index(t) if t in MODULES else 99)
        if "ispconfig" in new_types:
            from .integrations import ispconfig_auto
            if ispconfig_auto(db, system):
                say("ISPConfig erkannt – Einrichtung der Schnittstelle (Remote-API) ist eingeplant.\n")
    upd = dict(system.updates or {})
    for key, mod in MODULES.items():
        if key == "debian" or not mod.applies(system):
            continue
        try:
            say(f"{mod.label}: Updates prüfen ...\n")
            data = mod.check(conn, system, ctx)
            if data is not None:
                upd[key] = data
        except Exception as exc:  # noqa: BLE001
            say(f"[WARNUNG] {mod.label}: Prüfung fehlgeschlagen: {exc}\n")
            upd[key] = dict(upd.get(key) or {}, error=str(exc)[:300])
    system.updates = upd
    system.last_deep_check = utcnow()


def update_summary(system: System) -> dict:
    """Aggregate pending updates of a system for the overview page."""
    items = []
    total = 0
    for key, mod in MODULES.items():
        if not mod.applies(system):
            continue
        s = mod.summary(system)
        if s:
            items.append(dict(s, module=key, label=mod.label))
            total += s.get("count", 0)
    upd = system.upd
    rel = release_upgrade_info(system)
    reboot = (upd.get("reboot") or {}).get("required", False)
    return {"items": items, "total": total, "release": rel, "reboot": reboot,
            "security": int((upd.get("apt") or {}).get("security") or 0)}


def has_pending_updates(system: System) -> bool:
    s = update_summary(system)
    return s["total"] > 0
