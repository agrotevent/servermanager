"""Nextcloud module (occ based)."""
from __future__ import annotations

import json
import re
import time
from typing import Optional

from ..models import LEVEL_FULL, System
from .base import Action, Module, run_module_script

CORE_RE = re.compile(r"(?:Nextcloud|ownCloud)\s+([0-9][0-9.]*)\s+is available", re.I)
APP_RE = re.compile(r"Update for\s+(\S+)\s+to version\s+(\S+)\s+is available", re.I)


def parse_check(text: str) -> dict:
    status: dict = {}
    updates_txt = ""
    if "__STATUS__" in text:
        after = text.split("__STATUS__", 1)[1]
        status_txt, _, updates_txt = after.partition("__UPDATES__")
        m = re.search(r"\{.*\}", status_txt, re.S)
        if m:
            try:
                status = json.loads(m.group(0))
            except ValueError:
                status = {}
    core = None
    m = CORE_RE.search(updates_txt)
    if m:
        core = m.group(1)
    apps = [{"app": a, "version": v} for a, v in APP_RE.findall(updates_txt)]
    return {
        "installed": status.get("versionstring", ""),
        "maintenance": bool(status.get("maintenance")),
        "needs_db_upgrade": bool(status.get("needsDbUpgrade")),
        "core": core,
        "apps": apps,
        "checked": int(time.time()),
    }


class NextcloudModule(Module):
    key = "nextcloud"
    label = "Nextcloud"
    description = "Status, App- und Core-Updates, Wartungsmodus, Reparaturen"
    panel_template = "modules/nextcloud.html"

    def build_actions(self) -> list[Action]:
        t = "nextcloud.sh"
        return [
            Action("status", "Status & Update-Prüfung", t, env={"SM_TASK": "status"}, group="Status"),
            Action("apps_update", "Apps aktualisieren", t, env={"SM_TASK": "apps_update"}, group="Updates",
                   confirm="Alle Nextcloud-Apps aktualisieren?"),
            Action("core_update", "Nextcloud aktualisieren (Core)", t, env={"SM_TASK": "core_update"},
                   group="Updates", level=LEVEL_FULL, detached=True, timeout=3 * 3600, danger=True,
                   description="Führt den offiziellen Updater (updater.phar) aus, danach occ upgrade und "
                               "Datenbank-Reparaturen. Die Nextcloud ist währenddessen im Wartungsmodus.",
                   confirm="Nextcloud-Core-Update starten? Die Instanz ist währenddessen nicht erreichbar."),
            Action("maintenance_on", "Wartungsmodus an", t, env={"SM_TASK": "maintenance_on"}, group="Wartung"),
            Action("maintenance_off", "Wartungsmodus aus", t, env={"SM_TASK": "maintenance_off"}, group="Wartung"),
            Action("db_repair", "DB-Indizes ergänzen", t, env={"SM_TASK": "db_repair"}, group="Wartung",
                   description="db:add-missing-indices / -columns / -primary-keys"),
            Action("repair", "Reparatur (maintenance:repair)", t, env={"SM_TASK": "repair"}, group="Wartung"),
            Action("repair_expensive", "Reparatur inkl. aufwendiger Schritte", t,
                   env={"SM_TASK": "repair_expensive"}, group="Wartung", level=LEVEL_FULL, timeout=6 * 3600),
            Action("files_scan", "Dateien neu einlesen", t, env={"SM_TASK": "files_scan"}, group="Wartung",
                   level=LEVEL_FULL, timeout=12 * 3600, detached=True),
            Action("cron", "Hintergrundjobs ausführen", t, env={"SM_TASK": "cron"}, group="Wartung"),
        ]

    def detect(self, facts: dict) -> bool:
        return bool(facts.get("nextcloud"))

    def env(self, system: System) -> dict:
        path = system.nextcloud_path
        if not path:
            found = system.fact.get("nextcloud") or []
            path = found[0]["path"] if found and found[0].get("path") != "snap" else ""
        env = {"SM_NC_PATH": path}
        if system.occ_command:
            env["SM_OCC"] = system.occ_command
        elif (system.fact.get("nextcloud") or [{}])[0].get("path") == "snap" and not system.nextcloud_path:
            env["SM_OCC"] = "nextcloud.occ"
        return env

    def check(self, conn, system: System, ctx: dict) -> Optional[dict]:
        env = dict(self.env(system), SM_TASK="check")
        text = run_module_script(conn, self, "nextcloud.sh", env, timeout=180)
        return parse_check(text)

    def panel(self, conn, system: System) -> dict:
        data = self.check(conn, system, {}) or {}
        return {"nc": data, "path": self.env(system).get("SM_NC_PATH", "")}

    def summary(self, system: System) -> Optional[dict]:
        nc = system.upd.get("nextcloud") or {}
        count = len(nc.get("apps") or []) + (1 if nc.get("core") else 0)
        if not count:
            return None
        parts = []
        if nc.get("core"):
            parts.append(f"Nextcloud {nc['core']}")
        if nc.get("apps"):
            parts.append(f"{len(nc['apps'])} App(s)")
        return {"count": count, "text": ", ".join(parts), "severity": "warn"}


# --------------------------------------------------------------------------
# user management and SSO (synchronous occ calls)
# --------------------------------------------------------------------------
UID_RE = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")
GROUP_RE = re.compile(r"^[A-Za-z0-9 ._@-]{1,64}$")
QUOTA_RE = re.compile(r"^(none|default|[0-9]+(\.[0-9]+)? ?(B|KB|MB|GB|TB))$", re.I)


def occ_task(conn, system: System, task: str, extra: Optional[dict] = None, timeout: int = 180) -> str:
    from . import get_module
    mod = get_module("nextcloud")
    env = dict(mod.env(system), SM_TASK=task, **(extra or {}))
    return run_module_script(conn, mod, "nextcloud.sh", env, timeout=timeout)


def _json_after(text: str, marker: str, end: Optional[str] = None):
    if marker not in text:
        return None
    part = text.split(marker, 1)[1]
    if end and end in part:
        part = part.split(end, 1)[0]
    m = re.search(r"[\[{].*[\]}]", part, re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except ValueError:
        return None


def parse_users(text: str) -> tuple[list[dict], list[str]]:
    data = _json_after(text, "__USERS__", "__GROUPS__") or {}
    groups = _json_after(text, "__GROUPS__") or {}
    users = []
    for uid, info in (data.items() if isinstance(data, dict) else []):
        if isinstance(info, dict):
            users.append({"uid": uid, "display": info.get("display_name") or info.get("displayname") or "",
                          "email": info.get("email") or "", "enabled": info.get("enabled", True) is not False,
                          "groups": info.get("groups") or [], "quota": info.get("quota") or "",
                          "last_seen": info.get("last_seen") or info.get("lastLogin") or "",
                          "backend": info.get("backend") or ""})
        else:
            users.append({"uid": uid, "display": str(info), "email": "", "enabled": True, "groups": [],
                          "quota": "", "last_seen": "", "backend": ""})
    users.sort(key=lambda u: u["uid"].lower())
    group_names = sorted(groups.keys()) if isinstance(groups, dict) else []
    return users, group_names


def validate_user(uid: str, email: str = "", groups: str = "", quota: str = "") -> dict:
    if not UID_RE.match(uid or ""):
        raise ValueError("Ungültige Benutzer-ID (Buchstaben, Ziffern, . _ @ -)")
    if email and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        raise ValueError("Ungültige E-Mail-Adresse")
    gl = [g.strip() for g in (groups or "").split(",") if g.strip()]
    for g in gl:
        if not GROUP_RE.match(g):
            raise ValueError(f"Ungültige Gruppe {g}")
    if quota and not QUOTA_RE.match(quota.strip()):
        raise ValueError("Quota z. B. 10 GB, none oder default")
    return {"SM_UID": uid, "SM_EMAIL": email, "SM_GROUPS": ",".join(gl), "SM_QUOTA": quota.strip()}
