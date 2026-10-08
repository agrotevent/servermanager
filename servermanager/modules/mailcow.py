"""mailcow-dockerized: update check and update with the official update.sh, backup, container status (SSH).

The users, mailboxes and domains are managed through the API (Infrastruktur → Mailcow); this module covers what
only works on the host itself.
"""
from __future__ import annotations

import time
from typing import Optional

from ..models import LEVEL_FULL, System
from .base import Action, Module, Param, parse_kv, run_module_script

PATH_RE = r"^/[A-Za-z0-9._/-]{1,200}$"
DEFAULT_PATH = "/opt/mailcow-dockerized"


class MailcowModule(Module):
    key = "mailcow"
    label = "Mailcow"
    description = "Update (update.sh), Sicherung, Container-Status"
    panel_template = "modules/mailcow.html"

    def build_actions(self) -> list[Action]:
        t = "mailcow.sh"
        backup_dir = Param("backup_dir", "Sicherungsordner", pattern=PATH_RE, default="/var/backups/mailcow",
                           required=False, help="helper-scripts/backup_and_restore.sh backup all")
        return [
            Action("check", "Update prüfen", t, env={"SM_TASK": "check"}, group="Updates",
                   description="update.sh --check"),
            Action("update", "Mailcow aktualisieren", t, env={"SM_TASK": "update"}, group="Updates",
                   level=LEVEL_FULL, detached=True, timeout=2 * 3600, danger=True,
                   params=[Param("backup", "Vorher sichern", kind="bool", default="0", required=False), backup_dir,
                           Param("skip_ping", "Internet-Prüfung per Ping überspringen", kind="bool", default="0",
                                 required=False, help="--skip-ping-check, wenn ICMP nach außen gesperrt ist")],
                   description="Offizielles update.sh mit --force (ohne Rückfragen): neuer Code, neue Images, "
                               "Container neu starten. Läuft das Skript nach einer Selbstaktualisierung ein zweites "
                               "Mal, übernimmt der Servermanager das.",
                   confirm="Mailcow jetzt aktualisieren? Die Container werden neu gestartet – Mail und Webmail "
                           "sind dabei einige Minuten nicht erreichbar."),
            Action("backup", "Sicherung erstellen", t, env={"SM_TASK": "backup"}, group="Wartung",
                   level=LEVEL_FULL, detached=True, timeout=6 * 3600, params=[backup_dir],
                   description="helper-scripts/backup_and_restore.sh backup all (Mails, Datenbank, Konfiguration)"),
        ]

    def detect(self, facts: dict) -> bool:
        return bool(facts.get("mailcow_path"))

    def env(self, system: System) -> dict:
        return {"SM_MC_PATH": system.fact.get("mailcow_path") or DEFAULT_PATH}

    def check(self, conn, system: System, ctx: dict) -> Optional[dict]:
        kv = parse_kv(run_module_script(conn, self, "mailcow.sh", dict(self.env(system), SM_TASK="check"),
                                        timeout=180))
        return {"installed": (kv.get("mailcow_version") or [""])[0],
                "available": (kv.get("mailcow_update") or [""])[0] == "yes", "checked": int(time.time())}

    def panel(self, conn, system: System) -> dict:
        kv = parse_kv(run_module_script(conn, self, "mailcow.sh", dict(self.env(system), SM_TASK="status"),
                                        timeout=60))
        containers = []
        for line in kv.get("container", []):
            name, _, state = line.partition("|")
            containers.append({"name": name, "state": state})
        return {"version": (kv.get("mailcow_version") or [""])[0], "branch": (kv.get("mailcow_branch") or [""])[0],
                "containers": containers, "path": self.env(system)["SM_MC_PATH"],
                "upd": system.upd.get("mailcow") or {}}

    def summary(self, system: System) -> Optional[dict]:
        d = system.upd.get("mailcow") or {}
        if not d.get("available"):
            return None
        return {"count": 1, "text": "Mailcow-Update", "severity": "warn"}
