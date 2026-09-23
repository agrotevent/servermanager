"""ISPConfig module."""
from __future__ import annotations

import re
import time
from typing import Optional

from ..models import System
from .base import Action, Module, parse_kv, run_module_script


def version_tuple(v: str) -> tuple:
    """'3.2.11p2' -> (3, 2, 11, 2)"""
    nums = [int(x) for x in re.findall(r"\d+", v or "")]
    return tuple(nums + [0] * (4 - len(nums)))


def is_newer(latest: str, installed: str) -> bool:
    if not latest or not installed:
        return False
    return version_tuple(latest) > version_tuple(installed)


class ISPConfigModule(Module):
    key = "ispconfig"
    label = "ISPConfig"
    description = "Version, Update, Dienste, Mail-Warteschlange"
    panel_template = "modules/ispconfig.html"

    def build_actions(self) -> list[Action]:
        t = "ispconfig.sh"
        return [
            Action("update", "ISPConfig aktualisieren", t, env={"SM_TASK": "update"}, group="Updates",
                   detached=True, timeout=2 * 3600, danger=True,
                   description="Lädt die aktuelle stabile Version und führt das Update unbeaufsichtigt aus "
                               "(ISPConfig-Backup, Dienste neu konfigurieren, Crontab neu schreiben).",
                   confirm="ISPConfig-Update starten? Dienste werden dabei neu konfiguriert."),
            Action("mailqueue_flush", "Mail-Warteschlange abarbeiten", t, env={"SM_TASK": "mailqueue_flush"},
                   group="Mail"),
        ]

    def detect(self, facts: dict) -> bool:
        return bool(facts.get("ispconfig_version"))

    def check(self, conn, system: System, ctx: dict) -> Optional[dict]:
        installed = system.fact.get("ispconfig_version", "")
        latest = ctx.get("ispconfig_latest") or ""
        if not latest:
            kv = parse_kv(run_module_script(conn, self, "ispconfig.sh", {"SM_TASK": "check"}, timeout=60))
            latest = (kv.get("latest") or [""])[0]
            installed = (kv.get("installed") or [installed])[0]
        return {"installed": installed, "latest": latest, "available": is_newer(latest, installed),
                "checked": int(time.time())}

    def panel(self, conn, system: System) -> dict:
        kv = parse_kv(run_module_script(conn, self, "ispconfig.sh", {"SM_TASK": "status"}, timeout=60))
        services = []
        for line in kv.get("service", []):
            name, _, state = line.partition("|")
            services.append({"name": name, "state": state})
        return {"version": (kv.get("version") or [""])[0], "port": (kv.get("port") or [""])[0],
                "services": services, "mailqueue": (kv.get("mailqueue") or ["?"])[0],
                "cron_errors": (kv.get("cronlog_errors") or ["0"])[0],
                "upd": system.upd.get("ispconfig") or {}}

    def summary(self, system: System) -> Optional[dict]:
        d = system.upd.get("ispconfig") or {}
        if not d.get("available"):
            return None
        return {"count": 1, "text": f"ISPConfig {d.get('latest')}", "severity": "warn"}
