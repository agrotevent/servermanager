"""Asterisk / FreePBX: status, reload/restart, FreePBX module updates."""
from __future__ import annotations

import time
from typing import Optional

from ..models import LEVEL_FULL, System
from .base import Action, Module, run_module_script


class AsteriskModule(Module):
    key = "asterisk"
    label = "Asterisk/FreePBX"
    description = "Telefonanlage: Status, Trunks, Neu laden, FreePBX-Modul-Updates"
    panel_template = "modules/asterisk.html"

    def build_actions(self) -> list[Action]:
        t = "asterisk.sh"
        return [
            Action("reload", "Konfiguration neu laden", t, env={"SM_TASK": "reload"}, group="Telefonanlage",
                   description="fwconsole reload bzw. core reload – Gespräche bleiben bestehen", timeout=600),
            Action("module_upgrade", "FreePBX-Module aktualisieren", t, env={"SM_TASK": "module_upgrade"},
                   group="Updates", level=LEVEL_FULL, timeout=3600,
                   description="fwconsole ma upgradeall, danach Rechte korrigieren und neu laden",
                   confirm="Alle FreePBX-Module aktualisieren?"),
            Action("restart", "Asterisk neu starten", t, env={"SM_TASK": "restart"}, group="Telefonanlage",
                   level=LEVEL_FULL, danger=True, timeout=600,
                   confirm="Asterisk neu starten? Laufende Gespräche werden getrennt."),
        ]

    def detect(self, facts: dict) -> bool:
        return bool(facts.get("asterisk_version"))

    def check(self, conn, system: System, ctx: dict) -> Optional[dict]:
        if not system.fact.get("freepbx"):
            return None
        from ..pbx import parse_upgrades
        text = run_module_script(conn, self, "asterisk.sh", {"SM_TASK": "check"}, timeout=300)
        return {"modules": parse_upgrades(text), "checked": int(time.time())}

    def panel(self, conn, system: System) -> dict:
        from ..pbx import parse_status
        data = parse_status(run_module_script(conn, self, "asterisk.sh", {"SM_TASK": "status"}, timeout=90))
        data["upgrades"] = (system.upd.get("asterisk") or {}).get("modules") or []
        return data

    def summary(self, system: System) -> Optional[dict]:
        mods = (system.upd.get("asterisk") or {}).get("modules") or []
        if not mods:
            return None
        return {"count": len(mods), "text": f"{len(mods)} FreePBX-Modul(e)", "severity": "warn"}
