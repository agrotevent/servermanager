"""Newt: tunnel client of a Pangolin site (runs in a small container/VM of the internal network)."""
from __future__ import annotations

from ..models import LEVEL_FULL, System
from .base import Action, Module, parse_kv, run_module_script


class NewtModule(Module):
    key = "newt"
    label = "Newt (Pangolin-Tunnel)"
    description = "Tunnel-Client einer Pangolin-Site: Status, Neustart, Update"
    panel_template = "modules/newt.html"

    def build_actions(self) -> list[Action]:
        t = "newt.sh"
        return [
            Action("restart", "Newt neu starten", t, env={"SM_TASK": "restart"}, group="Tunnel",
                   description="Tunnel neu aufbauen (Dienste sind kurz nicht erreichbar)", timeout=300),
            Action("update", "Newt aktualisieren", t, env={"SM_TASK": "update"}, group="Tunnel", level=LEVEL_FULL,
                   description="Neueste Version von GitHub laden und neu starten", timeout=900),
        ]

    def detect(self, facts: dict) -> bool:
        return bool(facts.get("newt_version"))

    def panel(self, conn, system: System) -> dict:
        kv = parse_kv(run_module_script(conn, self, "newt.sh", {"SM_TASK": "status"}, timeout=60))
        first = {k: v[-1] for k, v in kv.items() if k != "log"}
        first["log"] = kv.get("log", [])
        return first
