"""Proxmox VE module."""
from __future__ import annotations

import json
import re
from typing import Optional

from ..models import System
from .base import Action, Module, Param

NODE_RE = r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$"


class ProxmoxModule(Module):
    key = "proxmox"
    label = "Proxmox VE"
    description = "VMs/Container, Sicherungen, Upgrade-Prüfung"
    panel_template = "modules/proxmox.html"

    def build_actions(self) -> list[Action]:
        t = "proxmox.sh"
        guest = [Param("node", "Node", pattern=NODE_RE),
                 Param("type", "Typ", kind="select", choices=[("qemu", "VM"), ("lxc", "Container")]),
                 Param("vmid", "VMID", pattern=r"^[0-9]{1,9}$")]
        return [
            Action("upgrade_check", "Upgrade-Prüfung (pve8to9)", t, env={"SM_TASK": "upgrade_check"},
                   group="Updates", description="Führt den offiziellen Proxmox-Upgrade-Checker aus"),
            Action("guest_action", "Gast-Aktion", t, env={"SM_TASK": "guest_action"}, hidden=True,
                   params=guest + [Param("op", "Aktion", kind="select",
                                         choices=[("start", "Start"), ("shutdown", "Herunterfahren"),
                                                  ("reboot", "Neustart"), ("stop", "Hart stoppen"),
                                                  ("suspend", "Pausieren"), ("resume", "Fortsetzen")])]),
            Action("vzdump", "Sicherung (vzdump)", t, env={"SM_TASK": "vzdump"}, hidden=True, timeout=12 * 3600,
                   params=guest + [Param("mode", "Modus", kind="select", default="snapshot",
                                         choices=[("snapshot", "Snapshot"), ("suspend", "Suspend"),
                                                  ("stop", "Stop")]),
                                   Param("storage", "Storage", required=False, pattern=r"^[A-Za-z0-9._-]+$")]),
        ]

    def detect(self, facts: dict) -> bool:
        return bool(facts.get("pve_version"))

    def panel(self, conn, system: System) -> dict:
        res = conn.exec("pvesh get /cluster/resources --output-format json", root=True, timeout=45)
        if not res.ok:
            raise RuntimeError(res.stderr.strip() or "pvesh fehlgeschlagen")
        try:
            items = json.loads(res.stdout or "[]")
        except ValueError as exc:
            raise RuntimeError("Ungültige Antwort von pvesh") from exc
        guests, nodes, storage = [], [], []
        for it in items:
            t = it.get("type")
            if t in ("qemu", "lxc"):
                guests.append({
                    "vmid": it.get("vmid"), "name": it.get("name", ""), "type": t, "node": it.get("node", ""),
                    "status": it.get("status", ""), "cpu": round((it.get("cpu") or 0) * 100, 1),
                    "mem": it.get("mem") or 0, "maxmem": it.get("maxmem") or 0, "uptime": it.get("uptime") or 0,
                    "template": bool(it.get("template")),
                })
            elif t == "node":
                nodes.append({"node": it.get("node"), "status": it.get("status"),
                              "cpu": round((it.get("cpu") or 0) * 100, 1),
                              "mem": it.get("mem") or 0, "maxmem": it.get("maxmem") or 0,
                              "uptime": it.get("uptime") or 0})
            elif t == "storage":
                storage.append({"storage": it.get("storage"), "node": it.get("node"),
                                "status": it.get("status"), "disk": it.get("disk") or 0,
                                "maxdisk": it.get("maxdisk") or 0, "content": it.get("content", "")})
        guests.sort(key=lambda g: g["vmid"] or 0)
        ver = conn.exec("pveversion", timeout=20).stdout.strip()
        return {"guests": guests, "nodes": nodes, "storage": storage, "version": ver}

    def summary(self, system: System) -> Optional[dict]:
        ver = system.fact.get("pve_version", "")
        m = re.match(r"(\d+)\.", ver or "")
        if m and int(m.group(1)) == 8:
            return {"count": 0, "text": "Proxmox VE 9 verfügbar (Upgrade-Prüfung)", "severity": "info"}
        return None
