"""Debian / generic Linux module (always active)."""
from __future__ import annotations

import time
from typing import Optional

from ..models import LEVEL_FULL, System
from .base import Action, Module, Param, parse_kv

RELEASES = {"12": ("13", "Debian 13 (trixie)")}


def parse_facts(text: str) -> tuple[dict, dict]:
    """Parse facts.sh output into (facts, apt-updates)."""
    kv = parse_kv(text)
    facts: dict = {}
    for key, values in kv.items():
        if key in ("disk", "pkg", "nextcloud"):
            continue
        facts[key] = values[-1]
    disks = []
    for line in kv.get("disk", []):
        parts = line.split("|")
        if len(parts) == 4:
            try:
                total, used, avail = int(parts[1]), int(parts[2]), int(parts[3])
            except ValueError:
                continue
            pct = round(used * 100 / total) if total else 0
            disks.append({"mount": parts[0], "total": total, "used": used, "avail": avail, "pct": pct})
    facts["disks"] = disks
    ncs = []
    for line in kv.get("nextcloud", []):
        path, _, ver = line.partition("|")
        ncs.append({"path": path, "version": ver})
    facts["nextcloud"] = ncs
    for k in ("uptime", "cpus", "mem_total", "mem_avail", "swap_total", "swap_free", "docker_running",
              "docker_total", "pve_guests", "apt_updated", "needrestart_services"):
        if k in facts:
            try:
                facts[k] = int(facts[k] or 0)
            except ValueError:
                facts[k] = 0
    facts["reboot_required"] = facts.get("reboot_required") == "1"
    facts["checked_at"] = int(time.time())

    packages = []
    for line in kv.get("pkg", []):
        parts = line.split("|")
        if len(parts) >= 5:
            packages.append({"name": parts[0], "current": parts[1], "new": parts[2],
                             "origin": parts[3], "security": parts[4] == "1"})
    apt = None
    if facts.get("apt") == "1":
        apt = {"count": len(packages), "security": sum(1 for p in packages if p["security"]),
               "packages": packages, "lists_updated": facts.get("apt_updated", 0)}
    return facts, apt


def detect_types(facts: dict) -> list[str]:
    types = ["debian"]
    if "docker_version" in facts:
        types.append("docker")
    if facts.get("nextcloud"):
        types.append("nextcloud")
    if facts.get("ispconfig_version"):
        types.append("ispconfig")
    if facts.get("pve_version"):
        types.append("proxmox")
    return types


class DebianModule(Module):
    key = "debian"
    label = "System (Debian)"
    description = "Paketupdates, Release-Upgrade, Dienste, Neustart"
    panel_template = "modules/debian.html"
    always = True

    def build_actions(self) -> list[Action]:
        return [
            Action("apt_update", "Paketlisten aktualisieren", "debian_apt_update.sh",
                   description="apt-get update und Anzeige der ausstehenden Updates", group="Updates"),
            Action("upgrade", "Updates installieren", "debian_upgrade.sh",
                   env={"SM_MODE": "upgrade"},
                   params=[Param("autoremove", "Nicht benötigte Pakete entfernen", kind="bool", default="1",
                                 required=False)],
                   description="apt-get upgrade (Proxmox: dist-upgrade), anschließend autoremove",
                   confirm="Updates jetzt installieren?", group="Updates"),
            Action("full_upgrade", "Vollständiges Upgrade (dist-upgrade)", "debian_upgrade.sh",
                   env={"SM_MODE": "full-upgrade"},
                   params=[Param("autoremove", "Nicht benötigte Pakete entfernen", kind="bool", default="1",
                                 required=False)],
                   description="apt-get dist-upgrade - installiert auch neue Abhängigkeiten / entfernt Pakete",
                   confirm="Vollständiges Upgrade (dist-upgrade) jetzt ausführen?", group="Updates"),
            Action("security_upgrade", "Nur Sicherheitsupdates", "debian_upgrade.sh",
                   env={"SM_MODE": "security", "SM_AUTOREMOVE": "0"},
                   description="Installiert nur Pakete aus den Security-Repositories", group="Updates"),
            Action("release_check", "Release-Upgrade prüfen (12 → 13)", "debian_release_upgrade.sh",
                   env={"SM_CHECK_ONLY": "1"}, group="Release-Upgrade",
                   description="Vorprüfung für das Upgrade von Debian 12 auf Debian 13"),
            Action("release_upgrade", "Release-Upgrade auf Debian 13", "debian_release_upgrade.sh",
                   env={"SM_CHECK_ONLY": "0"}, level=LEVEL_FULL, detached=True, timeout=6 * 3600,
                   danger=True, group="Release-Upgrade",
                   params=[
                       Param("third_party", "Drittanbieter-Quellen", kind="select", default="keep",
                             choices=[("keep", "ebenfalls auf trixie umstellen"),
                                      ("disable", "während des Upgrades deaktivieren")]),
                       Param("force", "Trotz Warnungen der Vorprüfung fortfahren", kind="bool",
                             default="0", required=False),
                       Param("modernize", "Quellen ins deb822-Format umwandeln", kind="bool",
                             default="0", required=False),
                   ],
                   description="Upgrade Debian 12 (bookworm) → 13 (trixie). Läuft im Hintergrund weiter, "
                               "auch wenn die Verbindung abbricht. Vorher wird automatisch /etc gesichert.",
                   confirm="Release-Upgrade auf Debian 13 starten? Dies ist ein größerer Eingriff - "
                           "ein aktuelles Backup/Snapshot wird dringend empfohlen."),
            Action("autoremove", "Autoremove", "debian_simple.sh", env={"SM_TASK": "autoremove"}, group="Pflege"),
            Action("clean", "Paket-Cache leeren", "debian_simple.sh", env={"SM_TASK": "clean"}, group="Pflege"),
            Action("fix_dpkg", "dpkg/apt reparieren", "debian_simple.sh", env={"SM_TASK": "fix_dpkg"},
                   group="Pflege", description="dpkg --configure -a und apt-get -f install"),
            Action("journal_vacuum", "Journal verkleinern", "debian_simple.sh",
                   env={"SM_TASK": "journal_vacuum"}, group="Pflege"),
            Action("needrestart", "Dienste mit alten Bibliotheken neu starten", "debian_simple.sh",
                   env={"SM_TASK": "needrestart"}, group="Pflege"),
            Action("reset_failed", "Fehlgeschlagene Units zurücksetzen", "debian_simple.sh",
                   env={"SM_TASK": "reset_failed"}, group="Pflege"),
            Action("restart_service", "Dienst neu starten", "debian_simple.sh",
                   env={"SM_TASK": "restart_service"}, params=[Param("service", "Dienst")], hidden=True),
            Action("start_service", "Dienst starten", "debian_simple.sh",
                   env={"SM_TASK": "start_service"}, params=[Param("service", "Dienst")], hidden=True),
            Action("stop_service", "Dienst stoppen", "debian_simple.sh",
                   env={"SM_TASK": "stop_service"}, params=[Param("service", "Dienst")], hidden=True,
                   level=LEVEL_FULL),
            Action("reboot", "Neustart", "", special="reboot", group="Neustart",
                   confirm="System jetzt neu starten?", danger=True,
                   description="Startet das System neu und wartet, bis es wieder erreichbar ist"),
            Action("reboot_if_required", "Neustart falls erforderlich", "", special="reboot_if_required",
                   group="Neustart", description="Nur neu starten, wenn Updates einen Neustart erfordern"),
        ]

    def panel(self, conn, system: System) -> dict:
        res = conn.exec("systemctl list-units --type=service --all --no-legend --plain --no-pager", timeout=30)
        services = []
        for line in res.stdout.splitlines():
            parts = line.split(None, 4)
            if len(parts) >= 4 and parts[0].endswith(".service"):
                services.append({"name": parts[0], "load": parts[1], "active": parts[2], "sub": parts[3],
                                 "description": parts[4] if len(parts) > 4 else ""})
        services.sort(key=lambda s: (s["active"] != "failed", s["active"] != "active", s["name"]))
        return {"services": services}

    def summary(self, system: System) -> Optional[dict]:
        apt = system.upd.get("apt") or {}
        count = int(apt.get("count") or 0)
        if not count:
            return None
        sec = int(apt.get("security") or 0)
        text = f"{count} Paket{'e' if count != 1 else ''}"
        if sec:
            text += f", davon {sec} Sicherheit"
        return {"count": count, "text": text, "severity": "danger" if sec else "warn"}


def release_upgrade_info(system: System) -> Optional[dict]:
    facts = system.fact
    if facts.get("os_id") != "debian" or facts.get("pve_version"):
        return None
    target = RELEASES.get(str(facts.get("os_version", "")))
    if not target:
        return None
    return {"from": facts.get("os_version"), "to": target[0], "label": target[1]}
