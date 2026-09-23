"""Docker module."""
from __future__ import annotations

import json
import time
from typing import Optional

from ..models import LEVEL_FULL, System
from .base import Action, Module, Param, parse_kv, run_module_script


class DockerModule(Module):
    key = "docker"
    label = "Docker"
    description = "Container, Compose-Projekte, Image-Updates"
    panel_template = "modules/docker.html"

    def build_actions(self) -> list[Action]:
        t = "docker.sh"
        cparam = [Param("container", "Container")]
        pparam = [Param("project", "Compose-Projekt")]
        return [
            Action("check_updates", "Image-Updates prüfen", t, env={"SM_TASK": "check_updates"}, group="Updates",
                   description="Lädt die Images laufender Container neu (docker pull) und vergleicht sie"),
            Action("compose_update_all", "Alle Compose-Projekte aktualisieren", t,
                   env={"SM_TASK": "compose_update_all"}, group="Updates",
                   description="pull + up -d für alle Compose-Projekte",
                   confirm="Alle Compose-Projekte aktualisieren (Container werden neu erstellt)?"),
            Action("image_prune", "Ungenutzte Images entfernen", t, env={"SM_TASK": "image_prune"}, group="Pflege"),
            Action("compose_update", "Projekt aktualisieren", t, env={"SM_TASK": "compose_update"},
                   params=pparam, hidden=True),
            Action("compose_restart", "Projekt neu starten", t, env={"SM_TASK": "compose_restart"},
                   params=pparam, hidden=True),
            Action("container_start", "Container starten", t, env={"SM_TASK": "container_start"},
                   params=cparam, hidden=True),
            Action("container_stop", "Container stoppen", t, env={"SM_TASK": "container_stop"},
                   params=cparam, hidden=True),
            Action("container_restart", "Container neu starten", t, env={"SM_TASK": "container_restart"},
                   params=cparam, hidden=True),
            Action("container_remove", "Container entfernen", t, env={"SM_TASK": "container_remove"},
                   params=cparam, hidden=True, level=LEVEL_FULL, danger=True),
        ]

    def detect(self, facts: dict) -> bool:
        return "docker_version" in facts

    def check(self, conn, system: System, ctx: dict) -> Optional[dict]:
        if not ctx.get("docker_image_check"):
            return None
        text = run_module_script(conn, self, "docker.sh", {"SM_TASK": "check_updates"}, timeout=1800)
        return parse_update_check(text)

    def panel(self, conn, system: System) -> dict:
        res = conn.exec("docker ps -a --no-trunc --format '{{json .}}'", root=True, timeout=30)
        if not res.ok:
            raise RuntimeError(res.stderr.strip() or "docker ps fehlgeschlagen")
        containers = []
        for line in res.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                c = json.loads(line)
            except ValueError:
                continue
            labels = {}
            for item in (c.get("Labels") or "").split(","):
                if "=" in item:
                    k, v = item.split("=", 1)
                    labels[k] = v
            containers.append({
                "id": (c.get("ID") or "")[:12], "name": c.get("Names", ""), "image": c.get("Image", ""),
                "state": c.get("State", ""), "status": c.get("Status", ""), "ports": c.get("Ports", ""),
                "project": labels.get("com.docker.compose.project", ""),
            })
        containers.sort(key=lambda c: (c["project"] or "~", c["name"]))
        projects: dict[str, dict] = {}
        for c in containers:
            if c["project"]:
                p = projects.setdefault(c["project"], {"name": c["project"], "running": 0, "total": 0})
                p["total"] += 1
                p["running"] += 1 if c["state"] == "running" else 0
        df = conn.exec("docker system df --format '{{.Type}}|{{.TotalCount}}|{{.Size}}|{{.Reclaimable}}'",
                       root=True, timeout=30)
        usage = [dict(zip(("type", "count", "size", "reclaimable"), line.split("|")))
                 for line in df.stdout.splitlines() if line.count("|") == 3]
        return {"containers": containers, "projects": sorted(projects.values(), key=lambda p: p["name"]),
                "usage": usage}

    def summary(self, system: System) -> Optional[dict]:
        d = system.upd.get("docker") or {}
        count = len(d.get("updates") or [])
        if not count:
            return None
        return {"count": count, "text": f"{count} Container-Image(s)", "severity": "info"}


def parse_update_check(text: str) -> dict:
    kv = parse_kv(text)
    ups = []
    for line in kv.get("update", []):
        name, _, image = line.partition("|")
        ups.append({"container": name, "image": image})
    unchecked = [line.split("|", 1)[0] for line in kv.get("unchecked", [])]
    return {"updates": ups, "unchecked": unchecked, "checked": int(time.time())}
