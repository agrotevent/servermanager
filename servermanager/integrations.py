"""API connections to Proxmox VE, RouterOS and Pangolin: clients, polling, alerts."""
from __future__ import annotations

import logging
from typing import Optional, Union

from sqlalchemy.orm import Session

from . import notify, pve, security, settings
from .mikrotik import MikroTik, MikroTikError
from .models import (KIND_PANGOLIN, KIND_PVE, KIND_ROUTER, STATUS_ERROR, STATUS_ONLINE, PangolinServer,
                     PveServer, RouterDevice, utcnow)
from .pangolin import Pangolin, PangolinError
from .pveapi import PveError

log = logging.getLogger(__name__)

MODELS = {KIND_PVE: PveServer, KIND_ROUTER: RouterDevice, KIND_PANGOLIN: PangolinServer}
Integration = Union[PveServer, RouterDevice, PangolinServer]
ApiError = (PveError, MikroTikError, PangolinError, ValueError)


def kind_of(obj: Integration) -> str:
    for k, m in MODELS.items():
        if isinstance(obj, m):
            return k
    raise TypeError(obj)


def router_client(router: RouterDevice, timeout: int = 15) -> MikroTik:
    return MikroTik(router.api_url, router.username, security.decrypt(router.password_enc),
                    verify_tls=bool(router.verify_ca), timeout=timeout, fingerprint=router.fingerprint or "")


def pangolin_client(p: PangolinServer, timeout: int = 20) -> Pangolin:
    return Pangolin(p.api_url, security.decrypt(p.api_key_enc), p.org_id, fingerprint=p.fingerprint or "",
                    timeout=timeout)


# --------------------------------------------------------------------------
# polling
# --------------------------------------------------------------------------
def router_overview(mt: MikroTik) -> dict:
    res = mt._req("GET", "system/resource") or {}
    ident = mt.identity()
    ifaces = mt.get("interface")
    leases = mt.get("ip/dhcp-server/lease")
    total = int(res.get("total-memory") or 0)
    free = int(res.get("free-memory") or 0)
    return {
        "identity": ident, "version": res.get("version", ""), "board": res.get("board-name", ""),
        "arch": res.get("architecture-name", ""), "uptime": res.get("uptime", ""),
        "cpu_load": int(res.get("cpu-load") or 0), "mem_total": total, "mem_used": total - free,
        "mem_pct": round((total - free) * 100 / total) if total else 0,
        "interfaces": len(ifaces), "interfaces_running": sum(1 for i in ifaces if i.get("running") == "true"),
        "leases": len(leases), "leases_dynamic": sum(1 for le in leases if le.get("dynamic") == "true"),
    }


def pangolin_overview(pg: Pangolin) -> dict:
    sites = pg.sites()
    resources = pg.resources()
    return {
        "sites": [{"id": s.get("siteId"), "name": s.get("name", ""), "online": bool(s.get("online")),
                   "type": s.get("type", ""), "subnet": s.get("subnet", "")} for s in sites],
        "resources": len(resources),
    }


def poll(db: Session, obj: Integration) -> list[dict]:
    """Refresh status/cache/alerts of one connection; returns the new alerts."""
    kind = kind_of(obj)
    disk_pct = int(settings.get(db, "integrations.disk_alert_pct") or 0)
    alerts: list[dict] = []
    try:
        if kind == KIND_PVE:
            data = pve.overview(pve.client(obj))
            alerts = pve.alerts_for(obj, data, disk_pct)
        elif kind == KIND_ROUTER:
            data = router_overview(router_client(obj))
            if data["cpu_load"] >= 90:
                alerts.append({"key": "cpu", "severity": "warn", "text": f"CPU-Last {data['cpu_load']} %"})
            if data["mem_pct"] >= 90:
                alerts.append({"key": "mem", "severity": "warn", "text": f"Arbeitsspeicher zu {data['mem_pct']} % belegt"})
        else:
            data = pangolin_overview(pangolin_client(obj))
            for s in data["sites"]:
                if not s["online"]:
                    alerts.append({"key": f"site:{s['id']}", "severity": "crit",
                                   "text": f"Site {s['name']} (Newt) ist offline"})
        obj.cache = data
        obj.status = STATUS_ONLINE
        obj.status_message = ""
        obj.last_ok = utcnow()
    except ApiError as exc:
        obj.status = STATUS_ERROR
        obj.status_message = str(exc)[:1000]
        alerts = [{"key": "conn", "severity": "crit", "text": f"API nicht erreichbar: {str(exc)[:300]}"}]
    obj.last_poll = utcnow()
    _alert_changes(db, obj, alerts)
    return alerts


def _alert_changes(db: Session, obj: Integration, alerts: list[dict]) -> None:
    before = {a["key"]: a for a in (obj.alerts or [])}
    now = utcnow().isoformat(timespec="seconds")
    current = []
    for a in alerts:
        a = dict(a)
        a["since"] = before.get(a["key"], {}).get("since") or now
        current.append(a)
    new = [a for a in current if a["key"] not in before]
    resolved = [a for k, a in before.items() if k not in {x["key"] for x in current}]
    obj.alerts = current
    if (new or resolved) and settings.get(db, "integrations.notify"):
        label = {KIND_PVE: "Proxmox", KIND_ROUTER: "RouterOS", KIND_PANGOLIN: "Pangolin"}[kind_of(obj)]
        lines = [f"{label}: {obj.name}", ""]
        lines += [f"NEU: {a['text']}" for a in new]
        lines += [f"BEHOBEN: {a['text']}" for a in resolved]
        subject = f"{label} {obj.name}: " + (f"{len(new)} neue Warnung(en)" if new else "Warnung behoben")
        notify.notify(db, notify.recipients(settings.get(db, "mail.admin_recipients") or ""), subject,
                      "\n".join(lines))


def due(obj: Integration, interval_min: int) -> bool:
    if not obj.monitor or interval_min <= 0:
        return False
    return obj.last_poll is None or (utcnow() - obj.last_poll).total_seconds() >= interval_min * 60


def get(db: Session, kind: str, obj_id: int) -> Optional[Integration]:
    model = MODELS.get(kind)
    return db.get(model, obj_id) if model else None
