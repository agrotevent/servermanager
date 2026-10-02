"""API connections to Proxmox VE, RouterOS and Pangolin: clients, polling, alerts."""
from __future__ import annotations

import logging
from typing import Optional, Union

from sqlalchemy.orm import Session

from . import notify, pve, security, settings
from .mikrotik import MikroTik, MikroTikError
from .authentik import Authentik, AuthentikError
from .mailcow import Mailcow, MailcowError
from .ispconfig_api import IspConfig, IspError
from .models import (KIND_EASYBELL, KIND_ISPC, KIND_MAILCOW, KIND_PANGOLIN, KIND_PBX, KIND_PVE, KIND_ROUTER,
                     KIND_SSO, KIND_ZABBIX, KIND_ZAMMAD, STATUS_ERROR, STATUS_ONLINE, EasybellAccount, IspServer,
                     MailcowServer, PangolinServer, PbxServer, PveServer, RouterDevice, SsoServer, System, ZabbixHost,
                     ZabbixServer, ZammadServer, utcnow)
from .pangolin import Pangolin, PangolinError
from .pbx import PbxError
from .pveapi import PveError
from .ssh import SSHError
from .zabbix import Zabbix, ZabbixError
from .zammad import Zammad, ZammadError
from .ami import Ami, AmiError

log = logging.getLogger(__name__)

MODELS = {KIND_PVE: PveServer, KIND_ROUTER: RouterDevice, KIND_PANGOLIN: PangolinServer,
          KIND_MAILCOW: MailcowServer, KIND_SSO: SsoServer, KIND_PBX: PbxServer, KIND_ZABBIX: ZabbixServer,
          KIND_ISPC: IspServer, KIND_ZAMMAD: ZammadServer, KIND_EASYBELL: EasybellAccount}
LABELS = {KIND_PVE: "Proxmox", KIND_ROUTER: "RouterOS", KIND_PANGOLIN: "Pangolin", KIND_MAILCOW: "Mailcow",
          KIND_SSO: "SSO", KIND_PBX: "Telefonie", KIND_ZABBIX: "Zabbix", KIND_ISPC: "ISPConfig",
          KIND_ZAMMAD: "Zammad", KIND_EASYBELL: "easybell"}
Integration = Union[PveServer, RouterDevice, PangolinServer, MailcowServer, SsoServer, PbxServer, ZabbixServer,
                    IspServer, ZammadServer, EasybellAccount]
ApiError = (PveError, MikroTikError, PangolinError, MailcowError, AuthentikError, PbxError, ZabbixError, IspError,
            ZammadError, AmiError, SSHError, ValueError)


def kind_of(obj: Integration) -> str:
    for k, m in MODELS.items():
        if isinstance(obj, m):
            return k
    raise TypeError(obj)


def source_ip_for(url: str) -> str:
    """Local address the servermanager uses to reach a host (no packet is sent)."""
    import socket
    from urllib.parse import urlsplit
    parts = urlsplit(url if "://" in url else "https://" + url)
    if not parts.hostname:
        return ""
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or 443, proto=socket.IPPROTO_UDP)
        family, _t, _p, _c, addr = infos[0]
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.connect(addr)
            return s.getsockname()[0]
    except OSError:
        return ""


def router_login_hint(router: RouterDevice) -> str:
    src = source_ip_for(router.api_url)
    return ("Prüfen: Benutzername und Passwort; bei einem eigenen API-Benutzer braucht dessen Gruppe die Rechte "
            "read, api und rest-api (für Änderungen write), und die erlaubte Adresse des Benutzers "
            f"(/user … address=) muss {src or 'die Adresse des Servermanagers'} enthalten. "
            "Tipp: mit dem Admin-Zugang anlegen und „eigenen API-Benutzer anlegen“ wählen.")


def router_client(router: RouterDevice, timeout: int = 15) -> MikroTik:
    return MikroTik(router.api_url, router.username, security.decrypt(router.password_enc),
                    verify_tls=bool(router.verify_ca), timeout=timeout, fingerprint=router.fingerprint or "")


def mailcow_client(mc: MailcowServer, timeout: int = 20) -> Mailcow:
    return Mailcow(mc.api_url, security.decrypt(mc.api_key_enc), fingerprint=mc.fingerprint or "",
                   verify_ca=bool(mc.verify_ca) or not mc.fingerprint, timeout=timeout)


def sso_client(s: SsoServer, timeout: int = 20) -> Authentik:
    return Authentik(s.api_url, security.decrypt(s.token_enc), public_url=s.public_url,
                     fingerprint=s.fingerprint or "", verify_ca=bool(s.verify_ca) or not s.fingerprint,
                     timeout=timeout)


def zabbix_client(z: ZabbixServer, timeout: int = 20) -> Zabbix:
    return Zabbix(z.api_url, security.decrypt(z.token_enc), fingerprint=z.fingerprint or "",
                  verify_ca=bool(z.verify_ca) or not z.fingerprint, timeout=timeout)


def zabbix_overview(db: Session, z: ZabbixServer, zx: Zabbix) -> tuple[dict, list[dict]]:
    from . import tickets
    problems = zx.problems(0)
    hosts = zx.hosts()
    by_sev = {str(i): 0 for i in range(6)}
    for p in problems:
        by_sev[str(p["severity"])] += 1
    managed = {h.hostid: h for h in db.query(ZabbixHost).filter(ZabbixHost.zabbix_id == z.id)}
    alerts = []
    for h in hosts:
        if h["hostid"] in managed and h["available"] == 2:
            alerts.append({"key": f"agent:{h['hostid']}", "severity": "warn",
                           "text": f"Zabbix erreicht den Agenten auf {h['name']} nicht"})
    result = tickets.sync_problems(db, z, problems)
    data = {"version": zx.version(), "hosts": len(hosts), "hosts_unavailable": sum(1 for h in hosts
                                                                                    if h["available"] == 2),
            "problems": len(problems), "by_severity": by_sev, "tickets_created": result["created"],
            "top": [{k: p.get(k) for k in ("eventid", "name", "severity", "host_name", "clock", "acknowledged")}
                    for p in problems[:30]]}
    return data, alerts


def ispconfig_client(i: IspServer, timeout: int = 30) -> IspConfig:
    if not i.api_url or not i.username:
        raise IspError("Schnittstelle noch nicht eingerichtet")
    return IspConfig(i.api_url, i.username, security.decrypt(i.password_enc), fingerprint=i.fingerprint or "",
                     verify_ca=bool(i.verify_ca), timeout=timeout)


def ispconfig_overview(isp: IspConfig) -> dict:
    with isp:
        sites = isp.websites()
        boxes = isp.mailboxes()
        return {"version": isp.version(), "clients": len(isp.clients()), "websites": len(sites),
                "websites_inactive": sum(1 for w in sites if str(w.get("active")) == "n"),
                "mail_domains": len(isp.mail_domains()), "mailboxes": len(boxes), "databases": len(isp.databases()),
                "dns_zones": len(isp.dns_zones()), "servers": [s.get("server_name") for s in isp.servers()]}


def ispconfig_auto(db: Session, system: System) -> Optional[int]:
    """A system was detected as ISPConfig: create the connection and queue the SSH setup (once)."""
    from . import jobs
    if not settings.get(db, "ispconfig.auto_setup") or not system.id:
        return None
    if db.query(IspServer).filter(IspServer.system_id == system.id).first():
        return None
    isp = IspServer(name=system.name, system_id=system.id, monitor=True, verify_ca=False)
    db.add(isp)
    db.flush()
    job = jobs.enqueue(db, kind="ispconfig_setup", title=f"ISPConfig-Schnittstelle: {system.name}", system=system,
                       payload={"isp_id": isp.id, "auto": True})
    return job.id


def zammad_client(z: ZammadServer, timeout: int = 20) -> Zammad:
    return Zammad(z.api_url, security.decrypt(z.token_enc), fingerprint=z.fingerprint or "",
                  verify_ca=bool(z.verify_ca) or not z.fingerprint, timeout=timeout)


def easybell_client(e: EasybellAccount, timeout: float = 15.0) -> Ami:
    return Ami(e.host, e.port, e.username, security.decrypt(e.secret_enc) if e.secret_enc else "",
               allow_plain=bool(e.allow_plain), timeout=timeout)


def easybell_overview(e: EasybellAccount) -> tuple[dict, list[dict]]:
    alerts: list[dict] = []
    data: dict = {"errors": {}}
    with easybell_client(e) as ami:
        data["version"] = ami.version()
        try:
            data["endpoints"] = sorted(ami.endpoints(), key=lambda x: x["name"])
        except AmiError as exc:
            data["endpoints"], data["errors"]["endpoints"] = [], str(exc)
        try:
            data["channels"] = ami.channels()
        except AmiError as exc:
            data["channels"], data["errors"]["channels"] = [], str(exc)
    bad = {"unavailable", "unreachable", "unknown", "invalid"}
    data["offline"] = [x["name"] for x in data["endpoints"] if str(x["state"]).lower().split(" ")[0] in bad]
    if e.watch_devices:
        for name in data["offline"]:
            alerts.append({"key": f"dev:{name}", "severity": "warn", "text": f"Endgerät {name} ist nicht erreichbar"})
    lst = e.listener or {}
    if e.listen and lst.get("error") and not lst.get("connected"):
        alerts.append({"key": "listener", "severity": "warn",
                       "text": f"Ereignis-Verbindung getrennt: {str(lst['error'])[:200]}"})
    return data, alerts


def zammad_overview(db: Session, z: ZammadServer) -> tuple[dict, list[dict]]:
    from . import tickets
    from .models import Ticket
    client = zammad_client(z)
    me = client.me()
    if me.get("id"):
        z.agent_id = int(me["id"])
    groups = [g.get("name") for g in client.groups()]
    result = tickets.sync_zammad(db, z)
    failed = db.query(Ticket).filter(Ticket.zabbix_id.in_(
        [x.id for x in db.query(ZabbixServer).filter(ZabbixServer.zammad_id == z.id)]),
        Ticket.zammad_ticket_id.is_(None), Ticket.zammad_error != "").count()
    alerts = []
    if z.group_name and groups and z.group_name not in groups:
        alerts.append({"key": "group", "severity": "warn", "text": f"Gruppe „{z.group_name}“ gibt es in Zammad nicht"})
    if failed:
        alerts.append({"key": "create", "severity": "warn",
                       "text": f"{failed} Ticket(s) konnten nicht in Zammad angelegt werden"})
    data = {"user": me.get("login") or me.get("email") or "", "groups": groups,
            "linked": db.query(Ticket).filter(Ticket.zammad_server_id == z.id).count(), **result}
    return data, alerts


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
        elif kind == KIND_MAILCOW:
            mc = mailcow_client(obj)
            boxes = mc.mailboxes()
            data = {"version": mc.version(), "domains": len(mc.domains()), "mailboxes": len(boxes),
                    "inactive": sum(1 for b in boxes if str(b.get("active")) in ("0", "False", "false"))}
            for b in boxes:
                quota, used = int(b.get("quota") or 0), int(b.get("quota_used") or 0)
                if quota and disk_pct and used * 100 / quota >= disk_pct:
                    alerts.append({"key": f"quota:{b.get('username')}", "severity": "warn",
                                   "text": f"Postfach {b.get('username')} zu {round(used * 100 / quota)} % voll"})
        elif kind == KIND_PBX:
            from . import pbx
            system = db.get(System, obj.system_id) if obj.system_id else None
            if system is None:
                raise PbxError("Kein System (SSH) zugeordnet")
            data = pbx.status(system)
            alerts = pbx.alerts(data)
        elif kind == KIND_ZABBIX:
            data, alerts = zabbix_overview(db, obj, zabbix_client(obj))
        elif kind == KIND_ZAMMAD:
            data, alerts = zammad_overview(db, obj)
        elif kind == KIND_EASYBELL:
            data, alerts = easybell_overview(obj)
        elif kind == KIND_ISPC:
            data = ispconfig_overview(ispconfig_client(obj))
        elif kind == KIND_SSO:
            au = sso_client(obj)
            data = {"version": au.version(), "applications": len(au.applications())}
        else:
            data = pangolin_overview(pangolin_client(obj))
            others = [p for p in db.query(PangolinServer).filter(PangolinServer.id != obj.id).all()
                      if p.role != obj.role and p.status == STATUS_ONLINE
                      and any(x.get("online") for x in (p.data.get("sites") or []))]
            fallback = (f" – Backup-Weg über {others[0].name} ist verfügbar" if others and obj.role == "primary"
                        else (" – KEIN weiterer Weg verfügbar" if obj.role == "primary" else ""))
            for s in data["sites"]:
                if not s["online"]:
                    alerts.append({"key": f"site:{s['id']}", "severity": "crit",
                                   "text": f"Site {s['name']} (Newt) ist offline{fallback}"})
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
        label = LABELS[kind_of(obj)]
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
