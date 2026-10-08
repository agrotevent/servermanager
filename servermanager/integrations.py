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
from .models import (KIND_DNS, KIND_EASYBELL, KIND_HCLOUD, KIND_HCLOUD_SRV, KIND_HETZNER, KIND_HETZNER_SRV, KIND_ISPC, KIND_MAILCOW,
                     KIND_NEXTCLOUD, KIND_PANGOLIN, KIND_PBX, KIND_PVE, KIND_ROUTER,
                     KIND_SSO, KIND_ZABBIX, KIND_ZAMMAD, STATUS_ERROR, STATUS_ONLINE, EasybellAccount, HcloudProject, HcloudServer,
                     HetznerAccount,
                     HetznerServer, IspServer,
                     DnsAccount, MailcowServer, NextcloudServer, PangolinServer, PbxServer, PveServer, RouterDevice, SsoServer, System, ZabbixHost,
                     ZabbixServer, ZammadServer, utcnow)
from .pangolin import Pangolin, PangolinError
from .pbx import PbxError
from .pveapi import PveError
from .ssh import SSHError
from .zabbix import Zabbix, ZabbixError
from .zammad import Zammad, ZammadError
from .ami import Ami, AmiError
from .hetzner import Robot, RobotError
from .hcloud import Cloud, CloudError
from .nextcloud_api import Nextcloud, NextcloudError
from .dnsapi import DnsError

log = logging.getLogger(__name__)

MODELS = {KIND_PVE: PveServer, KIND_ROUTER: RouterDevice, KIND_PANGOLIN: PangolinServer,
          KIND_MAILCOW: MailcowServer, KIND_SSO: SsoServer, KIND_PBX: PbxServer, KIND_ZABBIX: ZabbixServer,
          KIND_ISPC: IspServer, KIND_ZAMMAD: ZammadServer, KIND_EASYBELL: EasybellAccount,
          KIND_HETZNER: HetznerAccount, KIND_HCLOUD: HcloudProject, KIND_NEXTCLOUD: NextcloudServer,
          KIND_DNS: DnsAccount}
# objects permissions can be granted on (single Hetzner servers are not polled on their own)
ACCESS_MODELS = {**MODELS, KIND_HETZNER_SRV: HetznerServer, KIND_HCLOUD_SRV: HcloudServer}
LABELS = {KIND_PVE: "Proxmox", KIND_ROUTER: "RouterOS", KIND_PANGOLIN: "Pangolin", KIND_MAILCOW: "Mailcow",
          KIND_SSO: "SSO", KIND_PBX: "Telefonie", KIND_ZABBIX: "Zabbix", KIND_ISPC: "ISPConfig",
          KIND_ZAMMAD: "Zammad", KIND_EASYBELL: "easybell", KIND_HETZNER: "Hetzner",
          KIND_HCLOUD: "Hetzner Cloud", KIND_NEXTCLOUD: "Nextcloud", KIND_DNS: "DNS"}
Integration = Union[PveServer, RouterDevice, PangolinServer, MailcowServer, SsoServer, PbxServer, ZabbixServer,
                    IspServer, ZammadServer, EasybellAccount, HetznerAccount, HcloudProject, NextcloudServer,
                    DnsAccount]
ApiError = (PveError, MikroTikError, PangolinError, MailcowError, AuthentikError, PbxError, ZabbixError, IspError,
            ZammadError, AmiError, RobotError, CloudError, NextcloudError, DnsError, SSHError, ValueError)


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


def dns_client(a: DnsAccount, timeout: int = 25):
    from . import dnsapi
    secret = security.decrypt(a.secret_enc) if a.secret_enc else ""
    kw = {"fingerprint": a.fingerprint or "", "verify_ca": bool(a.verify_ca) or not a.fingerprint, "timeout": timeout}
    if a.provider == "inwx":
        return dnsapi.Inwx(a.api_url, a.username, secret,
                           security.decrypt(a.totp_enc) if a.totp_enc else "", **kw)
    if a.provider == "hostingde":
        return dnsapi.HostingDe(a.api_url, secret, **kw)
    raise DnsError("Unbekannter Anbieter")


def dns_overview(a: DnsAccount) -> tuple[dict, list[dict]]:
    """Zones and domains of the account; warnings for domains running out or not active."""
    from .dnsapi import days_left
    client = dns_client(a)
    try:
        zones = client.zones()
        data: dict = {"zones": [z["name"] for z in zones], "domains": [], "domain_error": ""}
        try:
            data["domains"] = client.domains()
        except DnsError as exc:   # e.g. an API key with DNS rights only
            data["domain_error"] = str(exc)[:300]
    finally:
        client.close()
    alerts = []
    for d in data["domains"]:
        left = days_left(d.get("deletion") or "")
        if d.get("deletion") and left is not None and left <= max(a.expiry_days or 30, 1):
            alerts.append({"key": f"del:{d['name']}", "severity": "crit" if left <= 7 else "warn",
                           "text": f"Domain {d['name']} läuft am {d['deletion']} aus (wird nicht verlängert)"})
        elif d.get("status") and d["status"].lower() not in ("active", "ok", "ordered", "transfer", "createpending",
                                                               "updatepending", "pending", "renewpending"):
            alerts.append({"key": f"status:{d['name']}", "severity": "warn",
                           "text": f"Domain {d['name']}: Status {d['status']}"})
    data["expiring"] = [d["name"] for d in data["domains"]
                        if (days_left(d.get("expires") or "") or 9999) <= max(a.expiry_days or 30, 1)]
    return data, alerts


def nextcloud_client(n: NextcloudServer, timeout: int = 20) -> Nextcloud:
    if not n.api_url or not n.username or not n.password_enc:
        raise NextcloudError("Schnittstelle noch nicht eingerichtet")
    return Nextcloud(n.api_url, n.username, security.decrypt(n.password_enc), fingerprint=n.fingerprint or "",
                     verify_ca=bool(n.verify_ca) or not n.fingerprint, timeout=timeout)


def nextcloud_overview(nc: Nextcloud, disk_pct: int) -> tuple[dict, list[dict]]:
    from .nextcloud_api import quota_info, summary
    data = summary(nc.serverinfo())
    users = nc.users()
    data.update({"users": len(users), "disabled": sum(1 for u in users if u.get("enabled") is False),
                 "groups": len(nc.groups())})
    alerts = []
    for u in users:
        q = quota_info(u)
        if q["total"] and disk_pct and q["pct"] >= disk_pct:
            alerts.append({"key": f"quota:{u['id']}", "severity": "warn",
                           "text": f"Speicher von {u['id']} zu {q['pct']} % belegt"})
    return data, alerts


def easybell_client(e: EasybellAccount, timeout: float = 15.0) -> Ami:
    return Ami(e.host, e.port, e.username, security.decrypt(e.secret_enc) if e.secret_enc else "",
               allow_plain=bool(e.allow_plain), timeout=timeout, transport=e.transport or "auto")


def easybell_overview(e: EasybellAccount) -> tuple[dict, list[dict]]:
    from datetime import datetime, timedelta
    alerts: list[dict] = []
    data: dict = {"errors": {}}
    lst = e.listener or {}
    snap = lst.get("status") or {}
    try:
        fresh = bool(snap) and utcnow() - datetime.fromisoformat(snap["at"]) < timedelta(minutes=15)
    except (KeyError, ValueError):
        fresh = False
    if e.listen and lst.get("connected") and fresh:
        # easybell allows one AMI connection per access: use what the event connection queried itself
        data.update({k: snap.get(k) or ([] if k != "version" else "") for k in ("version", "endpoints", "channels")})
        data["errors"] = dict(snap.get("errors") or {})
        data["via"] = "Ereignis-Verbindung"
        data["transport"] = lst.get("transport", "")
    elif e.listen and lst.get("connected"):
        # connected, first snapshot still pending: do not disturb the event connection with a second login
        data.update({"version": "", "endpoints": [], "channels": [], "via": "Ereignis-Verbindung",
                     "errors": {"endpoints": "Abfrage über die Ereignis-Verbindung läuft – gleich erneut ansehen"}})
    else:
        _easybell_query(e, data)
    bad = {"unavailable", "unreachable", "unknown", "invalid"}
    data["offline"] = [x["name"] for x in data["endpoints"] if str(x["state"]).lower().split(" ")[0] in bad]
    if e.watch_devices:
        for name in data["offline"]:
            alerts.append({"key": f"dev:{name}", "severity": "warn", "text": f"Endgerät {name} ist nicht erreichbar"})
    if e.listen and lst.get("error") and not lst.get("connected"):
        alerts.append({"key": "listener", "severity": "warn",
                       "text": f"Ereignis-Verbindung getrennt: {str(lst['error'])[:200]}"})
    return data, alerts


def _easybell_query(e: EasybellAccount, data: dict) -> None:
    with easybell_client(e) as ami:
        data["transport"] = ami.transport_used
        data["version"] = ami.version()
        try:
            data["endpoints"] = sorted(ami.endpoints(), key=lambda x: x["name"])
        except AmiError as exc:
            data["endpoints"], data["errors"]["endpoints"] = [], str(exc)
        try:
            data["channels"] = ami.channels()
        except AmiError as exc:
            data["channels"], data["errors"]["channels"] = [], str(exc)


def hetzner_client(a: HetznerAccount, timeout: int = 25) -> Robot:
    from . import hetzner
    return Robot(a.username, security.decrypt(a.password_enc) if a.password_enc else "",
                 base=a.api_url or hetzner.API_URL, fingerprint=a.fingerprint or "", timeout=timeout)


VSWITCH_NO_TRAFFIC = ("Hetzner liefert für die Netze dieses vSwitches keine Traffic-Werte über die Robot-API "
                      "(nur für Server-IPs und deren Subnetze)")


def hetzner_sync(db: Session, a: HetznerAccount, today=None) -> tuple[dict, list[dict]]:
    """Servers, IPs, subnets, reverse DNS, reset options and the traffic of the current month."""
    from datetime import date

    from . import hetzner
    robot = hetzner_client(a)
    servers = robot.servers()
    ips = {i["ip"]: i for i in robot.ips()}
    subnets = robot.subnets()
    rdns = robot.rdns()
    try:
        resets = robot.reset_options()
    except RobotError:
        resets = {}
    vswitches, vswitch_error = [], ""
    try:
        for ref in robot.vswitches():
            v = robot.vswitch(int(ref["id"]))
            vswitches.append({"id": int(v.get("id") or ref["id"]), "name": v.get("name") or ref.get("name") or "",
                              "vlan": v.get("vlan") or ref.get("vlan"), "cancelled": bool(v.get("cancelled")),
                              "servers": [{"number": int(x.get("server_number") or 0),
                                           "ip": x.get("server_ip") or "", "status": x.get("status") or ""}
                                          for x in v.get("server") or []],
                              "subnets": [{"ip": n.get("ip"), "mask": n.get("mask"), "gateway": n.get("gateway")}
                                          for n in v.get("subnet") or [] if n.get("ip")],
                              "cloud_networks": [{"id": n.get("id"), "ip": n.get("ip"), "mask": n.get("mask")}
                                                 for n in v.get("cloud_network") or []]})
    except RobotError as exc:
        vswitch_error = str(exc)
    today = today or date.today()
    start, end = hetzner.month_range(today.year, today.month, today)
    all_ips, all_nets = [], []
    for s in servers:
        i, n = hetzner.addresses_of(s)
        all_ips += i
        all_nets += n
    try:
        traffic = robot.traffic("month", start, end, all_ips, all_nets)
        traffic_error = ""
        if robot.skipped_subnets:
            traffic_error = ("Traffic ohne " + ", ".join(robot.skipped_subnets)
                             + " – Hetzner liefert für dieses Subnetz keine Werte")
    except RobotError as exc:
        traffic, traffic_error = {}, str(exc)
    by_number = {r.number: r for r in db.query(HetznerServer).filter(HetznerServer.account_id == a.id)}
    systems = db.query(System).all()
    alerts: list[dict] = []
    seen = set()
    total_gb = 0.0
    for s in servers:
        number = int(s["server_number"])
        seen.add(number)
        row = by_number.get(number)
        if row is None:
            row = HetznerServer(account_id=a.id, number=number)
            db.add(row)
        addr_ips, addr_nets = hetzner.addresses_of(s)
        days, total = hetzner.sum_series(traffic, addr_ips + addr_nets)
        total_gb += total["sum"]
        own_nets = [x for x in subnets if int(x.get("server_number") or 0) == number]
        limit = hetzner.parse_limit_gb(s.get("traffic"))
        row.name = (s.get("server_name") or f"#{number}")[:128]
        row.server_ip = s.get("server_ip") or ""
        row.product, row.dc = (s.get("product") or "")[:128], (s.get("dc") or "")[:32]
        row.status, row.cancelled = (s.get("status") or "")[:32], bool(s.get("cancelled"))
        addresses = sorted(set(addr_ips) | {r for r in rdns if hetzner.belongs_to(r, s)},
                           key=lambda x: (":" in x, x))
        own_vswitches = [{"id": v["id"], "name": v["name"], "vlan": v["vlan"],
                          "status": next(x["status"] for x in v["servers"] if x["number"] == number),
                          "subnets": v["subnets"]}
                         for v in vswitches if any(x["number"] == number for x in v["servers"])]
        row.data = {
            "server": s, "reset": resets.get(number, []), "subnets": own_nets, "vswitches": own_vswitches,
            "ips": [{"ip": ip, "ptr": rdns.get(ip, ""), "main": ip == s.get("server_ip"),
                     **{k: ips.get(ip, {}).get(k) for k in ("locked", "traffic_warnings", "traffic_hourly",
                                                             "traffic_daily", "traffic_monthly")}}
                    for ip in addresses],
            "traffic": {"month": start[:7], "days": days, "total": total, "limit_gb": limit,
                        "error": traffic_error},
        }
        match = next((x for x in systems if x.host in set(addr_ips) | {s.get("server_ip")}), None)
        row.system_id = match.id if match else row.system_id if row.system_id in {x.id for x in systems} else None
        label = row.name if row.name == f"#{number}" else f"{row.name} (#{number})"
        if row.status and row.status != "ready":
            alerts.append({"key": f"status:{number}", "severity": "warn",
                           "text": f"{label}: Status „{row.status}“"})
        if row.cancelled:
            alerts.append({"key": f"cancelled:{number}", "severity": "warn",
                           "text": f"{label} ist gekündigt (bezahlt bis {s.get('paid_until') or '?'})"})
        if limit and a.traffic_alert_pct and total["sum"] >= limit * a.traffic_alert_pct / 100:
            pct = round(total["sum"] * 100 / limit)
            alerts.append({"key": f"traffic:{number}", "severity": "crit" if pct >= 100 else "warn",
                           "text": f"{label}: {pct} % des Inklusiv-Traffics verbraucht ({total['sum']:.0f} GB)"})
    # vSwitches: networks with their PTR entries and traffic, connection state of the servers
    names = {int(s["server_number"]): s.get("server_name") or f"#{s['server_number']}" for s in servers}
    for v in vswitches:
        # queried separately: Hetzner may have no traffic data for vSwitch nets, which must not cost the
        # servers their traffic figures
        keys = [f"{n['ip']}/{n['mask']}" for n in v["subnets"]]
        v_error, v_data = "", {}
        if keys:
            try:
                v_data = robot.traffic("month", start, end, [], keys)
                if robot.skipped_subnets and len(robot.skipped_subnets) == len(keys):
                    v_error = VSWITCH_NO_TRAFFIC
                elif robot.skipped_subnets:
                    v_error = "Ohne " + ", ".join(robot.skipped_subnets) + " – " + VSWITCH_NO_TRAFFIC
            except RobotError as exc:
                v_error = str(exc)
        days, total = hetzner.sum_series(v_data, keys)
        v["traffic"] = {"month": start[:7], "days": days, "total": total, "error": v_error}
        v["rdns"] = sorted(({"ip": ip, "ptr": ptr} for ip, ptr in rdns.items() if hetzner.in_nets(ip, v["subnets"])),
                           key=lambda r: (":" in r["ip"], r["ip"]))
        for x in v["servers"]:
            x["name"] = names.get(x["number"], f"#{x['number']}")
            if x["status"] == "failed":
                alerts.append({"key": f"vswitch:{v['id']}:{x['number']}", "severity": "warn",
                               "text": f"vSwitch {v['name']} (VLAN {v['vlan']}): Anbindung von {x['name']} "
                                       "fehlgeschlagen"})
    for number, row in by_number.items():
        if number not in seen:
            from . import access
            access.remove_integration(db, KIND_HETZNER_SRV, row.id)
            db.delete(row)
    data = {"servers": len(servers), "ips": len(ips), "subnets": len(subnets), "rdns": len(rdns),
            "month": start[:7], "traffic_gb": round(total_gb, 1), "traffic_error": traffic_error,
            "vswitches": vswitches, "vswitch_error": vswitch_error}
    return data, alerts


def hcloud_client(p: HcloudProject, timeout: int = 25) -> Cloud:
    from . import hcloud
    return Cloud(security.decrypt(p.token_enc) if p.token_enc else "", base=p.api_url or hcloud.API_URL,
                 fingerprint=p.fingerprint or "", timeout=timeout)


def hcloud_sync(db: Session, p: HcloudProject) -> tuple[dict, list[dict]]:
    """Servers with status, addresses (PTR), traffic of the billing period; alerts."""
    from . import hcloud
    cloud = hcloud_client(p)
    servers = cloud.servers()
    floating = cloud.floating_ips()
    by_id = {r.cloud_id: r for r in db.query(HcloudServer).filter(HcloudServer.project_id == p.id)}
    systems = db.query(System).all()
    alerts: list[dict] = []
    seen, out_total = set(), 0
    for s in servers:
        cid = int(s["id"])
        seen.add(cid)
        row = by_id.get(cid)
        if row is None:
            row = HcloudServer(project_id=p.id, cloud_id=cid)
            db.add(row)
        pub = s.get("public_net") or {}
        stype, dc = s.get("server_type") or {}, s.get("datacenter") or {}
        row.name = (s.get("name") or f"#{cid}")[:128]
        row.status = (s.get("status") or "")[:32]
        row.ipv4 = ((pub.get("ipv4") or {}).get("ip") or "")[:64]
        row.ipv6_net = ((pub.get("ipv6") or {}).get("ip") or "")[:64]
        row.server_type = (stype.get("name") or "")[:64]
        row.location = (((dc.get("location") or {}).get("city")) or dc.get("name") or "")[:64]
        out_b, in_b, incl = (int(s.get(k) or 0) for k in ("outgoing_traffic", "ingoing_traffic", "included_traffic"))
        out_total += out_b
        addrs = hcloud.addresses(s, floating)
        row.data = {"server": {k: s.get(k) for k in ("id", "name", "status", "created", "labels", "protection",
                                                     "rescue_enabled", "locked", "backup_window",
                                                     "primary_disk_size", "image", "server_type", "datacenter",
                                                     "public_net", "private_net")},
                    "ips": addrs, "floating": [f for f in floating if f.get("server") == cid],
                    "traffic": {"out": out_b, "in": in_b, "included": incl}}
        own = {a["ip"] for a in addrs}
        match = next((x for x in systems if x.host in own), None)
        row.system_id = match.id if match else (row.system_id if row.system_id in {x.id for x in systems} else None)
        if row.status not in ("running", "off", ""):
            alerts.append({"key": f"status:{cid}", "severity": "warn", "text": f"{row.name}: Status „{row.status}“"})
        if s.get("locked"):
            alerts.append({"key": f"locked:{cid}", "severity": "warn", "text": f"{row.name} ist gesperrt"})
        if incl and p.traffic_alert_pct and out_b >= incl * p.traffic_alert_pct / 100:
            pct = round(out_b * 100 / incl)
            alerts.append({"key": f"traffic:{cid}", "severity": "crit" if pct >= 100 else "warn",
                           "text": f"{row.name}: {pct} % des Inklusiv-Traffics verbraucht"})
    for cid, row in by_id.items():
        if cid not in seen:
            from . import access
            access.remove_integration(db, KIND_HCLOUD_SRV, row.id)
            db.delete(row)
    data = {"servers": len(servers), "running": sum(1 for s in servers if s.get("status") == "running"),
            "floating_ips": len(floating), "outgoing_gb": round(out_total / 1024 ** 3, 1)}
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


def published_via_pangolin(db: Session, host: str) -> Optional[str]:
    """Name of the Pangolin instance that publishes ``host`` (from the last poll), if any."""
    host = (host or "").lower()
    for p in db.query(PangolinServer).all():
        if host and host in ((p.cache or {}).get("published") or []):
            return p.name
    return None


def pangolin_overview(pg: Pangolin) -> dict:
    sites = pg.sites()
    resources = pg.resources()
    return {
        "sites": [{"id": s.get("siteId"), "name": s.get("name", ""), "online": bool(s.get("online")),
                   "type": s.get("type", ""), "subnet": s.get("subnet", "")} for s in sites],
        "resources": len(resources),
        "published": sorted({str(r.get("fullDomain")).lower() for r in resources if r.get("fullDomain")}),
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
        elif kind == KIND_HETZNER:
            data, alerts = hetzner_sync(db, obj)
        elif kind == KIND_HCLOUD:
            data, alerts = hcloud_sync(db, obj)
        elif kind == KIND_ISPC:
            data = ispconfig_overview(ispconfig_client(obj))
        elif kind == KIND_NEXTCLOUD:
            data, alerts = nextcloud_overview(nextcloud_client(obj), disk_pct)
        elif kind == KIND_DNS:
            data, alerts = dns_overview(obj)
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
    if isinstance(obj, (HetznerAccount, HcloudProject)):
        interval_min = max(interval_min, 15)  # Robot rate limits; the data changes slowly
    return obj.last_poll is None or (utcnow() - obj.last_poll).total_seconds() >= interval_min * 60


def get(db: Session, kind: str, obj_id: int) -> Optional[Integration]:
    model = MODELS.get(kind)
    return db.get(model, obj_id) if model else None
