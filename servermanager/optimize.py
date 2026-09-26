"""Optimisation proposals for the whole infrastructure.

The scan only reads. Every proposal describes what would be changed; the
administrator selects proposals, confirms them and the worker applies them
(job kind ``optimize``), re-checking the preconditions right before the change.

Guiding principle: as few public IPs as possible - services are reached from
outside through Pangolin tunnels (with a backup path over a second Pangolin
whose Newt client runs on a different Proxmox host), port forwards become
superfluous, management goes through the management network.
"""
from __future__ import annotations

import ipaddress
import math
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import discovery, integrations, pve, routeros, settings
from .models import (IspServer, MailcowServer, PangolinServer, PbxServer, PveServer, RouterDevice, SsoClient,
                     SsoServer, System)
from .pveapi import PveError

HTTP_PORTS = {80: "http", 8080: "http", 8000: "http", 3000: "http", 443: "https", 8443: "https"}
AREAS = {"goal": "Ziel: eine Public-IP über Pangolin", "tunnel": "Pangolin-Tunnel & Ausfallsicherheit",
         "pve": "Proxmox", "router": "RouterOS", "pangolin": "Pangolin", "system": "Systeme"}
STATE_KEY = "state.optimize"


def proposal(pid: str, area: str, obj: dict, title: str, detail: str = "", severity: str = "warn",
             action: Optional[str] = None, params: Optional[dict] = None, inputs: Optional[list] = None,
             note: str = "") -> dict:
    return {"id": pid, "area": area, "obj": obj, "title": title, "detail": detail, "severity": severity,
            "action": action, "params": params or {}, "inputs": inputs or [], "note": note}


def _obj(kind: str, o) -> dict:
    return {"kind": kind, "id": o.id, "name": o.name}


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


# ==========================================================================
def scan(db: Session, log=lambda _m: None) -> dict:
    out: list[dict] = []
    errors: dict[str, str] = {}
    disk_pct = int(settings.get(db, "integrations.disk_alert_pct") or 90)
    pangolins = list(db.execute(select(PangolinServer).order_by(PangolinServer.id)).scalars())
    log("Pangolin-Dienste einlesen ...")
    services = discovery.services_map(db, pangolins)
    errors.update({f"Pangolin {k}": v for k, v in services["errors"].items()})
    published = {(t["ip"], int(t["port"] or 0)) for t in services["targets"]}
    published_ips = {t["ip"] for t in services["targets"]}
    inventories: dict[int, list[dict]] = {}
    for server in db.execute(select(PveServer).order_by(PveServer.id)).scalars():
        log(f"Proxmox {server.name} einlesen ...")
        try:
            inv = discovery.pve_inventory(db, server)
            inventories[server.id] = inv
            out += scan_pve(db, server, inv, disk_pct)
        except (integrations.ApiError, pve.PveParamError) as exc:
            errors[f"Proxmox {server.name}"] = str(exc)
    for router in db.execute(select(RouterDevice).order_by(RouterDevice.id)).scalars():
        log(f"RouterOS {router.name} einlesen ...")
        try:
            out += scan_router(db, router, published, published_ips, pangolins)
        except integrations.ApiError as exc:
            errors[f"RouterOS {router.name}"] = str(exc)
    log("Pangolin-Wege und Tunnel prüfen ...")
    out += scan_pangolin(db, pangolins, services)
    out += scan_tunnels(db, pangolins, inventories)
    out += scan_systems(db)
    out += scan_apps(db, pangolins, services)
    for mc in db.execute(select(MailcowServer).order_by(MailcowServer.id)).scalars():
        try:
            out += scan_mail(db, mc)
        except integrations.ApiError as exc:
            errors[f"Mail-IP {mc.name}"] = str(exc)
    for p in db.execute(select(PbxServer).order_by(PbxServer.id)).scalars():
        try:
            out += scan_pbx(db, p)
        except integrations.ApiError as exc:
            errors[f"Telefonie {p.name}"] = str(exc)
    return {"at": datetime.now().isoformat(timespec="seconds"), "proposals": out, "errors": errors}


# --------------------------------------------------------------------------
# Proxmox
# --------------------------------------------------------------------------
def scan_pve(db: Session, server: PveServer, inv: list[dict], disk_pct: int) -> list[dict]:
    out = []
    o = _obj("pve", server)
    api = pve.client(server, timeout=15)
    jobs = api.backup_jobs()
    covered_all = any(str(j.get("all", 0)) == "1" and str(j.get("enabled", 1)) != "0" for j in jobs)
    covered = set()
    for j in jobs:
        if str(j.get("enabled", 1)) == "0":
            continue
        for v in str(j.get("vmid", "")).split(","):
            if v.strip().isdigit():
                covered.add(int(v))
    backup_storages = []
    for n in server.data.get("nodes", []):
        try:
            backup_storages = [s["storage"] for s in api.storages(n["node"], "backup")]
            if backup_storages:
                break
        except PveError:
            continue
    vs_bridge = f"vmbr{server.vswitch_vlan}" if server.hosting == "hetzner" and server.vswitch_vlan else ""
    for g in inv:
        label = f"{'CT' if g['type'] == 'lxc' else 'VM'} {g['vmid']} ({g['name']})"
        ref = {"node": g["node"], "type": g["type"], "vmid": g["vmid"], "name": g["name"]}
        base = f"pve:{server.id}:{g['vmid']}"
        if g["status"] == "running" and not g["onboot"]:
            out.append(proposal(f"{base}:onboot", "pve", o, f"{label}: Autostart aktivieren",
                                "Der Gast läuft, startet nach einem Neustart des Hosts aber nicht automatisch.",
                                action="pve_set", params={**ref, "config": {"onboot": 1}}))
        if g["type"] == "qemu" and not g["agent"]:
            out.append(proposal(f"{base}:agent", "pve", o, f"{label}: QEMU-Guest-Agent aktivieren",
                                "Ermöglicht sauberes Herunterfahren, IP-Anzeige, konsistente Sicherungen und den "
                                "Management-Zugang ohne SSH-Passwort. Wirkt nach dem nächsten Neustart der VM; "
                                "im Gast muss qemu-guest-agent installiert sein.",
                                severity="info", action="pve_set", params={**ref, "config": {"agent": 1}}))
        if g["type"] == "lxc" and g["unprivileged"] is False:
            out.append(proposal(f"{base}:priv", "pve", o, f"{label}: privilegierter Container",
                                "Privilegierte Container sind weniger stark vom Host isoliert. Umstellung nur per "
                                "Sicherung und Wiederherstellung als unprivilegierter Container möglich.",
                                severity="info"))
        if not covered_all and g["vmid"] not in covered:
            out.append(proposal(f"{base}:backup", "pve", o, f"{label}: in keinem Sicherungsjob",
                                "Wird in den nächtlichen Sicherungsjob des Servermanagers aufgenommen (02:30, "
                                "Snapshot-Modus, 7 tägliche + 4 wöchentliche Stände).",
                                action="pve_backup_job" if backup_storages else None,
                                params={**ref, "storage": backup_storages[0] if backup_storages else ""},
                                note="" if backup_storages else "Kein Storage mit Inhalt „Backup“ gefunden."))
        if g.get("disk_pct") is not None and disk_pct and g["disk_pct"] >= disk_pct:
            add = max(2, math.ceil((g["maxdisk"] or 0) / 2 ** 30 * 0.25))
            out.append(proposal(f"{base}:disk", "pve", o, f"{label}: Root-Disk zu {g['disk_pct']} % belegt",
                                f"Vergrößerung um {add} GB (Verkleinern ist später nicht möglich).",
                                action="pve_resize", params={**ref, "add_gb": add}))
        if g["status"] == "running" and not g["system"]:
            how = "per pct exec über den Proxmox-Host" if g["type"] == "lxc" else "über den QEMU-Guest-Agent"
            possible = (g["type"] == "lxc" and server.system_id) or (g["type"] == "qemu" and g["agent"])
            out.append(proposal(f"{base}:import", "pve", o, f"{label}: noch nicht verwaltet",
                                f"Management-Zugang anlegen ({how}): SSH-Schlüssel des Servermanagers hinterlegen, "
                                "Hostkey sicher übernehmen und als System aufnehmen (Updates, Überwachung).",
                                severity="info", action="pve_import" if possible else None,
                                params={**ref, "ip": g["ip"]},
                                inputs=[{"name": "install_ssh", "label": "SSH-Server installieren, falls er fehlt",
                                         "kind": "bool", "default": ""}] if possible else [],
                                note="" if possible else ("Proxmox-Host als System verknüpfen (Verbindung "
                                                          "bearbeiten)" if g["type"] == "lxc" else
                                                          "Guest-Agent fehlt")))
        if vs_bridge and g["bridge"] == vs_bridge and g["mtu"] != 1400 and g["config"].get("net0"):
            new = _set_net_opt(g["config"]["net0"], "mtu", "1400")
            out.append(proposal(f"{base}:mtu", "pve", o, f"{label}: MTU 1400 im vSwitch-Netz",
                                "Das Hetzner-vSwitch-Netz hat eine MTU von 1400 – größere Pakete gehen verloren "
                                "(hängende Verbindungen, v. a. bei TLS). Die Netzwerkkarte wird kurz neu initialisiert.",
                                action="pve_set", params={**ref, "config": {"net0": new}}))
    if server.hosting == "hetzner":
        out += _scan_vswitch(server, api, o)
    return out


def _set_net_opt(net: str, key: str, value: str) -> str:
    parts = [p for p in net.split(",") if not p.startswith(key + "=")]
    parts.append(f"{key}={value}")
    return ",".join(parts)


def _scan_vswitch(server: PveServer, api, o: dict) -> list[dict]:
    out = []
    vlan = server.vswitch_vlan
    if not vlan:
        return [proposal(f"pve:{server.id}:vswitch-cfg", "pve", o, "Hetzner: vSwitch-VLAN nicht hinterlegt",
                         "In der Proxmox-Verbindung die VLAN-ID des vSwitch (4000–4091) eintragen, damit die "
                         "Einbindung auf allen Nodes geprüft werden kann.", severity="info")]
    for n in server.data.get("nodes", []):
        node = n["node"]
        try:
            nets = api.networks(node)
        except PveError:
            continue
        vl = next((x for x in nets if x.get("type") == "vlan" and (str(x.get("vlan-id")) == str(vlan)
                   or str(x.get("iface", "")).endswith(f".{vlan}"))), None)
        br = next((x for x in nets if x.get("type") == "bridge" and vl is not None and
                   vl.get("iface") in str(x.get("bridge_ports", "")).split()), None)
        if vl and br:
            bad = [x["iface"] for x in (vl, br) if str(x.get("mtu", "")) != "1400"]
            if bad:
                out.append(proposal(f"pve:{server.id}:{node}:vsmtu", "pve", o,
                                    f"Node {node}: MTU der vSwitch-Interfaces ist nicht 1400",
                                    f"Betroffen: {', '.join(bad)}. Hetzner verlangt MTU 1400 im vSwitch.",
                                    severity="info"))
            continue
        phys = next((x.get("bridge_ports", "").split()[0] for x in nets if x.get("iface") == "vmbr0"
                     and x.get("bridge_ports")), "")
        if not phys:
            phys = next((x["iface"] for x in nets if x.get("type") == "eth" and x.get("active")), "")
        out.append(proposal(f"pve:{server.id}:{node}:vswitch", "pve", o,
                            f"Node {node}: vSwitch (VLAN {vlan}) nicht eingebunden",
                            f"Legt {phys}.{vlan} (MTU 1400) und die Bridge vmbr{vlan} an und lädt die Netzwerk-"
                            "konfiguration neu (ifreload, vorhandene Interfaces bleiben unverändert). Danach können "
                            "Gäste über lokale IPs mit den anderen Hosts kommunizieren.",
                            action="pve_vswitch" if phys else None,
                            params={"node": node, "vlan": vlan, "phys": phys, "bridge": f"vmbr{vlan}"},
                            note="" if phys else "Physisches Interface nicht ermittelbar"))
    return out


# --------------------------------------------------------------------------
# RouterOS
# --------------------------------------------------------------------------
def scan_router(db: Session, router: RouterDevice, published: set, published_ips: set,
                pangolins: list[PangolinServer]) -> list[dict]:
    out = []
    o = _obj("router", router)
    mt = integrations.router_client(router)
    snap = routeros.snapshot_from_api(mt)
    target = router.target_cfg or routeros.detect_target(snap)
    target, _err = routeros.validate_target(target)
    for f in routeros.analyze(snap, target):
        if f["status"] in ("ok", "check"):
            continue
        out.append(proposal(f"router:{router.id}:{f['id']}", "router", o, f["title"], f["detail"],
                            severity=f["severity"], action="router_finding" if f["applicable"] else None,
                            params={"finding": f["id"], "script": f["script"]},
                            note="" if f["applicable"] else "Nur als Skript (Zugangsschutz) – siehe Router → "
                                                            "Konfigurationsanalyse"))
    primary = next((p for p in pangolins if p.role == "primary"), None)
    leases = routeros.items(snap, "ip/dhcp-server/lease")
    systems_ips = {s.host for s in db.execute(select(System)).scalars()}
    for r in routeros.items(snap, "ip/firewall/nat"):
        if r.get("chain") != "dstnat" or not routeros.enabled(r) or not r.get("to-addresses"):
            continue
        ip = r["to-addresses"]
        port_s = str(r.get("to-ports") or r.get("dst-port") or "")
        if not port_s.isdigit():
            continue
        port = int(port_s)
        proto = r.get("protocol", "tcp")
        if _is_mail_forward(db, r) or _is_pbx_forward(db, r):
            continue  # mail and SIP/RTP need real port forwarding - an intended exception
        text = routeros._rule_text(r)
        if (ip, port) in published:
            out.append(proposal(f"router:{router.id}:fwd-off:{r.get('.id')}", "goal", o,
                                f"Portfreigabe {proto}/{r.get('dst-port')} → {ip}:{port} ist durch Pangolin ersetzt",
                                "Der Dienst ist bereits über Pangolin erreichbar – die Portfreigabe auf der "
                                "öffentlichen IP kann deaktiviert werden (nicht gelöscht, jederzeit reaktivierbar).",
                                action="router_nat_disable", params={"nat_id": r.get(".id"), "ip": ip, "port": port},
                                note=text))
            continue
        lease = next((le for le in leases if le.get("address") == ip), {})
        name = (lease.get("host-name") or r.get("comment") or f"dienst-{port}").lower()
        name = "".join(c if c.isalnum() or c == "-" else "-" for c in name).strip("-")[:40] or f"dienst-{port}"
        http = proto == "tcp" and port in HTTP_PORTS
        out.append(proposal(f"router:{router.id}:fwd:{r.get('.id')}", "goal", o,
                            f"Portfreigabe {proto}/{r.get('dst-port')} → {ip}:{port} über Pangolin veröffentlichen",
                            "Statt einer Portfreigabe auf der öffentlichen IP wird der Dienst über den Pangolin-"
                            "Tunnel veröffentlicht (Portfreigabe bleibt zunächst bestehen; nach erfolgreichem Test "
                            "schlägt der nächste Scan das Deaktivieren vor).",
                            action="publish_forward" if primary else None,
                            params={"pangolin_id": primary.id if primary else None, "ip": ip, "port": port,
                                    "protocol": "http" if http else proto, "method": HTTP_PORTS.get(port, "http"),
                                    "name": name, "proxy_port": int(port_s) if not http else None},
                            inputs=[{"name": "subdomain", "label": "Subdomain", "kind": "text", "default": name}]
                            if http else [],
                            note="" if primary else "Keine primäre Pangolin-Instanz eingerichtet"))
    for le in leases:
        if le.get("dynamic") == "true" and (le.get("address") in published_ips or le.get("address") in systems_ips):
            out.append(proposal(f"router:{router.id}:lease:{le.get('mac-address')}", "router", o,
                                f"Lease {le.get('address')} ({le.get('host-name') or le.get('mac-address')}) statisch machen",
                                "Die Adresse wird von Pangolin oder dem Servermanager verwendet – ändert sie sich, "
                                "ist der Dienst nicht mehr erreichbar.",
                                action="router_lease_static", params={"lease_id": le.get(".id"),
                                                                      "address": le.get("address"),
                                                                      "mac": le.get("mac-address")}))
    return out


# --------------------------------------------------------------------------
# Pangolin paths
# --------------------------------------------------------------------------
def scan_pangolin(db: Session, pangolins: list[PangolinServer], services: dict) -> list[dict]:
    out = []
    primaries = [p for p in pangolins if p.role == "primary"]
    backups = [p for p in pangolins if p.role == "backup"]
    if primaries and not backups:
        out.append(proposal("pangolin:no-backup", "tunnel", {"kind": "pangolin", "id": primaries[0].id,
                                                             "name": primaries[0].name},
                            "Kein Backup-Weg eingerichtet",
                            "Fällt der Pangolin-Server oder sein Newt-Container aus, sind alle Dienste von außen "
                            "nicht erreichbar. Empfohlen: zweiter Pangolin-Server (Rolle „Backup-Weg“) mit eigenem "
                            "Newt-Container auf einem anderen Proxmox-Host.", severity="info"))
    backup = backups[0] if backups else None
    for t in services["targets"]:
        primary_paths = [p for p in t["paths"] if p["role"] == "primary"]
        if backup and primary_paths and not t["backup"]:
            p = primary_paths[0]
            r = p["resource"]
            name = r.get("name") or f"{t['ip']}:{t['port']}"
            plan = t.get("planned") or {}
            if plan.get("error"):
                out.append(proposal(f"pangolin:mirror:{t['ip']}:{t['port']}", "tunnel", _obj("pangolin", backup),
                                    f"{name}: Backup-Weg fehlt", plan["error"] + " (Pangolin → Bearbeiten → "
                                    "Domain-Zuordnung)", severity="warn"))
            else:
                target_name = plan.get("full") or ""
                out.append(proposal(f"pangolin:mirror:{t['ip']}:{t['port']}", "tunnel", _obj("pangolin", backup),
                                    f"{name}: Backup-Weg {p['domain']} → {target_name}",
                                    f"{t['ip']}:{t['port']} wird zusätzlich über {backup.name} veröffentlicht"
                                    + ("" if plan.get("mapped", True) else " (keine Domain-Zuordnung für "
                                       f"{p['base']} – Standard-Domain)") + ".",
                                    action="pangolin_mirror",
                                    params={"pangolin_id": backup.id, "name": name, "ip": t["ip"], "port": t["port"],
                                            "http": p["http"], "method": p.get("method") or "http",
                                            "subdomain": plan.get("subdomain", ""),
                                            "domain_id": plan.get("domain_id", ""),
                                            "proxy_port": r.get("proxyPort"),
                                            "protocol": "http" if p["http"] else (r.get("protocol") or "tcp"),
                                            "sso": bool(r.get("sso"))}))
        if backup and t.get("planned") and t["planned"].get("mismatch"):
            have = ", ".join(x["domain"] for x in t["paths"] if x["role"] == "backup")
            out.append(proposal(f"pangolin:mirror-name:{t['ip']}:{t['port']}", "tunnel", _obj("pangolin", backup),
                                f"Backup-Adresse weicht von der Domain-Zuordnung ab ({have})",
                                f"Laut Zuordnung wäre es {t['planned']['full']}. Bei Bedarf in Pangolin anpassen.",
                                severity="info"))
        for p in t["paths"]:
            if p["http"] and not p["sso"]:
                out.append(proposal(f"pangolin:sso:{p['pangolin'].id}:{p['resource'].get('resourceId')}", "pangolin",
                                    _obj("pangolin", p["pangolin"]), f"{p['domain']} ohne Pangolin-Anmeldung",
                                    "Der Dienst ist für jeden im Internet erreichbar. Wenn er keine eigene, sichere "
                                    "Anmeldung hat: Pangolin-Anmeldung (SSO) aktivieren.", severity="info",
                                    action="pangolin_sso", params={"pangolin_id": p["pangolin"].id,
                                                                   "resource_id": p["resource"].get("resourceId")}))
    for pg in pangolins:
        for s in pg.data.get("sites", []):
            if not s.get("online"):
                out.append(proposal(f"pangolin:{pg.id}:site:{s.get('id')}", "tunnel", _obj("pangolin", pg),
                                    f"Site {s.get('name')} ist offline", "Der Newt-Client ist nicht verbunden – "
                                    "alle Dienste über diesen Weg sind nicht erreichbar.", severity="crit",
                                    action="newt_restart" if pg.tunnel_system_id else None,
                                    params={"system_id": pg.tunnel_system_id}))
    return out


def scan_tunnels(db: Session, pangolins: list[PangolinServer], inventories: dict[int, list[dict]]) -> list[dict]:
    out = []
    placements = []
    for pg in pangolins:
        o = _obj("pangolin", pg)
        if not pg.tunnel_system_id:
            out.append(proposal(f"tunnel:{pg.id}:none", "tunnel", o, f"{pg.name}: Tunnel-Container nicht zugeordnet",
                                "Unter Pangolin → Bearbeiten das System mit dem Newt-Client auswählen oder unter "
                                "„Tunnel-Container einrichten“ Newt installieren – dann kann der Servermanager den "
                                "Tunnel überwachen, neu starten und die Verteilung auf die Hosts prüfen.",
                                severity="info"))
            continue
        system = db.get(System, pg.tunnel_system_id)
        if system is None:
            continue
        if (system.fact.get("newt_active") or "") not in ("active", "") and system.fact.get("newt_version"):
            out.append(proposal(f"tunnel:{pg.id}:down", "tunnel", o, f"Newt auf {system.name} läuft nicht",
                                "Der Tunnel-Dienst ist gestoppt.", severity="crit", action="newt_restart",
                                params={"system_id": system.id}))
        place = None
        if system.pve_server_id and system.pve_vmid:
            server = db.get(PveServer, system.pve_server_id)
            guest = next((g for g in (inventories.get(system.pve_server_id) or server.data.get("guests", []) if server
                                      else []) if g["vmid"] == system.pve_vmid), None)
            if server and guest:
                place = {"pg": pg, "system": system, "server": server, "node": guest["node"], "type": guest["type"],
                         "vmid": guest["vmid"]}
                if system.pve_vmid not in server.watch_list:
                    out.append(proposal(f"tunnel:{pg.id}:watch", "tunnel", o,
                                        f"Tunnel-Container {system.name} überwachen",
                                        "Warnung, wenn der Container nicht läuft.", severity="info",
                                        action="pve_watch", params={"pve_id": server.id, "vmid": system.pve_vmid}))
        if place is None:
            out.append(proposal(f"tunnel:{pg.id}:unplaced", "tunnel", o,
                                f"Standort des Tunnel-Containers {system.name} unbekannt",
                                "Das System ist keinem Proxmox-Gast zugeordnet – die Verteilung der Tunnel auf "
                                "verschiedene Hosts kann nicht geprüft werden.", severity="info"))
        else:
            placements.append(place)
    # the Newt clients of different Pangolin servers must not share a host
    for a_idx, a in enumerate(placements):
        for b in placements[a_idx + 1:]:
            if a["server"].id == b["server"].id and a["node"] == b["node"]:
                victim = b if b["pg"].role == "backup" else a
                other = a if victim is b else b
                nodes = [n for n in victim["server"].data.get("nodes", [])
                         if n.get("status") == "online" and n["node"] != victim["node"]]
                target = min(nodes, key=lambda n: n.get("mem_pct", 0))["node"] if nodes else ""
                out.append(proposal(
                    f"tunnel:{victim['pg'].id}:colocated", "tunnel", _obj("pangolin", victim["pg"]),
                    f"Beide Tunnel laufen auf demselben Host ({victim['server'].name}/{victim['node']})",
                    f"Fällt {victim['node']} aus, sind primärer und Backup-Weg gleichzeitig weg. "
                    + (f"{victim['system'].name} wird auf {target} migriert (Container: kurzer Neustart)."
                       if target else "Der Cluster hat keinen weiteren Node – den Tunnel-Container von "
                       f"{victim['pg'].name} auf einem anderen Proxmox-Host neu anlegen (Container anlegen → "
                       "„Als Newt-Tunnel einrichten“) und hier zuordnen."),
                    severity="crit", action="pve_migrate" if target else None,
                    params={"pve_id": victim["server"].id, "node": victim["node"], "type": victim["type"],
                            "vmid": victim["vmid"], "target": target, "name": victim["system"].name,
                            "other": other["system"].name}))
    return out


def _is_mail_forward(db: Session, r: dict) -> bool:
    ports = set(str(r.get("dst-port", "")).split(","))
    for mc in db.execute(select(MailcowServer)).scalars():
        if not mc.mail_public_ip:
            continue
        if (r.get("dst-address") == mc.mail_public_ip or r.get("to-addresses") == mc.mail_internal_ip) and \
                ports <= {str(p) for p in mc.port_list}:
            return True
    return False


def _is_pbx_forward(db: Session, r: dict) -> bool:
    for p in db.execute(select(PbxServer)).scalars():
        if p.sip_internal_ip and r.get("to-addresses") == p.sip_internal_ip and \
                r.get("protocol", "") in ("udp", "tcp"):
            return True
    return False


def _host_port(url: str, default_port: int = 443) -> tuple[str, int, str]:
    from urllib.parse import urlsplit
    parts = urlsplit(url if "://" in url else "https://" + url)
    return parts.hostname or "", parts.port or (443 if parts.scheme == "https" else 80), parts.scheme or "https"


def scan_apps(db: Session, pangolins: list[PangolinServer], services: dict) -> list[dict]:
    """Web UIs of authentik, Mailcow and connected Nextclouds must be reachable through Pangolin."""
    out = []
    primary = next((p for p in pangolins if p.role == "primary"), None)
    published = {p["domain"] for t in services["targets"] for p in t["paths"]}
    domains = services.get("domains", {}).get(primary.id, {}) if primary else {}
    apps = []
    for srv in db.execute(select(SsoServer)).scalars():
        apps.append(("sso", srv, srv.public_url, srv.api_url, f"authentik {srv.name}"))
    for mc in db.execute(select(MailcowServer)).scalars():
        apps.append(("mailcow", mc, mc.public_url, mc.api_url, f"Mailcow {mc.name}"))
    for p in db.execute(select(PbxServer)).scalars():
        apps.append(("pbx", p, p.public_url, p.web_url, f"Telefonanlage {p.name}"))
    for i in db.execute(select(IspServer)).scalars():
        apps.append(("ispconfig", i, i.public_url, i.panel_url, f"ISPConfig {i.name}"))
    for cl in db.execute(select(SsoClient).where(SsoClient.target_kind == "nextcloud")).scalars():
        system = db.get(System, cl.target_id)
        if system:
            apps.append(("system", system, cl.app_url, f"https://{system.host}", f"Nextcloud {system.name}"))
    for kind, obj, public, internal, label in apps:
        if not public or not internal:
            continue
        host, _p, _s = _host_port(public)
        if host in published:
            continue
        ihost, iport, ischeme = _host_port(internal)
        match = next(((did, base) for did, base in domains.items() if host == base or host.endswith("." + base)),
                     None)
        sub = host[:-len(match[1]) - 1] if match and host != match[1] else ""
        out.append(proposal(f"app:{kind}:{obj.id}:publish", "goal", _obj(kind, obj),
                            f"{label}: Weboberfläche {host} über Pangolin veröffentlichen",
                            f"Ziel {ischeme}://{ihost}:{iport} (intern) wird als {host} über {primary.name if primary else '–'} "
                            "veröffentlicht – ohne Pangolin-Anmeldung, weil die Anwendung selbst anmeldet bzw. SSO "
                            "nutzt (Clients und Apps müssen durchkommen).",
                            action="publish_forward" if primary and match else None,
                            params={"pangolin_id": primary.id if primary else None, "ip": ihost, "port": iport,
                                    "protocol": "http", "method": ischeme, "name": label, "subdomain": sub,
                                    "domain_id": match[0] if match else "", "proxy_port": None, "sso": False},
                            note="" if primary and match else f"Domain von {host} ist auf keinem primären Pangolin "
                                                              "eingerichtet"))
    return out


def scan_mail(db: Session, mc: MailcowServer) -> list[dict]:
    """Own public IP for IMAP/SMTP: address on WAN, dst-nat of the mail ports, outgoing mail via that IP."""
    out = []
    o = _obj("mailcow", mc)
    if not mc.mail_public_ip or not mc.mail_internal_ip or not mc.router_id:
        if mc.mail_public_ip:
            out.append(proposal(f"mail:{mc.id}:cfg", "router", o, f"{mc.name}: Mail-IP ohne Router/interne Adresse",
                                "Für die Prüfung der Weiterleitung interne Mailcow-Adresse und RouterOS angeben.",
                                severity="info"))
        return out
    router = db.get(RouterDevice, mc.router_id)
    if router is None:
        return out
    mt = integrations.router_client(router)
    snap = routeros.snapshot_from_api(mt)
    target, _e = routeros.validate_target(router.target_cfg or routeros.detect_target(snap))
    wan = target["wan_interface"]
    ip, internal, ports = mc.mail_public_ip, mc.mail_internal_ip, ",".join(str(p) for p in mc.port_list)
    ops = []
    if not any(str(a.get("address", "")).split("/")[0] == ip for a in routeros.items(snap, "ip/address")):
        ops.append(routeros.op_add("ip/address", {"address": f"{ip}/32", "interface": wan,
                                                  "comment": f"servermanager: Mail-IP {mc.name}"}))
    nat = routeros.items(snap, "ip/firewall/nat")
    covered = set()
    for r in nat:
        if r.get("chain") == "dstnat" and routeros.enabled(r) and r.get("dst-address") == ip and \
                r.get("to-addresses") == internal:
            covered |= set(str(r.get("dst-port", "")).split(","))
    missing = [p for p in ports.split(",") if p and p not in covered]
    if missing:
        ops.append(routeros.op_add("ip/firewall/nat", {
            "chain": "dstnat", "action": "dst-nat", "dst-address": ip, "protocol": "tcp",
            "dst-port": ",".join(missing), "to-addresses": internal,
            "comment": f"servermanager: Mail {mc.name}"}))
    snat = [r for r in nat if r.get("chain") == "srcnat" and r.get("action") == "src-nat" and routeros.enabled(r)
            and r.get("src-address") in (internal, f"{internal}/32") and r.get("to-addresses") == ip]
    if not snat:
        first_masq = next((r for r in nat if r.get("chain") == "srcnat" and r.get("action") == "masquerade"), None)
        data = {"chain": "srcnat", "action": "src-nat", "src-address": internal, "out-interface": wan,
                "to-addresses": ip, "comment": f"servermanager: ausgehende Mails {mc.name} über Mail-IP"}
        if first_masq and first_masq.get(".id"):
            data["place-before"] = first_masq[".id"]
        ops.append(routeros.op_add("ip/firewall/nat", data))
    if ops:
        out.append(proposal(f"mail:{mc.id}:router", "router", o,
                            f"{mc.name}: Mail-IP {ip} auf {router.name} einrichten",
                            f"IMAP/SMTP über die eigene Public-IP: {len(ops)} Änderung(en) – "
                            + "; ".join(routeros.op_to_cli(x) for x in ops),
                            action="router_direct_ops",
                            params={"router_id": router.id, "ops": ops}))
    out.append(proposal(f"mail:{mc.id}:dns", "router", o, f"{mc.name}: DNS für den Mailversand prüfen",
                        f"PTR (Reverse-DNS) von {ip} → {mc.mail_hostname or 'Mail-Hostname'} (beim Provider, z. B. "
                        f"Hetzner Robot), MX und A-Record von {mc.mail_hostname or 'mail.…'} → {ip}, SPF mit "
                        f"ip4:{ip}, DKIM und DMARC. Die Weboberfläche läuft unter einem eigenen Namen über "
                        "Pangolin.", severity="info"))
    return out


PBX_TAG = "servermanager: SIP"


def pbx_router_ops(p: PbxServer, snap: dict, wan: str) -> list[dict]:
    """RouterOS changes for SIP/RTP to the PBX: allowed peers, dst-nat, own public IP (+ src-nat)."""
    ops: list[dict] = []
    internal = p.sip_internal_ip
    list_name = f"sm-sip-{p.id}"
    if p.sip_public_ip and not any(str(a.get("address", "")).split("/")[0] == p.sip_public_ip
                                   for a in routeros.items(snap, "ip/address")):
        ops.append(routeros.op_add("ip/address", {"address": f"{p.sip_public_ip}/32", "interface": wan,
                                                  "comment": f"{PBX_TAG} {p.name}"}))
    have = {(a.get("list"), a.get("address")) for a in routeros.items(snap, "ip/firewall/address-list")}
    for src in p.source_list:
        if (list_name, src) not in have:
            ops.append(routeros.op_add("ip/firewall/address-list", {"list": list_name, "address": src,
                                                                    "comment": f"{PBX_TAG} {p.name}"}))
    nat = [r for r in routeros.items(snap, "ip/firewall/nat") if r.get("chain") == "dstnat" and routeros.enabled(r)
           and r.get("to-addresses") == internal]

    def covered(proto: str, port: str) -> bool:
        return any(r.get("protocol") == proto and port in str(r.get("dst-port", "")).split(",") for r in nat)
    wanted = [("udp", str(p.sip_port), True), ("tcp", str(p.sip_port), True)]
    if p.sip_tls_port:
        wanted.append(("tcp", str(p.sip_tls_port), True))
    wanted.append(("udp", f"{p.rtp_start}-{p.rtp_end}", False))
    for proto, port, signalling in wanted:
        if covered(proto, port):
            continue
        data = {"chain": "dstnat", "action": "dst-nat", "protocol": proto, "dst-port": port,
                "to-addresses": internal, "comment": f"{PBX_TAG} {p.name}"}
        if p.sip_public_ip:
            data["dst-address"] = p.sip_public_ip
        else:
            data["in-interface"] = wan
        if signalling and p.source_list:
            data["src-address-list"] = list_name
        ops.append(routeros.op_add("ip/firewall/nat", data))
    if p.sip_public_ip:
        snat = [r for r in routeros.items(snap, "ip/firewall/nat") if r.get("chain") == "srcnat"
                and r.get("action") == "src-nat" and routeros.enabled(r)
                and r.get("src-address") in (internal, f"{internal}/32") and r.get("to-addresses") == p.sip_public_ip]
        if not snat:
            nat_all = routeros.items(snap, "ip/firewall/nat")
            first_masq = next((r for r in nat_all if r.get("chain") == "srcnat" and r.get("action") == "masquerade"),
                              None)
            data = {"chain": "srcnat", "action": "src-nat", "src-address": internal, "out-interface": wan,
                    "to-addresses": p.sip_public_ip, "comment": f"{PBX_TAG} {p.name} ausgehend"}
            if first_masq and first_masq.get(".id"):
                data["place-before"] = first_masq[".id"]
            ops.append(routeros.op_add("ip/firewall/nat", data))
    return ops


def scan_pbx(db: Session, p: PbxServer) -> list[dict]:
    """SIP/RTP to the PBX: port forwarding on the router, SIP-ALG off, restricted peers, Asterisk NAT settings."""
    out = []
    o = _obj("pbx", p)
    if not p.router_id or not p.sip_internal_ip:
        out.append(proposal(f"pbx:{p.id}:cfg", "router", o, f"{p.name}: kein Router/keine interne Adresse",
                            "Für Weiterleitung und Prüfung RouterOS und interne IP der Telefonanlage angeben.",
                            severity="info"))
        return out
    router = db.get(RouterDevice, p.router_id)
    if router is None:
        return out
    mt = integrations.router_client(router)
    snap = routeros.snapshot_from_api(mt)
    target, _e = routeros.validate_target(router.target_cfg or routeros.detect_target(snap))
    wan = target["wan_interface"]
    sip_helper = next((sp for sp in routeros.items(snap, "ip/firewall/service-port") if sp.get("name") == "sip"),
                      None)
    if sip_helper and not routeros.yes(sip_helper.get("disabled")):
        out.append(proposal(f"pbx:{p.id}:alg", "router", o, f"{router.name}: SIP-Helper (SIP-ALG) abschalten",
                            "Der SIP-Helper von RouterOS schreibt SIP-Pakete um und verursacht einseitige Audio, "
                            "abbrechende Registrierungen und verlorene Anrufe. Asterisk regelt NAT selbst.",
                            action="router_direct_ops",
                            params={"router_id": router.id, "ops": [routeros.op_set(
                                "ip/firewall/service-port", {"disabled": "yes"}, item_id=sip_helper.get(".id", ""),
                                find="name=sip")]}))
    ops = pbx_router_ops(p, snap, wan)
    if ops:
        out.append(proposal(f"pbx:{p.id}:router", "router", o,
                            f"{p.name}: SIP/RTP-Weiterleitung auf {router.name} einrichten",
                            f"{len(ops)} Änderung(en) – " + "; ".join(routeros.op_to_cli(x) for x in ops),
                            action="router_direct_ops", params={"router_id": router.id, "ops": ops}))
    if not p.source_list:
        out.append(proposal(f"pbx:{p.id}:open", "router", o, f"{p.name}: SIP-Port für alle Absender offen",
                            "Unter Telefonie → Bearbeiten die Adressen des SIP-Providers als erlaubte Gegenstellen "
                            "eintragen; die Weiterleitung wird dann darauf beschränkt. Externe Telefone besser per "
                            "VPN anbinden.", severity="warn"))
    nat = (p.data or {}).get("nat") or {}
    if p.data and not (nat.get("external_media_address") or nat.get("external_signaling_address")):
        out.append(proposal(f"pbx:{p.id}:extaddr", "router", o, f"{p.name}: externe Adresse in Asterisk fehlt",
                            "FreePBX → Einstellungen → Asterisk SIP Settings: External Address und Local Networks "
                            "setzen, sonst fehlt bei Gesprächen von außen der Ton.", severity="warn"))
    return out


def scan_systems(db: Session) -> list[dict]:
    out = []
    for s in db.execute(select(System).order_by(System.name)).scalars():
        if s.connection == "direct" and _is_public(s.host):
            out.append(proposal(f"system:{s.id}:public", "goal", _obj("system", s),
                                f"{s.name}: Verwaltung über öffentliche IP {s.host}",
                                "SSH ist dafür aus dem Internet erreichbar. Besser: Verwaltung über das "
                                "WireGuard-Management-Netz oder eine interne Adresse, SSH auf der öffentlichen IP "
                                "sperren (Enrollment → WireGuard).", severity="info"))
    return out


# --------------------------------------------------------------------------
def load(db: Session) -> dict:
    return settings.get(db, STATE_KEY) or {}


def save(db: Session, result: dict) -> None:
    settings.set(db, STATE_KEY, result)


def get(db: Session, pid: str) -> Optional[dict]:
    return next((p for p in load(db).get("proposals", []) if p["id"] == pid), None)


def summary(result: dict) -> dict[str, Any]:
    props = result.get("proposals", [])
    return {"total": len(props), "actionable": sum(1 for p in props if p.get("action")),
            "crit": sum(1 for p in props if p["severity"] == "crit")}
