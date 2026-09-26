"""Inventory of existing infrastructure: what exists where, and what is already managed.

Everything here only reads - changes are proposed by optimize.py and applied
after confirmation.
"""
from __future__ import annotations

import ipaddress
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import integrations, pve
from .models import PangolinServer, PveServer, RouterDevice, System
from .pangolin import PangolinError, backup_address
from .pveapi import PveError


def _systems_by_ip(db: Session) -> dict[str, System]:
    return {s.host: s for s in db.execute(select(System)).scalars() if s.host}


def pve_inventory(db: Session, server: PveServer, with_ip: bool = True) -> list[dict]:
    """Guests of a Proxmox connection with IP, MAC and the matching system (if any)."""
    api = pve.client(server, timeout=15)
    data = pve.overview(api)
    by_ip = _systems_by_ip(db)
    linked = {s.pve_vmid: s for s in db.execute(select(System).where(System.pve_server_id == server.id)).scalars()}
    rows = []
    for g in data["guests"]:
        if g["template"]:
            continue
        row = dict(g)
        row.update({"ip": "", "mac": "", "system": None, "match": "", "agent": False, "unprivileged": None,
                    "onboot": None, "ostype": "", "bridge": "", "mtu": None})
        try:
            cfg = api.guest_config(g["node"], g["type"], g["vmid"])
        except PveError:
            cfg = {}
        net0 = str(cfg.get("net0", ""))
        row["mac"] = pve.net0_mac(cfg) or _qemu_mac(net0)
        row["bridge"] = _net_opt(net0, "bridge")
        mtu = _net_opt(net0, "mtu")
        row["mtu"] = int(mtu) if mtu.isdigit() else None
        row["agent"] = str(cfg.get("agent", "0")).split(",")[0] in ("1", "enabled=1")
        row["unprivileged"] = bool(int(cfg.get("unprivileged", 0) or 0)) if g["type"] == "lxc" else None
        row["onboot"] = bool(int(cfg.get("onboot", 0) or 0))
        row["ostype"] = cfg.get("ostype", "")
        row["config"] = cfg
        if with_ip and g["status"] == "running":
            try:
                row["ip"] = pve.container_ipv4(api, g["node"], g["vmid"]) if g["type"] == "lxc" \
                    else api.agent_ipv4(g["node"], g["vmid"])
            except PveError:
                pass
        if not row["ip"]:
            ipcfg = _net_opt(net0, "ip")
            if ipcfg and ipcfg not in ("dhcp", "manual"):
                row["ip"] = ipcfg.split("/")[0]
        if g["vmid"] in linked:
            row["system"], row["match"] = linked[g["vmid"]], "linked"
        elif row["ip"] and row["ip"] in by_ip:
            row["system"], row["match"] = by_ip[row["ip"]], "ip"
        rows.append(row)
    return rows


def _net_opt(net: str, key: str) -> str:
    for part in net.split(","):
        k, _, v = part.partition("=")
        if k.strip() == key:
            return v.strip()
    return ""


def _qemu_mac(net: str) -> str:
    # qemu: "virtio=BC:24:11:..,bridge=vmbr0"
    first = net.split(",")[0]
    if "=" in first:
        v = first.split("=", 1)[1]
        if len(v) == 17 and v.count(":") == 5:
            return v.upper()
    return ""


def router_devices(db: Session, router: RouterDevice) -> list[dict]:
    """Devices in the router's networks (DHCP leases + ARP), matched with systems."""
    mt = integrations.router_client(router)
    leases = mt.get("ip/dhcp-server/lease")
    try:
        arp = mt.get("ip/arp")
    except Exception:  # noqa: BLE001 - optional
        arp = []
    nat = [r for r in mt.get("ip/firewall/nat") if r.get("chain") == "dstnat" and r.get("disabled") != "true"]
    by_ip = _systems_by_ip(db)
    devices: dict[str, dict] = {}
    for le in leases:
        ip = le.get("address") or le.get("active-address")
        if not ip:
            continue
        devices[ip] = {"ip": ip, "mac": (le.get("mac-address") or le.get("active-mac-address") or "").upper(),
                       "host": le.get("host-name", ""), "lease": "dynamisch" if le.get("dynamic") == "true" else
                       "statisch", "lease_id": le.get(".id"), "comment": le.get("comment", ""),
                       "interface": le.get("server", ""), "forwards": []}
    for a in arp:
        ip = a.get("address")
        if not ip or ip in devices or a.get("complete") == "false":
            continue
        if a.get("dynamic") == "true" or a.get("mac-address"):
            devices[ip] = {"ip": ip, "mac": (a.get("mac-address") or "").upper(), "host": "", "lease": "",
                           "lease_id": None, "comment": a.get("comment", ""), "interface": a.get("interface", ""),
                           "forwards": []}
    for r in nat:
        to = r.get("to-addresses", "")
        if to in devices:
            devices[to]["forwards"].append(f"{r.get('protocol', '')}/{r.get('dst-port', '')}→{r.get('to-ports', '') or r.get('dst-port', '')}")
    rows = sorted(devices.values(), key=lambda d: _ip_key(d["ip"]))
    for d in rows:
        d["system"] = by_ip.get(d["ip"])
    return rows


def _ip_key(ip: str):
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, ip)


def services_map(db: Session, pangolins: Optional[list[PangolinServer]] = None) -> dict:
    """All published services across Pangolin instances, grouped by internal target (ip:port)."""
    pangolins = pangolins if pangolins is not None else list(db.execute(select(PangolinServer)).scalars())
    by_ip = _systems_by_ip(db)
    targets: dict[str, dict] = {}
    errors: dict[str, str] = {}
    domains: dict[int, dict[str, str]] = {}
    for pg in pangolins:
        try:
            client = integrations.pangolin_client(pg)
            domains[pg.id] = {d.get("domainId"): d.get("baseDomain") for d in client.domains()}
            resources = client.resources()
            for r in resources:
                tlist = r.get("targets")
                if tlist is None:
                    tlist = client.targets(r["resourceId"])
                for t in tlist or []:
                    key = f"{t.get('ip')}:{t.get('port')}"
                    entry = targets.setdefault(key, {"ip": t.get("ip"), "port": t.get("port"), "paths": [],
                                                     "system": by_ip.get(t.get("ip"))})
                    entry["paths"].append({"pangolin": pg, "role": pg.role, "resource": r,
                                           "domain": r.get("fullDomain") or f"{(r.get('protocol') or '').upper()}:{r.get('proxyPort')}",
                                           "sso": r.get("sso"), "enabled": r.get("enabled", True) is not False,
                                           "http": bool(r.get("http")), "method": t.get("method"),
                                           "base": domains[pg.id].get(r.get("domainId"), ""),
                                           "sub": r.get("subdomain") or ""})
        except integrations.ApiError as exc:
            errors[pg.name] = str(exc)
    rows = sorted(targets.values(), key=lambda e: (_ip_key(e["ip"] or ""), e["port"] or 0))
    backups = [p for p in pangolins if p.role == "backup" and p.id in domains]
    for e in rows:
        roles = {p["role"] for p in e["paths"]}
        e["primary"] = "primary" in roles
        e["backup"] = "backup" in roles
        e["planned"] = None
        src = next((p for p in e["paths"] if p["role"] == "primary"), None)
        if src and backups:
            bk = backups[0]
            try:
                addr = backup_address(bk, src["base"], src["sub"], domains[bk.id]) if src["http"] else None
                e["planned"] = {"pangolin": bk, "source": src, **(addr or {"full": f"{(src['resource'].get('protocol') or 'tcp').upper()}:{src['resource'].get('proxyPort')}"})}
            except PangolinError as exc:
                e["planned"] = {"pangolin": bk, "source": src, "error": str(exc)}
            # an existing backup path with a different name than the mapping says
            if e["backup"] and e["planned"] and e["planned"].get("full"):
                have = {p["domain"] for p in e["paths"] if p["role"] == "backup"}
                e["planned"]["mismatch"] = src["http"] and e["planned"]["full"] not in have
    return {"targets": rows, "errors": errors, "domains": domains}
