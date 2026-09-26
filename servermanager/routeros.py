"""RouterOS 7 (e.g. CHR): configuration import, analysis against the target setup and fixes.

Target setup ("Soll")::

    Internet ── WAN (public IP) ── RouterOS ── LAN bridge (DHCP) ── LXC with Newt ─→ Pangolin
                                                             └── further services

* the internal network gets its addresses from the RouterOS DHCP server,
* the services reach the internet through source NAT (masquerade) on the WAN
  interface - optionally with policy routing (mangle marks + own routing table),
  so that e.g. a management WireGuard tunnel with wide AllowedIPs does not
  swallow the internet traffic and replies to connections that came in via WAN
  leave via WAN again,
* published services are reached through the Pangolin tunnel (Newt only needs
  outgoing connections - no port forwarding).

The running configuration is imported (REST API or a pasted ``/export``) and
compared with that target. Every finding says whether the current state can
stay, has to be changed or is missing. Additive and uncritical changes can be
applied through the API; everything that could lock the administrator out
(firewall input chain, IP services, users) is only emitted as a script.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any, Callable, Iterable, Optional

from .mikrotik import MikroTik, MikroTikError

TAG = "servermanager"

# menus read for the analysis (REST paths)
SNAPSHOT_MENUS = [
    "system/resource", "system/identity", "system/routerboard", "system/ntp/client",
    "interface", "interface/bridge", "interface/bridge/port", "interface/list", "interface/list/member",
    "interface/wireguard", "interface/wireguard/peers", "interface/vlan",
    "ip/address", "ip/route", "ip/pool", "ip/dhcp-client",
    "ip/dhcp-server", "ip/dhcp-server/network", "ip/dhcp-server/lease",
    "ip/dns", "ip/dns/static",
    "ip/firewall/filter", "ip/firewall/nat", "ip/firewall/mangle", "ip/firewall/address-list",
    "ip/firewall/service-port", "routing/table", "routing/rule",
    "ip/service", "ip/neighbor/discovery-settings", "tool/mac-server", "tool/mac-server/mac-winbox",
    "user", "user/group",
]
SINGLETONS = {"system/resource", "system/identity", "system/routerboard", "system/ntp/client", "ip/dns",
              "ip/neighbor/discovery-settings", "tool/mac-server", "tool/mac-server/mac-winbox"}

DEFAULT_SERVICES = [  # RouterOS 7 defaults (a plain export only lists changes)
    {"name": "telnet", "port": "23", "disabled": "false", "address": ""},
    {"name": "ftp", "port": "21", "disabled": "false", "address": ""},
    {"name": "www", "port": "80", "disabled": "false", "address": ""},
    {"name": "ssh", "port": "22", "disabled": "false", "address": ""},
    {"name": "www-ssl", "port": "443", "disabled": "true", "address": ""},
    {"name": "api", "port": "8728", "disabled": "false", "address": ""},
    {"name": "winbox", "port": "8291", "disabled": "false", "address": ""},
    {"name": "api-ssl", "port": "8729", "disabled": "false", "address": ""},
]

PRIVATE_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"]


class RouterOSError(Exception):
    pass


# ==========================================================================
# helpers
# ==========================================================================
def yes(value: Any, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    return str(value).lower() in ("true", "yes")


def items(snap: dict, menu: str) -> list[dict]:
    return list((snap.get("menus") or {}).get(menu) or [])


def single(snap: dict, menu: str) -> dict:
    lst = items(snap, menu)
    return lst[0] if lst else {}


def enabled(item: dict) -> bool:
    return not yes(item.get("disabled")) and not yes(item.get("invalid"))


def ours(item: dict) -> bool:
    return str(item.get("comment", "")).startswith(TAG)


def net_of(value: str) -> Optional[ipaddress.IPv4Network]:
    try:
        return ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return None


def iface_of(value: str) -> Optional[ipaddress.IPv4Interface]:
    try:
        return ipaddress.ip_interface(str(value).strip())
    except ValueError:
        return None


def is_public(ip: Any) -> bool:
    try:
        a = ipaddress.ip_address(str(ip).split("/")[0])
    except ValueError:
        return False
    return a.is_global


def split_list(value: str) -> list[str]:
    return [v.strip() for v in re.split(r"[,\s]+", value or "") if v.strip()]


def version_tuple(version: str) -> tuple[int, ...]:
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", version or "")
    return tuple(int(x or 0) for x in m.groups()) if m else (0,)


def quote_cli(value: Any) -> str:
    s = str(value)
    if s and re.match(r"^[A-Za-z0-9_./:,!*+@-]+$", s):
        return s
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$") + '"'


def interface_lists_of(snap: dict, iface: str) -> set[str]:
    lists = {m.get("list") for m in items(snap, "interface/list/member")
             if m.get("interface") == iface and enabled(m)}
    lists.add("all")
    return {x for x in lists if x}


def rule_matches_iface(rule: dict, key: str, iface: str, snap: dict) -> bool:
    """rule's in-/out-interface(-list) matches iface (positive match only)."""
    direct = rule.get(f"{key}-interface", "")
    if direct:
        return direct == iface
    lst = rule.get(f"{key}-interface-list", "")
    if lst:
        return not lst.startswith("!") and lst in interface_lists_of(snap, iface)
    return False


# ==========================================================================
# import
# ==========================================================================
def snapshot_from_api(mt: MikroTik, progress: Optional[Callable[[str], None]] = None) -> dict:
    menus: dict[str, list[dict]] = {}
    errors: dict[str, str] = {}
    for menu in SNAPSHOT_MENUS:
        try:
            res = mt._req("GET", menu)
            menus[menu] = [res] if isinstance(res, dict) else list(res or [])
        except MikroTikError as exc:
            if "401" in str(exc) or "Anmeldung" in str(exc) or "nicht erreichbar" in str(exc):
                raise
            errors[menu] = str(exc)
        if progress:
            progress(menu)
    return {"source": "api", "menus": menus, "errors": errors,
            "version": (menus.get("system/resource") or [{}])[0].get("version", ""),
            "taken_at": datetime.now().isoformat(timespec="seconds")}


_CMD_WORDS = {"add", "set", "remove", "enable", "disable", "print", "export"}
_SECTION_RE = re.compile(r"^/([a-z0-9-]+(?: [a-z0-9-]+)*)(?:\s+(.*))?$")


def _tokens(line: str) -> list[str]:
    """Split a RouterOS CLI line into tokens (quotes, escapes and [ find ... ] kept together)."""
    out: list[str] = []
    buf = ""
    i, n = 0, len(line)
    in_q = False
    depth = 0
    while i < n:
        c = line[i]
        if in_q:
            if c == "\\" and i + 1 < n:
                nxt = line[i + 1]
                buf += {"n": "\n", "t": "\t", "r": "\r"}.get(nxt, nxt)
                i += 2
                continue
            if c == '"':
                in_q = False
            else:
                buf += c
        elif c == '"':
            in_q = True
        elif c == "[":
            depth += 1
            buf += c
        elif c == "]":
            depth -= 1
            buf += c
        elif c.isspace() and depth == 0:
            if buf:
                out.append(buf)
                buf = ""
        else:
            buf += c
        i += 1
    if buf:
        out.append(buf)
    return out


def _kv(tokens: Iterable[str]) -> tuple[dict, list[str]]:
    data: dict[str, str] = {}
    rest: list[str] = []
    for t in tokens:
        if "=" in t and not t.startswith("["):
            k, v = t.split("=", 1)
            data[k] = v
        else:
            rest.append(t)
    return data, rest


def _find_filter(expr: str) -> dict:
    """[ find default-name=ether1 ] -> {"default-name": "ether1"}"""
    inner = expr.strip()[1:-1].strip()
    if inner.startswith("find"):
        inner = inner[4:]
    data, _ = _kv(_tokens(inner))
    return data


def parse_export(text: str) -> dict:
    """Parse the output of ``/export`` (compact or terse) into the snapshot format."""
    menus: dict[str, list[dict]] = {}
    version = ""
    lines: list[str] = []
    cur = ""
    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if line.startswith("#"):
            m = re.search(r"RouterOS (\d+\.\d+(?:\.\d+)?)", line)
            if m and not version:
                version = m.group(1)
            continue
        if cur:
            line = cur + line.lstrip()
            cur = ""
        if line.endswith("\\"):
            cur = line[:-1]
            continue
        if line.strip():
            lines.append(line.strip())
    if cur.strip():
        lines.append(cur.strip())

    section = ""
    for line in lines:
        if line.startswith("/"):
            m = _SECTION_RE.match(line)
            if not m:
                continue
            words = m.group(1).split(" ")
            path: list[str] = []
            cmd_rest = m.group(2) or ""
            for idx, w in enumerate(words):
                if w in _CMD_WORDS:
                    cmd_rest = " ".join(words[idx:]) + (" " + cmd_rest if cmd_rest else "")
                    break
                path.append(w)
            section = "/".join(path)
            line = cmd_rest.strip()
            if not line:
                continue
        toks = _tokens(line)
        if not toks or not section:
            continue
        cmd, args = toks[0], toks[1:]
        lst = menus.setdefault(section, [])
        if cmd == "add":
            data, _ = _kv(args)
            lst.append(data)
        elif cmd == "set":
            data, rest = _kv(args)
            target: Optional[dict] = None
            if rest and rest[0].startswith("["):
                flt = _find_filter(rest[0])
                for it in lst:
                    if all(it.get(k) == v for k, v in flt.items()):
                        target = it
                        break
                if target is None:
                    target = dict(flt)
                    lst.append(target)
            elif rest:
                name = rest[0]
                for it in lst:
                    if it.get("name") == name or it.get("numbers") == name:
                        target = it
                        break
                if target is None:
                    target = {"name": name}
                    lst.append(target)
            else:
                if not lst:
                    lst.append({})
                target = lst[0]
            target.update(data)

    # RouterOS only exports changes from the defaults - fill in the relevant defaults
    services = {s["name"]: dict(s) for s in DEFAULT_SERVICES}
    for s in menus.get("ip/service", []):
        if s.get("name") in services:
            services[s["name"]].update(s)
    menus["ip/service"] = list(services.values())
    for it in menus.get("ip/firewall/filter", []) + menus.get("ip/firewall/nat", []) + \
            menus.get("ip/firewall/mangle", []):
        it.setdefault("disabled", "no")
    # synthesized interface list: all typed interface menus + interfaces referenced elsewhere
    ifaces: dict[str, dict] = {}
    for menu, lst in menus.items():
        if menu.startswith("interface/") and menu.count("/") == 1 and menu not in ("interface/list",):
            itype = {"ethernet": "ether", "wireguard": "wg"}.get(menu.split("/")[1], menu.split("/")[1])
            for it in lst:
                name = it.get("name") or it.get("default-name")
                if name:
                    ifaces[name] = {"name": name, "type": itype, "disabled": it.get("disabled", "no")}
    for menu in ("ip/address", "ip/dhcp-client", "ip/dhcp-server", "interface/bridge/port",
                 "interface/list/member"):
        for it in menus.get(menu, []):
            name = it.get("interface")
            if name and name not in ifaces:
                ifaces[name] = {"name": name, "type": "ether" if name.startswith("ether") else "",
                                "disabled": "no"}
    menus["interface"] = list(ifaces.values())
    if version:
        menus.setdefault("system/resource", [{}])[0].setdefault("version", version)
    return {"source": "export", "menus": menus, "errors": {}, "version": version,
            "taken_at": datetime.now().isoformat(timespec="seconds")}


# ==========================================================================
# target detection
# ==========================================================================
def default_route(snap: dict) -> Optional[dict]:
    for r in items(snap, "ip/route"):
        if r.get("dst-address") == "0.0.0.0/0" and r.get("routing-table", "main") in ("main", "") \
                and enabled(r) and not yes(r.get("blackhole")):
            return r
    return None


def wan_gateway(snap: dict) -> str:
    r = default_route(snap)
    if r:
        gw = str(r.get("gateway", "")).split("%")[0]
        if gw and re.match(r"^\d+\.\d+\.\d+\.\d+$", gw):
            return gw
    for c in items(snap, "ip/dhcp-client"):
        if c.get("gateway"):
            return c["gateway"]
    return ""


def detect_target(snap: dict, mgmt_default: str = "") -> dict:
    addrs = [a for a in items(snap, "ip/address") if enabled(a)]
    wan = ""
    r = default_route(snap)
    if r:
        imm = str(r.get("immediate-gw", "") or r.get("gateway", ""))
        if "%" in imm:
            wan = imm.split("%", 1)[1]
        else:
            gw = imm.split(",")[0]
            for a in addrs:
                i = iface_of(a.get("address", ""))
                if i and gw and _in_net(gw, i.network):
                    wan = a.get("interface", "")
                    break
    if not wan:
        for c in items(snap, "ip/dhcp-client"):
            if enabled(c):
                wan = c.get("interface", "")
                break
    if not wan:
        for a in addrs:
            if is_public(a.get("address", "")):
                wan = a.get("interface", "")
                break
    bridges = {b.get("name") for b in items(snap, "interface/bridge")}
    lan, lan_addr = "", ""
    for prefer_bridge in (True, False):
        for a in addrs:
            ifc = a.get("interface", "")
            i = iface_of(a.get("address", ""))
            if not i or ifc == wan or is_public(i.ip) or yes(a.get("dynamic")):
                continue
            if prefer_bridge and ifc not in bridges:
                continue
            if any(w.get("name") == ifc for w in items(snap, "interface/wireguard")):
                continue
            lan, lan_addr = ifc, str(i)
            break
        if lan:
            break
    if not lan:
        lan, lan_addr = "bridge-lan", "10.20.0.1/24"
    lan_if = iface_of(lan_addr)
    net = lan_if.network if lan_if else ipaddress.ip_network("10.20.0.0/24")
    hosts = list(net.hosts())
    rng = f"{hosts[min(99, len(hosts) - 1)]}-{hosts[min(198, len(hosts) - 1)]}" if len(hosts) > 2 else ""
    for srv in items(snap, "ip/dhcp-server"):
        if srv.get("interface") == lan:
            for p in items(snap, "ip/pool"):
                if p.get("name") == srv.get("address-pool") and p.get("ranges"):
                    rng = p["ranges"]
    dns = single(snap, "ip/dns").get("servers", "") or "1.1.1.1,9.9.9.9"
    wg = [w.get("name") for w in items(snap, "interface/wireguard")]
    tables = [t for t in items(snap, "routing/table") if t.get("name") not in ("main", "")]
    return {
        "wan_interface": wan or "ether1",
        "lan_interface": lan,
        "lan_address": lan_addr,
        "dhcp_range": rng,
        "dns_servers": dns,
        "policy_routing": bool(wg or tables),
        "routing_table": "sm-inet",
        "mss_clamp": bool(wg),
        "mgmt_addresses": mgmt_default,
        "ntp_servers": "pool.ntp.org",
    }


def _in_net(ip: str, net) -> bool:
    try:
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


def validate_target(t: dict) -> tuple[dict, list[str]]:
    errors: list[str] = []
    out = dict(t)
    for key in ("wan_interface", "lan_interface"):
        if not re.match(r"^[A-Za-z0-9._<>-]{1,64}$", out.get(key, "")):
            errors.append(f"Ungültiger Interface-Name: {key}")
    i = iface_of(out.get("lan_address", ""))
    if not i or i.version != 4 or i.network.prefixlen > 30 or i.ip == i.network.network_address:
        errors.append("LAN-Adresse muss eine IPv4-Adresse mit Präfix sein, z. B. 10.20.0.1/24")
    rng = out.get("dhcp_range", "")
    m = re.match(r"^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$", rng)
    if not m or (i and not all(_in_net(x, i.network) for x in m.groups())):
        errors.append("DHCP-Bereich muss im LAN liegen, z. B. 10.20.0.100-10.20.0.199")
    for d in split_list(out.get("dns_servers", "")):
        if not _valid_ip(d):
            errors.append(f"Ungültiger DNS-Server {d}")
    for a in split_list(out.get("mgmt_addresses", "")):
        if not net_of(a):
            errors.append(f"Ungültige Management-Adresse {a}")
    if not re.match(r"^[A-Za-z0-9_-]{1,32}$", out.get("routing_table", "") or ""):
        errors.append("Ungültiger Name der Routing-Tabelle")
    out["policy_routing"] = yes(out.get("policy_routing"))
    out["mss_clamp"] = yes(out.get("mss_clamp"))
    return out, errors


def _valid_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


# ==========================================================================
# analysis
# ==========================================================================
OK, CHANGE, MISSING, CHECK = "ok", "change", "missing", "check"
STATUS_LABELS = {OK: "Bleibt so", CHANGE: "Anpassen", MISSING: "Fehlt", CHECK: "Prüfen / Hinweis"}
AREAS = {
    "system": "System", "wan": "WAN & Routing", "lan": "LAN & DHCP", "dns": "DNS",
    "nat": "Internetzugang (NAT)", "policy": "Policy-Routing (Mangle)", "firewall": "Firewall",
    "services": "Dienste & Zugang", "tunnel": "Tunnel (WireGuard / Newt)",
}


def finding(fid: str, area: str, status: str, title: str, detail: str = "", severity: str = "",
            current: str = "", ops: Optional[list] = None, script: Optional[list] = None) -> dict:
    sev = severity or {OK: "ok", CHANGE: "warn", MISSING: "warn", CHECK: "info"}[status]
    ops = ops or []
    script = list(script or []) or [op_to_cli(o) for o in ops]
    return {"id": fid, "area": area, "status": status, "severity": sev, "title": title, "detail": detail,
            "current": current, "ops": ops, "script": script, "applicable": bool(ops)}


def op_add(path: str, data: dict) -> dict:
    return {"m": "add", "path": path, "data": data}


def op_set(path: str, data: dict, item_id: str = "", find: str = "") -> dict:
    """item_id empty: singleton menu (POST <path>/set)."""
    return {"m": "set", "path": path, "id": item_id, "find": find, "data": data}


def direct_op_allowed(op: dict) -> bool:
    """Operations a confirmed optimization may send without a full analysis: additions of addresses, NAT rules
    and address-list entries, and switching off the SIP helper."""
    if op.get("m") == "add":
        return op.get("path") in ("ip/address", "ip/firewall/nat", "ip/firewall/address-list")
    return (op.get("m") == "set" and op.get("path") == "ip/firewall/service-port" and bool(op.get("id"))
            and op.get("data") == {"disabled": "yes"})


def op_to_cli(op: dict) -> str:
    path = "/" + op["path"].replace("/", " ")
    args = " ".join(f"{k}={quote_cli(v)}" for k, v in op["data"].items())
    if op["m"] == "add":
        return f"{path} add {args}"
    if op.get("id") or op.get("find"):
        return f"{path} set [ find {op.get('find') or ''} ] {args}"
    return f"{path} set {args}"


def analyze(snap: dict, target: dict) -> list[dict]:
    t = target
    out: list[dict] = []
    add = out.append
    wan, lan = t["wan_interface"], t["lan_interface"]
    lan_if = iface_of(t["lan_address"])
    lan_net = str(lan_if.network) if lan_if else ""
    router_ip = str(lan_if.ip) if lan_if else ""
    iface_names = {i.get("name") for i in items(snap, "interface")}
    tag = f"{TAG}: "

    # ---------------------------------------------------------------- system
    ver = single(snap, "system/resource").get("version", "") or snap.get("version", "")
    vt = version_tuple(ver)
    if vt[0] >= 7:
        add(finding("sys.version", "system", OK, f"RouterOS {ver}", "RouterOS 7 – REST-API verfügbar."))
    elif ver:
        add(finding("sys.version", "system", CHANGE, f"RouterOS {ver} ist zu alt",
                    "Für die REST-API wird RouterOS 7.1 oder neuer benötigt. Update über "
                    "/system package update.", severity="crit"))
    ident = single(snap, "system/identity").get("name", "")
    if ident and ident != "MikroTik":
        add(finding("sys.identity", "system", OK, f"Identität „{ident}“"))
    elif ident:
        add(finding("sys.identity", "system", CHECK, "Identität ist noch „MikroTik“",
                    "Eindeutigen Namen vergeben (erleichtert Protokolle und Überwachung).",
                    script=['/system identity set name="chr-…"']))
    ntp = single(snap, "system/ntp/client")
    if ntp and yes(ntp.get("enabled")):
        add(finding("sys.ntp", "system", OK, "NTP-Client aktiv", current=ntp.get("servers", "")))
    elif "system/ntp/client" in (snap.get("menus") or {}) or snap.get("source") == "export":
        add(finding("sys.ntp", "system", CHANGE, "NTP-Client nicht aktiv",
                    "Korrekte Zeit ist Voraussetzung für TLS, Protokolle und Leases.",
                    ops=[op_set("system/ntp/client", {"enabled": "yes", "servers": t.get("ntp_servers") or
                                                      "pool.ntp.org"})]))

    # ---------------------------------------------------------------- WAN
    wan_addrs = [a for a in items(snap, "ip/address") if a.get("interface") == wan and enabled(a)]
    wan_dhcp = [c for c in items(snap, "ip/dhcp-client") if c.get("interface") == wan and enabled(c)]
    if wan not in iface_names and wan_addrs == [] and not wan_dhcp:
        add(finding("wan.iface", "wan", MISSING, f"WAN-Interface {wan} nicht gefunden",
                    "Bitte in den Sollwerten das Interface mit der öffentlichen IP angeben.", severity="crit"))
    else:
        pub = [a.get("address") for a in wan_addrs if is_public(a.get("address"))]
        cur = ", ".join(a.get("address", "") for a in wan_addrs) or ("DHCP-Client" if wan_dhcp else "")
        if pub or wan_dhcp:
            add(finding("wan.iface", "wan", OK, f"WAN-Interface {wan}", current=cur))
        else:
            add(finding("wan.iface", "wan", CHECK, f"WAN-Interface {wan} ohne öffentliche Adresse",
                        "Liegt der Router hinter einem weiteren NAT, sind eingehende Verbindungen (z. B. "
                        "WireGuard) nur über dessen Portweiterleitung möglich.", current=cur))
    dr = default_route(snap)
    dhcp_default = any(yes(c.get("add-default-route"), True) for c in wan_dhcp)
    if dr:
        add(finding("wan.default", "wan", OK, "Default-Route vorhanden",
                    current=f"0.0.0.0/0 via {dr.get('gateway', '')}"))
    elif dhcp_default:
        add(finding("wan.default", "wan", OK, "Default-Route über DHCP-Client", current=wan))
    else:
        add(finding("wan.default", "wan", MISSING, "Keine Default-Route",
                    "Ohne Default-Route haben weder Router noch Dienste Internetzugang.", severity="crit",
                    script=["/ip route add dst-address=0.0.0.0/0 gateway=<GATEWAY-IP> comment=\"servermanager: "
                            "default\""]))

    # ---------------------------------------------------------------- LAN
    bridges = {b.get("name") for b in items(snap, "interface/bridge")}
    if lan in iface_names or lan in bridges:
        ports = [p.get("interface") for p in items(snap, "interface/bridge/port") if p.get("bridge") == lan]
        add(finding("lan.iface", "lan", OK, f"LAN-Interface {lan}",
                    current=("Ports: " + ", ".join(ports)) if ports else ""))
    else:
        add(finding("lan.iface", "lan", MISSING, f"LAN-Bridge {lan} fehlt",
                    "Die Bridge wird angelegt; die internen Ports (z. B. das Interface zum Proxmox-Host) "
                    "müssen anschließend zugeordnet werden.",
                    ops=[op_add("interface/bridge", {"name": lan, "comment": tag + "LAN"})],
                    script=[f"/interface bridge add name={lan} comment=\"{tag}LAN\"",
                            f"/interface bridge port add bridge={lan} interface=<PORT>"]))
    lan_addrs = [a for a in items(snap, "ip/address") if a.get("interface") == lan and enabled(a)]
    have = [a for a in lan_addrs if iface_of(a.get("address", "")) == lan_if]
    if have:
        add(finding("lan.address", "lan", OK, f"LAN-Adresse {t['lan_address']}"))
    elif lan_addrs:
        add(finding("lan.address", "lan", CHECK, "LAN hat eine andere Adresse",
                    "Die vorhandene Adresse bleibt – bitte die Sollwerte an das bestehende Netz anpassen oder "
                    "bewusst umstellen.", current=", ".join(a.get("address", "") for a in lan_addrs)))
    else:
        add(finding("lan.address", "lan", MISSING, f"LAN-Adresse {t['lan_address']} fehlt",
                    ops=[op_add("ip/address", {"address": t["lan_address"], "interface": lan,
                                               "comment": tag + "LAN"})]))

    # DHCP pool + server + network
    rng = t["dhcp_range"]
    pool = next((p for p in items(snap, "ip/pool") if p.get("ranges") == rng), None)
    srv = next((s for s in items(snap, "ip/dhcp-server") if s.get("interface") == lan), None)
    if srv:
        srv_pool = next((p for p in items(snap, "ip/pool") if p.get("name") == srv.get("address-pool")), None)
        pool = pool or srv_pool
    pool_name = pool.get("name") if pool else "sm-lan-pool"
    if pool:
        add(finding("lan.pool", "lan", OK, f"Adress-Pool {pool_name}", current=pool.get("ranges", "")))
    else:
        add(finding("lan.pool", "lan", MISSING, f"Adress-Pool für {rng} fehlt",
                    ops=[op_add("ip/pool", {"name": pool_name, "ranges": rng, "comment": tag + "LAN"})]))
    if srv and enabled(srv):
        add(finding("lan.dhcp", "lan", OK, f"DHCP-Server {srv.get('name')} auf {lan}",
                    current=f"Pool {srv.get('address-pool', '')}, Lease-Zeit {srv.get('lease-time', '')}"))
    elif srv:
        add(finding("lan.dhcp", "lan", CHANGE, f"DHCP-Server {srv.get('name')} ist deaktiviert",
                    ops=[op_set("ip/dhcp-server", {"disabled": "no"}, srv.get(".id", ""),
                                f"name={quote_cli(srv.get('name'))}")]))
    else:
        add(finding("lan.dhcp", "lan", MISSING, f"Kein DHCP-Server auf {lan}",
                    "Die Dienste (z. B. der Newt-LXC) erhalten ihre Adresse per DHCP.",
                    ops=[op_add("ip/dhcp-server", {"name": "sm-dhcp-lan", "interface": lan,
                                                    "address-pool": pool_name, "lease-time": "1d",
                                                    "comment": tag + "LAN"})]))
    dnet = next((n for n in items(snap, "ip/dhcp-server/network") if net_of(n.get("address", "")) and
                 lan_if and net_of(n.get("address", "")) == lan_if.network), None)
    dns_for_clients = router_ip
    if dnet:
        problems = {}
        if dnet.get("gateway") != router_ip:
            problems["gateway"] = router_ip
        if not dnet.get("dns-server"):
            problems["dns-server"] = dns_for_clients
        else:
            dns_for_clients = dnet.get("dns-server")
        if problems:
            add(finding("lan.network", "lan", CHANGE, "DHCP-Netz unvollständig",
                        "Ohne Gateway/DNS in der DHCP-Antwort kommen die Dienste nicht ins Internet.",
                        current=f"Gateway {dnet.get('gateway') or '–'}, DNS {dnet.get('dns-server') or '–'}",
                        ops=[op_set("ip/dhcp-server/network", problems, dnet.get(".id", ""),
                                    f"address={quote_cli(dnet.get('address'))}")]))
        else:
            add(finding("lan.network", "lan", OK, f"DHCP-Netz {dnet.get('address')}",
                        current=f"Gateway {dnet.get('gateway')}, DNS {dnet.get('dns-server')}"))
    else:
        add(finding("lan.network", "lan", MISSING, f"DHCP-Netz {lan_net} fehlt",
                    ops=[op_add("ip/dhcp-server/network", {"address": lan_net, "gateway": router_ip,
                                                            "dns-server": router_ip, "comment": tag + "LAN"})]))
    leases = [le for le in items(snap, "ip/dhcp-server/lease") if yes(le.get("dynamic")) and
              lan_if and _in_net(le.get("address", ""), lan_if.network)]
    if leases:
        add(finding("lan.leases", "lan", CHECK, f"{len(leases)} dynamische DHCP-Lease(s)",
                    "Für Server und veröffentlichte Dienste (Newt-LXC, Pangolin-Ziele) die Lease statisch "
                    "machen – sonst kann sich die IP ändern und das Pangolin-Ziel zeigt ins Leere. "
                    "(Reiter DHCP → „Statisch machen“)",
                    current=", ".join(f"{le.get('address')} {le.get('host-name', '')}".strip()
                                      for le in leases[:8])))

    # ---------------------------------------------------------------- DNS
    dns = single(snap, "ip/dns")
    servers = dns.get("servers", "")
    if servers or dns.get("dynamic-servers"):
        add(finding("dns.servers", "dns", OK, "Upstream-DNS gesetzt", current=servers or dns.get("dynamic-servers")))
    else:
        add(finding("dns.servers", "dns", MISSING, "Kein Upstream-DNS-Server",
                    ops=[op_set("ip/dns", {"servers": ",".join(split_list(t["dns_servers"]))})]))
    if dns_for_clients == router_ip:
        if yes(dns.get("allow-remote-requests")):
            add(finding("dns.remote", "dns", OK, "Router beantwortet DNS-Anfragen aus dem LAN"))
        else:
            add(finding("dns.remote", "dns", CHANGE, "DNS-Anfragen der Clients werden nicht beantwortet",
                        "Das DHCP-Netz verteilt den Router als DNS-Server – dafür muss allow-remote-requests "
                        "aktiv sein. Die Firewall muss DNS (Port 53) von außen blockieren (siehe Firewall).",
                        ops=[op_set("ip/dns", {"allow-remote-requests": "yes"})]))

    # ---------------------------------------------------------------- NAT
    nat = [r for r in items(snap, "ip/firewall/nat") if r.get("chain") == "srcnat" and enabled(r)
           and r.get("action") in ("masquerade", "src-nat")]
    covering = []
    broad = []
    for r in nat:
        src = net_of(r.get("src-address", "")) if r.get("src-address") and not str(
            r.get("src-address")).startswith("!") else None
        src_ok = (not r.get("src-address") and not r.get("src-address-list")) or \
                 (src is not None and lan_if is not None and lan_if.network.subnet_of(src))
        if not src_ok:
            continue
        if rule_matches_iface(r, "out", wan, snap):
            covering.append(r)
        elif not r.get("out-interface") and not r.get("out-interface-list"):
            broad.append(r)
    if covering:
        add(finding("nat.masq", "nat", OK, "NAT (masquerade) für das LAN über WAN",
                    current=_rule_text(covering[0])))
    elif broad:
        add(finding("nat.masq", "nat", CHANGE, "Masquerade ohne Ausgangs-Interface",
                    "Die Regel maskiert auch Verkehr in Tunnel und interne Netze (Quell-IPs gehen verloren, "
                    "WireGuard-Management und Protokolle zeigen nur noch die Router-IP). Empfohlen: auf das "
                    "WAN-Interface beschränken.", current=_rule_text(broad[0]),
                    script=[f"/ip firewall nat set [ find where chain=srcnat action={broad[0].get('action')} "
                            f"!out-interface !out-interface-list ] out-interface={wan}"]))
    else:
        add(finding("nat.masq", "nat", MISSING, "Kein NAT für das LAN – Dienste kommen nicht ins Internet",
                    severity="crit",
                    ops=[op_add("ip/firewall/nat", {"chain": "srcnat", "action": "masquerade",
                                                     "src-address": lan_net, "out-interface": wan,
                                                     "comment": tag + "LAN -> Internet"})]))
    dstnat = [r for r in items(snap, "ip/firewall/nat") if r.get("chain") == "dstnat" and enabled(r)]
    if dstnat:
        add(finding("nat.dstnat", "nat", CHECK, f"{len(dstnat)} Portweiterleitung(en) vorhanden",
                    "Können bleiben, wenn sie gebraucht werden. Über Pangolin veröffentlichte Dienste "
                    "benötigen keine Portweiterleitung – nicht mehr benötigte Weiterleitungen entfernen.",
                    current="; ".join(_rule_text(r) for r in dstnat[:5])))

    # ---------------------------------------------------------------- policy routing
    mangle = [r for r in items(snap, "ip/firewall/mangle") if enabled(r)]
    fasttrack = [r for r in items(snap, "ip/firewall/filter") if r.get("action") == "fasttrack-connection"
                 and enabled(r)]
    table = t["routing_table"]
    if t.get("policy_routing"):
        _policy_findings(snap, t, add, mangle, fasttrack, table, wan, lan_net, tag)
    else:
        foreign = [r for r in mangle if r.get("action") in ("mark-routing", "mark-connection") and not ours(r)]
        if foreign:
            add(finding("pol.foreign", "policy", CHECK, f"{len(foreign)} vorhandene Mangle-Markierung(en)",
                        "Bleiben unverändert. Prüfen, ob sie den LAN-Verkehr in eine andere Routing-Tabelle "
                        "lenken.", current="; ".join(_rule_text(r) for r in foreign[:5])))
        add(finding("pol.off", "policy", OK, "Policy-Routing nicht vorgesehen",
                    "Einfaches Routing über die Default-Route genügt, solange kein Tunnel eine "
                    "Default-Route (0.0.0.0/0) übernimmt."))
    if t.get("mss_clamp"):
        tunnels = [w.get("name") for w in items(snap, "interface/wireguard")]
        for tun in tunnels:
            have_mss = any(r.get("action") == "change-mss" and (r.get("out-interface") == tun or not
                           r.get("out-interface")) for r in mangle)
            if have_mss:
                add(finding(f"pol.mss.{tun}", "policy", OK, f"MSS-Clamping für {tun}"))
            else:
                add(finding(f"pol.mss.{tun}", "policy", MISSING, f"MSS-Clamping für {tun} fehlt",
                            "Verhindert hängende TCP-Verbindungen durch die kleinere MTU im Tunnel.",
                            ops=[op_add("ip/firewall/mangle", {
                                "chain": "forward", "action": "change-mss", "protocol": "tcp",
                                "tcp-flags": "syn", "out-interface": tun, "new-mss": "clamp-to-pmtu",
                                "passthrough": "yes", "comment": tag + f"MSS {tun}"})]))

    # ---------------------------------------------------------------- firewall (script only)
    _firewall_findings(snap, t, add, wan, lan, lan_net)

    # ---------------------------------------------------------------- services (script only)
    _service_findings(snap, t, add, wan)

    # ---------------------------------------------------------------- tunnels
    for w in items(snap, "interface/wireguard"):
        peers = [p for p in items(snap, "interface/wireguard/peers") if p.get("interface") == w.get("name")]
        wide = [p for p in peers if "0.0.0.0/0" in str(p.get("allowed-address", ""))]
        add(finding(f"tun.wg.{w.get('name')}", "tunnel", CHECK if wide else OK,
                    f"WireGuard {w.get('name')} ({len(peers)} Peer(s), Port {w.get('listen-port', '')})",
                    "Ein Peer mit AllowedIPs 0.0.0.0/0 kann Verkehr ins Internet an sich ziehen – dann "
                    "Policy-Routing aktivieren." if wide else ""))
    add(finding("tun.newt", "tunnel", CHECK, "Newt/Pangolin braucht nur ausgehende Verbindungen",
                "Der Newt-Client im LXC baut den Tunnel zum Pangolin-Server selbst auf (HTTPS/WebSocket und "
                "UDP 51820 ausgehend). Voraussetzung: NAT (siehe oben) und keine Forward-Regel, die "
                "ausgehenden Verkehr aus dem LAN blockiert. Die Newt-IP sollte eine statische Lease haben."))
    return out


def _rule_text(r: dict) -> str:
    keys = ["chain", "action", "src-address", "dst-address", "protocol", "dst-port", "in-interface",
            "in-interface-list", "out-interface", "out-interface-list", "connection-mark", "new-connection-mark",
            "new-routing-mark", "to-addresses", "to-ports", "comment"]
    return " ".join(f"{k}={r[k]}" for k in keys if r.get(k))


def _policy_findings(snap, t, add, mangle, fasttrack, table, wan, lan_net, tag) -> None:
    tables = {x.get("name"): x for x in items(snap, "routing/table")}
    if table in tables:
        add(finding("pol.table", "policy", OK, f"Routing-Tabelle {table}"))
    else:
        add(finding("pol.table", "policy", MISSING, f"Routing-Tabelle {table} fehlt",
                    ops=[op_add("routing/table", {"name": table, "fib": "", "comment": tag + "Internet"})],
                    script=[f"/routing table add name={table} fib comment=\"{tag}Internet\""]))
    have_route = any(r.get("dst-address") == "0.0.0.0/0" and r.get("routing-table") == table and enabled(r)
                     for r in items(snap, "ip/route"))
    gw = wan_gateway(snap)
    if have_route:
        add(finding("pol.route", "policy", OK, f"Default-Route in Tabelle {table}"))
    elif gw:
        add(finding("pol.route", "policy", MISSING, f"Default-Route in Tabelle {table} fehlt",
                    ops=[op_add("ip/route", {"dst-address": "0.0.0.0/0", "gateway": gw, "routing-table": table,
                                             "comment": tag + "Internet"})]))
    else:
        add(finding("pol.route", "policy", MISSING, f"Default-Route in Tabelle {table} fehlt",
                    "Gateway nicht ermittelbar (DHCP auf WAN?) – bitte Gateway-IP einsetzen. Bei DHCP kann "
                    "im DHCP-Client ein Skript die Route nachführen.",
                    script=[f"/ip route add dst-address=0.0.0.0/0 gateway=<GATEWAY-IP> routing-table={table} "
                            f"comment=\"{tag}Internet\""]))
    lists = items(snap, "ip/firewall/address-list")
    local_have = {x.get("address") for x in lists if x.get("list") == "sm-local-nets"}
    want = [n for n in dict.fromkeys([lan_net] + PRIVATE_NETS) if n]
    missing_nets = [n for n in want if n not in local_have]
    if missing_nets:
        add(finding("pol.local", "policy", MISSING, "Adressliste sm-local-nets unvollständig",
                    "Interne Ziele werden von der Markierung ausgenommen.",
                    ops=[op_add("ip/firewall/address-list", {"list": "sm-local-nets", "address": n,
                                                              "comment": tag + "lokale Netze"})
                         for n in missing_nets]))
    else:
        add(finding("pol.local", "policy", OK, "Adressliste sm-local-nets"))
    conn_mark = f"{table}-conn"

    def has(pred) -> bool:
        return any(pred(r) for r in mangle)

    rules = [
        ("pol.m1", "Verbindungen aus dem LAN ins Internet markieren",
         lambda r: r.get("action") == "mark-connection" and r.get("new-connection-mark") == conn_mark
         and r.get("src-address") == lan_net,
         {"chain": "prerouting", "action": "mark-connection", "src-address": lan_net,
          "dst-address-list": "!sm-local-nets", "connection-state": "new", "new-connection-mark": conn_mark,
          "passthrough": "yes", "comment": tag + "LAN -> Internet (Verbindung)"}),
        ("pol.m2", "Antworten auf eingehende WAN-Verbindungen markieren",
         lambda r: r.get("action") == "mark-connection" and r.get("new-connection-mark") == conn_mark
         and r.get("in-interface") == wan,
         {"chain": "prerouting", "action": "mark-connection", "in-interface": wan, "connection-state": "new",
          "new-connection-mark": conn_mark, "passthrough": "yes", "comment": tag + "WAN eingehend (Verbindung)"}),
        ("pol.m3", f"Routing-Markierung {table} für markierte Verbindungen aus dem LAN",
         lambda r: r.get("action") == "mark-routing" and r.get("new-routing-mark") == table,
         {"chain": "prerouting", "action": "mark-routing", "connection-mark": conn_mark, "src-address": lan_net,
          "dst-address-list": "!sm-local-nets", "new-routing-mark": table, "passthrough": "no",
          "comment": tag + "LAN -> Internet (Routing)"}),
    ]
    for fid, title, pred, data in rules:
        if has(pred):
            add(finding(fid, "policy", OK, title))
        else:
            add(finding(fid, "policy", MISSING, title, ops=[op_add("ip/firewall/mangle", data)]))
    foreign = [r for r in mangle if r.get("action") == "mark-routing" and not ours(r)
               and r.get("new-routing-mark") != table]
    if foreign:
        add(finding("pol.foreign", "policy", CHECK, f"{len(foreign)} weitere Routing-Markierung(en)",
                    "Bleiben bestehen. Überschneiden sie sich mit dem LAN, gewinnt die zuerst passende Regel "
                    "(Reihenfolge prüfen).", current="; ".join(_rule_text(r) for r in foreign[:5])))
    ft = [r for r in fasttrack if r.get("connection-mark") != "no-mark"]
    if ft:
        add(finding("pol.fasttrack", "policy", CHANGE, "FastTrack umgeht die Mangle-Markierungen",
                    "Per FastTrack beschleunigte Verbindungen durchlaufen Mangle nicht mehr – markierte "
                    "Verbindungen würden falsch geroutet. Die FastTrack-Regel auf unmarkierte Verbindungen "
                    "beschränken (Firewall-Regel – nur als Skript).", current=_rule_text(ft[0]),
                    script=["/ip firewall filter set [ find where action=fasttrack-connection ] "
                            "connection-mark=no-mark"]))


def _firewall_findings(snap, t, add, wan, lan, lan_net) -> None:
    rules = [r for r in items(snap, "ip/firewall/filter") if enabled(r)]
    inp = [r for r in rules if r.get("chain") == "input"]
    fwd = [r for r in rules if r.get("chain") == "forward"]
    est = any(r.get("action") == "accept" and "established" in str(r.get("connection-state", ""))
              for r in inp)
    invalid = any(r.get("action") == "drop" and "invalid" in str(r.get("connection-state", "")) for r in inp)
    wan_drop = any(r.get("action") in ("drop", "reject") and not r.get("protocol") and not r.get("dst-port")
                   and not r.get("src-address") and not r.get("connection-state") and
                   (rule_matches_iface(r, "in", wan, snap) or
                    str(r.get("in-interface-list", "")).startswith("!") or
                    (not r.get("in-interface") and not r.get("in-interface-list")))
                   for r in inp)
    mgmt = split_list(t.get("mgmt_addresses", ""))
    if est and invalid and wan_drop:
        add(finding("fw.input", "firewall", OK, "Input-Kette schützt den Router",
                    "Established/related erlaubt, invalid verworfen, Rest von WAN verworfen."))
    else:
        missing = [x for x, ok in (("established/related erlauben", est), ("invalid verwerfen", invalid),
                                   ("Rest von WAN verwerfen", wan_drop)) if not ok]
        wg_ports = [w.get("listen-port") for w in items(snap, "interface/wireguard") if w.get("listen-port")]
        script = [
            "/ip firewall address-list add list=sm-mgmt address=" + (mgmt[0] if mgmt else "<ADMIN-IP>")
            + " comment=\"servermanager: Management\"",
            *[f"/ip firewall address-list add list=sm-mgmt address={m} comment=\"servermanager: Management\""
              for m in mgmt[1:]],
            "/ip firewall filter",
            "add chain=input action=accept connection-state=established,related,untracked "
            "comment=\"servermanager: established\"",
            "add chain=input action=drop connection-state=invalid comment=\"servermanager: invalid\"",
            "add chain=input action=accept protocol=icmp comment=\"servermanager: icmp\"",
            *[f"add chain=input action=accept protocol=udp dst-port={p} comment=\"servermanager: WireGuard\""
              for p in wg_ports],
            "add chain=input action=accept src-address-list=sm-mgmt comment=\"servermanager: Management\"",
            f"add chain=input action=accept in-interface={lan} comment=\"servermanager: LAN\"",
            f"add chain=input action=drop in-interface={wan} comment=\"servermanager: drop WAN\"",
        ]
        add(finding("fw.input", "firewall", MISSING if not inp else CHANGE,
                    "Input-Kette unvollständig – Router von außen angreifbar",
                    "Fehlt: " + ", ".join(missing) + ". Nur als Skript: vor dem Einspielen prüfen, dass die eigene "
                    "Management-Adresse in sm-mgmt steht (sonst Aussperrung!) und die Regeln vor vorhandenen "
                    "drop-Regeln stehen (place-before).", severity="crit", script=script))
    fwd_est = any(r.get("action") in ("accept", "fasttrack-connection") and "established" in
                  str(r.get("connection-state", "")) for r in fwd)
    fwd_wan = any(r.get("action") == "drop" and rule_matches_iface(r, "in", wan, snap) and
                  "dstnat" in str(r.get("connection-nat-state", "")) for r in fwd)
    if fwd_est and fwd_wan:
        add(finding("fw.forward", "firewall", OK, "Forward-Kette schützt das LAN"))
    else:
        add(finding("fw.forward", "firewall", CHANGE if fwd else MISSING,
                    "Forward-Kette: LAN nicht gegen Zugriffe aus dem Internet geschützt",
                    "Empfohlen: established/related erlauben, invalid verwerfen, von WAN nur Portweiterleitungen "
                    "(dstnat) zulassen. Ausgehender Verkehr aus dem LAN (Newt!) bleibt erlaubt.",
                    script=["/ip firewall filter",
                            "add chain=forward action=accept connection-state=established,related,untracked "
                            "comment=\"servermanager: established\"",
                            "add chain=forward action=drop connection-state=invalid comment=\"servermanager: invalid\"",
                            f"add chain=forward action=drop in-interface={wan} connection-nat-state=!dstnat "
                            "connection-state=new comment=\"servermanager: drop WAN not dstnat\""]))
    blocking = [r for r in fwd if r.get("action") in ("drop", "reject") and
                (r.get("src-address") == lan_net or r.get("in-interface") == lan) and not r.get("dst-port")
                and not r.get("dst-address") and not r.get("connection-state")]
    if blocking:
        add(finding("fw.lanout", "firewall", CHANGE, "Forward-Regel blockiert Verkehr aus dem LAN",
                    "Damit erreichen Newt und die Dienste das Internet nicht.",
                    current="; ".join(_rule_text(r) for r in blocking[:3])))
    dns = single(snap, "ip/dns")
    if yes(dns.get("allow-remote-requests")) and not wan_drop:
        add(finding("fw.dns", "firewall", CHANGE, "Offener DNS-Resolver",
                    "allow-remote-requests ist aktiv, aber die Input-Kette verwirft Anfragen von WAN nicht – der "
                    "Router kann für DNS-Amplification missbraucht werden.", severity="crit",
                    script=[f"/ip firewall filter add chain=input action=drop in-interface={wan} protocol=udp "
                            "dst-port=53 comment=\"servermanager: DNS von WAN\"",
                            f"/ip firewall filter add chain=input action=drop in-interface={wan} protocol=tcp "
                            "dst-port=53 comment=\"servermanager: DNS von WAN\""]))


def _service_findings(snap, t, add, wan) -> None:
    services = {s.get("name"): s for s in items(snap, "ip/service")}
    mgmt = ",".join(split_list(t.get("mgmt_addresses", "")))
    insecure = [n for n in ("telnet", "ftp", "www", "api") if n in services and enabled(services[n])]
    if insecure:
        add(finding("svc.insecure", "services", CHANGE, "Unverschlüsselte Dienste aktiv: " + ", ".join(insecure),
                    "Nur als Skript: Wird der Servermanager noch über http/api angebunden, zuerst auf "
                    "www-ssl (https) umstellen.",
                    script=[f"/ip service disable {','.join(insecure)}"]))
    else:
        add(finding("svc.insecure", "services", OK, "Keine unverschlüsselten Dienste aktiv"))
    ssl = services.get("www-ssl")
    if ssl and enabled(ssl):
        if ssl.get("certificate") in (None, "", "none"):
            add(finding("svc.rest", "services", CHANGE, "www-ssl ohne Zertifikat",
                        script=["/certificate add name=sm-rest common-name=router key-usage=tls-server",
                                "/certificate sign sm-rest",
                                "/ip service set www-ssl certificate=sm-rest"]))
        else:
            add(finding("svc.rest", "services", OK, "REST-API über www-ssl (https)",
                        current=f"Port {ssl.get('port', '443')}, Zertifikat {ssl.get('certificate', '')}"))
    else:
        add(finding("svc.rest", "services", MISSING, "www-ssl (REST-API über https) nicht aktiv",
                    "Der Servermanager nutzt die REST-API – sie sollte nur über https erreichbar sein.",
                    script=["/certificate add name=sm-rest common-name=router key-usage=tls-server",
                            "/certificate sign sm-rest",
                            "/ip service set www-ssl certificate=sm-rest disabled=no"
                            + (f" address={mgmt}" if mgmt else "")]))
    open_mgmt = [n for n in ("ssh", "winbox", "www-ssl", "api-ssl") if n in services and
                 enabled(services[n]) and not services[n].get("address")]
    if open_mgmt:
        add(finding("svc.address", "services", CHANGE,
                    "Management-Dienste ohne Adressbeschränkung: " + ", ".join(open_mgmt),
                    "Nur als Skript – ACHTUNG Aussperrung: die Liste muss die Adresse enthalten, von der der "
                    "Servermanager und die Administratoren zugreifen (z. B. WireGuard-Management-Netz).",
                    script=[f"/ip service set {n} address={mgmt or '<MGMT-NETZ>'}" for n in open_mgmt]))
    elif any(n in services for n in ("ssh", "winbox")):
        add(finding("svc.address", "services", OK, "Management-Dienste auf Adressen beschränkt"))
    disc = single(snap, "ip/neighbor/discovery-settings")
    if disc and disc.get("discover-interface-list") in ("all", "", None):
        add(finding("svc.discovery", "services", CHANGE, "Neighbor Discovery auf allen Interfaces (auch WAN)",
                    script=["/interface list add name=LAN comment=\"servermanager\"",
                            f"/interface list member add list=LAN interface={t['lan_interface']}",
                            "/ip neighbor discovery-settings set discover-interface-list=LAN"]))
    mac = single(snap, "tool/mac-server")
    macw = single(snap, "tool/mac-server/mac-winbox")
    if (mac and mac.get("allowed-interface-list") in ("all", "")) or \
            (macw and macw.get("allowed-interface-list") in ("all", "")):
        add(finding("svc.mac", "services", CHANGE, "MAC-Telnet/MAC-Winbox auf allen Interfaces",
                    script=["/tool mac-server set allowed-interface-list=LAN",
                            "/tool mac-server mac-winbox set allowed-interface-list=LAN"]))
    users = items(snap, "user")
    if any(u.get("name") == "admin" and enabled(u) for u in users):
        add(finding("svc.admin", "services", CHECK, "Standardbenutzer „admin“ aktiv",
                    "Eigenen Administrator anlegen und admin deaktivieren (erschwert Brute-Force).",
                    script=["/user add name=<NAME> group=full password=<PASSWORT>", "/user disable admin"]))


def summarize(findings: list[dict]) -> dict:
    counts = {OK: 0, CHANGE: 0, MISSING: 0, CHECK: 0}
    crit = 0
    for f in findings:
        counts[f["status"]] += 1
        crit += f["severity"] == "crit"
    return {"counts": counts, "crit": crit, "applicable": sum(1 for f in findings if f["applicable"])}


def full_script(findings: list[dict]) -> str:
    lines = ["# Servermanager – Änderungen aus der Konfigurationsanalyse",
             "# Vor dem Einspielen prüfen! Firewall-/Dienst-Regeln können den Zugang sperren."]
    for f in findings:
        if f["status"] == OK or not f["script"]:
            continue
        lines.append(f"\n# {AREAS.get(f['area'], f['area'])}: {f['title']}")
        lines.extend(f["script"])
    return "\n".join(lines) + "\n"


# ==========================================================================
# apply
# ==========================================================================
def backup_before_change(mt: MikroTik) -> str:
    name = "sm-before-" + datetime.now().strftime("%Y%m%d-%H%M%S")
    mt.command("system/backup/save", {"name": name, "dont-encrypt": "yes"}, timeout=60)
    try:
        mt.command("export", {"file": name, "hide-sensitive": ""}, timeout=60)
    except MikroTikError:
        pass
    return name


def apply_ops(mt: MikroTik, ops: list[dict], log: Callable[[str], None]) -> int:
    done = 0
    for op in ops:
        if op["m"] == "add":
            mt.create(op["path"], op["data"])
        elif op["m"] == "set" and op.get("id"):
            mt.patch(op["path"], op["id"], op["data"])
        elif op["m"] == "set":
            mt.command(op["path"] + "/set", op["data"])
        else:
            raise RouterOSError(f"Unbekannte Operation {op['m']}")
        log(op_to_cli(op))
        done += 1
    return done


# --------------------------------------------------------------------------
# ping test diagnosis
# --------------------------------------------------------------------------
PING_STATUS = {"timeout": "Zeitüberschreitung", "no route to host": "keine Route zum Ziel",
               "net unreachable": "Netz nicht erreichbar", "host unreachable": "Host nicht erreichbar"}
_IP_IN = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


def ping_result(res: Any) -> dict:
    """Summary of a /ping reply (list of per-packet entries, the last one carries the totals)."""
    rows = res if isinstance(res, list) else ([res] if isinstance(res, dict) else [])
    last = rows[-1] if rows else {}
    statuses = []
    for r in rows:
        st = str(r.get("status") or "").strip()
        if st and st not in statuses:
            statuses.append(st)
    return {"sent": str(last.get("sent", "?")), "received": str(last.get("received", "")),
            "avg": last.get("avg-rtt", "?"), "statuses": statuses}


def ping_diagnosis(mt: MikroTik, target: str, src: str = "") -> list[str]:
    """Likely causes when the router itself cannot reach a host (each check is best effort)."""
    hints: list[str] = []
    try:
        routes = [r for r in mt.get("ip/route") if r.get("dst-address") == "0.0.0.0/0" and enabled(r)
                  and r.get("routing-table", "main") in ("main", "")]
    except MikroTikError:
        routes = None
    gw_ip = ""
    if routes is not None:
        active = [r for r in routes if yes(r.get("active"))]
        if not routes:
            hints.append("Keine Default-Route (0.0.0.0/0) in der Tabelle main – DHCP-Client mit "
                         "add-default-route=yes oder /ip route add dst-address=0.0.0.0/0 gateway=<GATEWAY>.")
        elif not active:
            gws = ", ".join(str(r.get("gateway", "?")) for r in routes)
            hints.append(f"Default-Route vorhanden, aber nicht aktiv (Gateway {gws} nicht erreichbar). Liegt das "
                         "Gateway außerhalb des eigenen Netzes (z. B. Hetzner Cloud: 172.31.1.1 bei einer /32-Adresse), "
                         "das Interface mit angeben: gateway=172.31.1.1%<WAN-Interface>.")
        else:
            m = _IP_IN.search(str(active[0].get("immediate-gw") or active[0].get("gateway") or ""))
            gw_ip = m.group(1) if m else ""
    if gw_ip and gw_ip != target:
        try:
            gw = ping_result(mt.command("ping", {"address": gw_ip, "count": "2"}, timeout=20))
            if gw["received"] in ("0", ""):
                hints.append(f"Auch das Gateway {gw_ip} antwortet nicht – Anbindung zum Provider prüfen "
                             "(manche Gateways beantworten allerdings keinen Ping).")
            else:
                hints.append(f"Das Gateway {gw_ip} antwortet – das Problem liegt dahinter oder in einer Filterregel.")
        except MikroTikError:
            pass
    try:
        drops = [r for r in mt.get("ip/firewall/filter") if r.get("chain") == "output" and enabled(r)
                 and r.get("action") in ("drop", "reject")]
        if drops:
            hints.append(f"{len(drops)} Firewall-Regel(n) in chain=output verwerfen Pakete des Routers selbst.")
    except MikroTikError:
        pass
    try:
        marks = [r for r in mt.get("ip/firewall/mangle") if r.get("chain") == "output" and enabled(r)
                 and r.get("action") == "mark-routing"]
        if marks:
            tables = ", ".join(sorted({str(r.get("new-routing-mark", "?")) for r in marks}))
            hints.append(f"Mangle-Regeln in chain=output leiten Pakete des Routers über die Tabelle(n) {tables} "
                         "– dort muss eine funktionierende Default-Route existieren.")
    except MikroTikError:
        pass
    if src:
        try:
            local = {str(a.get("address", "")).split("/")[0] for a in mt.get("ip/address")}
            if src not in local:
                hints.append(f"Die Quelladresse {src} ist keine Adresse des Routers.")
        except MikroTikError:
            pass
    return hints
