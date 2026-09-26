"""Proxmox VE via API: clients, guest operations, LXC creation parameters, polling."""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Optional

from . import security, sshkeys
from .models import LEVEL_FULL, LEVEL_OPERATE, PveServer
from .pveapi import GUEST_TYPES, NODE_RE, PveClient

HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$")
STORAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,63}$")
VOLID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]*:vztmpl/[A-Za-z0-9._+-]+\.tar\.(gz|xz|zst)$")
APPLIANCE_RE = re.compile(r"^[A-Za-z0-9._+-]+\.tar\.(gz|xz|zst)$")
SNAPNAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{1,39}$")
BRIDGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,15}$")
POOL_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
TAG_RE = re.compile(r"^[a-z0-9_][a-z0-9_.+-]{0,63}$")
SSH_KEY_RE = re.compile(r"^(ssh-(ed25519|rsa|dss)|ecdsa-sha2-nistp(256|384|521)|sk-(ssh-ed25519|ecdsa-sha2-nistp256)"
                        r"@openssh\.com) [A-Za-z0-9+/=]+( [^\r\n]*)?$")
TIMEFRAMES = {"hour": "Stunde", "day": "Tag", "week": "Woche", "month": "Monat", "year": "Jahr"}

# op -> (label, required level, guest types, needs confirmation text)
OPS: dict[str, dict[str, Any]] = {
    "start": {"label": "Starten", "level": LEVEL_OPERATE},
    "shutdown": {"label": "Herunterfahren", "level": LEVEL_OPERATE, "confirm": "herunterfahren"},
    "reboot": {"label": "Neu starten", "level": LEVEL_OPERATE, "confirm": "neu starten"},
    "stop": {"label": "Hart stoppen", "level": LEVEL_OPERATE, "confirm": "hart stoppen (wie Stecker ziehen)"},
    "suspend": {"label": "Pausieren", "level": LEVEL_OPERATE, "types": ("qemu",)},
    "resume": {"label": "Fortsetzen", "level": LEVEL_OPERATE, "types": ("qemu",)},
    "snapshot": {"label": "Snapshot erstellen", "level": LEVEL_OPERATE},
    "backup": {"label": "Sicherung (vzdump)", "level": LEVEL_OPERATE},
    "rollback": {"label": "Snapshot zurückspielen", "level": LEVEL_FULL},
    "delsnapshot": {"label": "Snapshot löschen", "level": LEVEL_FULL},
    "resize": {"label": "Disk vergrößern", "level": LEVEL_FULL, "types": ("lxc",)},
    "destroy": {"label": "Löschen", "level": LEVEL_FULL},
    "download": {"label": "Vorlage herunterladen", "level": LEVEL_FULL},
}


class PveParamError(ValueError):
    pass


def client(server: PveServer, timeout: int = 20) -> PveClient:
    return PveClient(server.api_url, server.token_id, security.decrypt(server.token_secret_enc),
                     fingerprint=server.fingerprint or "", verify_ca=bool(server.verify_ca), timeout=timeout)


def check_guest_ref(node: str, gtype: str, vmid: Any) -> tuple[str, str, int]:
    if not NODE_RE.match(node or ""):
        raise PveParamError("Ungültiger Node")
    if gtype not in GUEST_TYPES:
        raise PveParamError("Ungültiger Gast-Typ")
    try:
        vmid = int(vmid)
    except (TypeError, ValueError):
        raise PveParamError("Ungültige VMID") from None
    if not 100 <= vmid <= 999999999:
        raise PveParamError("Ungültige VMID")
    return node, gtype, vmid


def op_allowed(op: str, gtype: str) -> bool:
    spec = OPS.get(op)
    return bool(spec) and gtype in spec.get("types", GUEST_TYPES)


def clean_op_params(op: str, form: dict) -> dict:
    """Validated parameters of an operation (from a web form)."""
    p: dict[str, Any] = {}
    if op in ("snapshot", "rollback", "delsnapshot"):
        name = (form.get("snapname") or "").strip()
        if not SNAPNAME_RE.match(name):
            raise PveParamError("Snapshot-Name: Buchstabe am Anfang, dann Buchstaben, Ziffern, _ oder - (2–40)")
        p["snapname"] = name
        if op == "snapshot":
            p["description"] = (form.get("description") or "")[:500]
    elif op == "backup":
        storage = (form.get("storage") or "").strip()
        if not STORAGE_RE.match(storage):
            raise PveParamError("Bitte einen Backup-Storage wählen")
        mode = form.get("mode") or "snapshot"
        if mode not in ("snapshot", "suspend", "stop"):
            raise PveParamError("Ungültiger Backup-Modus")
        p.update({"storage": storage, "mode": mode, "notes": (form.get("notes") or "")[:200]})
    elif op == "resize":
        try:
            gb = int(form.get("add_gb") or 0)
        except ValueError:
            gb = 0
        if not 1 <= gb <= 16384:
            raise PveParamError("Vergrößerung in GB (1–16384) angeben")
        p["add_gb"] = gb
    elif op == "destroy":
        p["purge"] = bool(form.get("purge"))
    return p


def start_op(api: PveClient, op: str, node: str, gtype: str, vmid: int, params: dict) -> Optional[str]:
    """Issue the API call of an operation; returns the task UPID (or None for synchronous calls)."""
    base = api.guest_path(node, gtype, vmid)
    if op in ("start", "shutdown", "reboot", "stop", "suspend", "resume"):
        extra = {"timeout": 180} if op == "shutdown" else {}
        return api.post(f"{base}/status/{op}", **extra)
    if op == "snapshot":
        return api.post(f"{base}/snapshot", snapname=params["snapname"], description=params.get("description") or None)
    if op == "rollback":
        return api.post(f"{base}/snapshot/{params['snapname']}/rollback")
    if op == "delsnapshot":
        return api.delete(f"{base}/snapshot/{params['snapname']}")
    if op == "backup":
        return api.post(f"nodes/{node}/vzdump", vmid=vmid, storage=params["storage"], mode=params["mode"],
                        compress="zstd", **({"notes-template": params["notes"]} if params.get("notes") else {}))
    if op == "resize":
        return api.put(f"{base}/resize", disk="rootfs", size=f"+{int(params['add_gb'])}G")
    if op == "destroy":
        extra = {"purge": 1, "destroy-unreferenced-disks": 1} if params.get("purge") else {}
        return api.delete(base, **extra)
    raise PveParamError(f"Unbekannte Operation {op}")


# --------------------------------------------------------------------------
# LXC creation
# --------------------------------------------------------------------------
def _int(form: dict, key: str, lo: int, hi: int, label: str, default: Optional[int] = None) -> int:
    raw = (form.get(key) or "").strip() if isinstance(form.get(key), str) else form.get(key)
    if raw in (None, "") and default is not None:
        return default
    try:
        v = int(raw)
    except (TypeError, ValueError):
        raise PveParamError(f"{label}: Zahl erwartet") from None
    if not lo <= v <= hi:
        raise PveParamError(f"{label}: erlaubt {lo}–{hi}")
    return v


def build_create(form: dict) -> dict:
    """Validate the create form and return the job payload (password encrypted)."""
    f = {k: (v.strip() if isinstance(v, str) else v) for k, v in form.items()}
    node = f.get("node", "")
    if not NODE_RE.match(node):
        raise PveParamError("Bitte einen Node wählen")
    hostname = f.get("hostname", "")
    if not HOSTNAME_RE.match(hostname):
        raise PveParamError("Ungültiger Hostname (Buchstaben, Ziffern, Bindestrich, Punkte)")
    p: dict[str, Any] = {"node": node, "hostname": hostname.lower(),
                         "vmid": _int(f, "vmid", 100, 999999999, "VMID")}
    tpl = f.get("template", "")
    if tpl.startswith("download:"):
        name = tpl.split(":", 1)[1]
        if not APPLIANCE_RE.match(name):
            raise PveParamError("Ungültige Vorlage")
        tstore = f.get("template_storage", "")
        if not STORAGE_RE.match(tstore):
            raise PveParamError("Storage für den Download der Vorlage wählen")
        p["download"] = {"template": name, "storage": tstore}
        p["ostemplate"] = f"{tstore}:vztmpl/{name}"
    elif VOLID_RE.match(tpl):
        p["ostemplate"] = tpl
    else:
        raise PveParamError("Bitte eine Vorlage wählen")
    storage = f.get("storage", "")
    if not STORAGE_RE.match(storage):
        raise PveParamError("Storage für das Root-Dateisystem wählen")
    p["storage"] = storage
    p["disk_gb"] = _int(f, "disk_gb", 1, 16384, "Disk (GB)", 8)
    p["cores"] = _int(f, "cores", 1, 512, "CPU-Kerne", 1)
    p["memory"] = _int(f, "memory", 16, 4 * 1024 * 1024, "RAM (MB)", 1024)
    p["swap"] = _int(f, "swap", 0, 4 * 1024 * 1024, "Swap (MB)", 512)
    bridge = f.get("bridge", "")
    if not BRIDGE_RE.match(bridge):
        raise PveParamError("Netzwerk-Bridge wählen")
    p["bridge"] = bridge
    p["vlan"] = _int(f, "vlan", 1, 4094, "VLAN", 0) if f.get("vlan") else 0
    mode = f.get("ip_mode", "dhcp")
    if mode == "static":
        try:
            iface = ipaddress.ip_interface(f.get("ip", ""))
        except ValueError:
            raise PveParamError("IPv4-Adresse mit Präfix angeben, z. B. 10.20.0.50/24") from None
        if iface.version != 4 or iface.network.prefixlen >= 32 or iface.ip == iface.network.network_address:
            raise PveParamError("IPv4-Adresse mit Präfix angeben, z. B. 10.20.0.50/24")
        gw = f.get("gateway", "")
        try:
            if ipaddress.ip_address(gw) not in iface.network:
                raise PveParamError("Gateway muss im selben Netz liegen")
        except ValueError:
            raise PveParamError("Ungültiges Gateway") from None
        p.update({"ip": str(iface), "gateway": gw})
    elif mode != "dhcp":
        raise PveParamError("Ungültiger IP-Modus")
    p["ip_mode"] = mode
    ip6 = f.get("ip6", "none")
    if ip6 not in ("none", "auto", "dhcp"):
        raise PveParamError("Ungültiger IPv6-Modus")
    p["ip6"] = ip6
    dns = f.get("nameserver", "")
    for d in dns.split():
        try:
            ipaddress.ip_address(d)
        except ValueError:
            raise PveParamError(f"Ungültiger DNS-Server {d}") from None
    p["nameserver"] = dns
    sd = f.get("searchdomain", "")
    if sd and not HOSTNAME_RE.match(sd):
        raise PveParamError("Ungültige Suchdomain")
    p["searchdomain"] = sd
    pw = form.get("password") or ""
    if pw and len(pw) < 8:
        raise PveParamError("Root-Passwort: mindestens 8 Zeichen (oder leer lassen)")
    p["password_enc"] = security.encrypt(pw) if pw else None
    keys = []
    for line in (f.get("ssh_keys") or "").splitlines():
        line = line.strip()
        if not line:
            continue
        if not SSH_KEY_RE.match(line):
            raise PveParamError("Ungültiger SSH-Schlüssel: " + line[:40])
        keys.append(line)
    p["ssh_keys"] = keys
    p["add_sm_key"] = bool(f.get("add_sm_key"))
    if not pw and not keys and not p["add_sm_key"]:
        raise PveParamError("Root-Passwort oder SSH-Schlüssel angeben – sonst ist keine Anmeldung möglich")
    p["unprivileged"] = bool(f.get("unprivileged"))
    p["nesting"] = bool(f.get("nesting"))
    p["onboot"] = bool(f.get("onboot"))
    p["start"] = bool(f.get("start")) or bool(f.get("register")) or bool(f.get("publish"))
    pool = f.get("pool", "")
    if pool and not POOL_RE.match(pool):
        raise PveParamError("Ungültiger Pool")
    p["pool"] = pool
    tags = [t.strip().lower() for t in re.split(r"[,;\s]+", f.get("tags", "")) if t.strip()]
    for t in tags:
        if not TAG_RE.match(t):
            raise PveParamError(f"Ungültiges Tag {t}")
    p["tags"] = tags
    p["description"] = (f.get("description") or "")[:2000]
    p["watch"] = bool(f.get("watch"))
    # integration with the servermanager / RouterOS / Pangolin
    p["register"] = bool(f.get("register"))
    if p["register"] and not p["add_sm_key"]:
        raise PveParamError("Für die Aufnahme als System muss der Servermanager-Schlüssel hinterlegt werden")
    p["static_lease"] = bool(f.get("static_lease")) and mode == "dhcp"
    p["publish"] = None
    if f.get("publish"):
        from .pangolin import SUBDOMAIN_RE
        sub = (f.get("pub_subdomain") or "").lower()
        if sub and not SUBDOMAIN_RE.match(sub):
            raise PveParamError("Ungültige Subdomain")
        port = _int(f, "pub_port", 1, 65535, "Dienst-Port")
        method = f.get("pub_method", "http")
        if method not in ("http", "https"):
            raise PveParamError("Ungültiges Ziel-Protokoll")
        domain = f.get("pub_domain", "")
        site = _int(f, "pub_site", 0, 2 ** 31, "Pangolin-Site")
        if not domain or not re.match(r"^[A-Za-z0-9_-]{1,64}$", domain):
            raise PveParamError("Pangolin-Domain wählen")
        p["publish"] = {"subdomain": sub, "port": port, "method": method, "domain_id": domain, "site_id": site,
                        "sso": bool(f.get("pub_sso"))}
    p["newt"] = None
    if f.get("newt"):
        if not p["register"]:
            raise PveParamError("Für den Newt-Tunnel muss der Container als System verwaltet werden")
        p["newt"] = clean_newt(f)
        pid = f.get("newt_pangolin", "")
        p["newt"]["pangolin_id"] = int(pid) if str(pid).isdigit() else None
    return p


NEWT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{4,64}$")
NEWT_SECRET_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")


def clean_newt(f: dict) -> dict:
    """Newt credentials from a form (the secret is encrypted right away)."""
    from urllib.parse import urlsplit
    nid = (f.get("newt_id") or "").strip()
    secret = (f.get("newt_secret") or "").strip()
    endpoint = (f.get("newt_endpoint") or "").strip().rstrip("/")
    if not NEWT_ID_RE.match(nid):
        raise PveParamError("Newt-ID angeben (aus Pangolin: Site anlegen → Newt)")
    if not NEWT_SECRET_RE.match(secret):
        raise PveParamError("Newt-Secret angeben")
    parts = urlsplit(endpoint)
    if parts.scheme != "https" or not parts.hostname or parts.path not in ("", "/") or parts.username:
        raise PveParamError("Pangolin-Endpoint als https://pangolin.example.com angeben")
    return {"id": nid, "secret_enc": security.encrypt(secret), "endpoint": endpoint}


def create_params(p: dict) -> dict:
    """API parameters for POST /nodes/{node}/lxc."""
    net = f"name=eth0,bridge={p['bridge']},firewall=1"
    if p.get("vlan"):
        net += f",tag={int(p['vlan'])}"
    net += ",ip=dhcp" if p["ip_mode"] == "dhcp" else f",ip={p['ip']},gw={p['gateway']}"
    if p.get("ip6") in ("auto", "dhcp"):
        net += f",ip6={p['ip6']}"
    keys = list(p.get("ssh_keys") or [])
    if p.get("add_sm_key"):
        pub = sshkeys.public_key()
        if pub:
            keys.append(pub.strip())
    params: dict[str, Any] = {
        "vmid": int(p["vmid"]), "hostname": p["hostname"], "ostemplate": p["ostemplate"],
        "rootfs": f"{p['storage']}:{int(p['disk_gb'])}", "cores": p["cores"], "memory": p["memory"],
        "swap": p["swap"], "net0": net, "unprivileged": bool(p["unprivileged"]), "onboot": bool(p["onboot"]),
        "start": False,
    }
    if p.get("nesting"):
        params["features"] = "nesting=1"
    if p.get("nameserver"):
        params["nameserver"] = p["nameserver"]
    if p.get("searchdomain"):
        params["searchdomain"] = p["searchdomain"]
    if p.get("pool"):
        params["pool"] = p["pool"]
    if p.get("tags"):
        params["tags"] = ";".join(p["tags"])
    if p.get("description"):
        params["description"] = p["description"]
    if keys:
        params["ssh-public-keys"] = "\n".join(keys) + "\n"
    if p.get("password_enc"):
        params["password"] = security.decrypt(p["password_enc"])
    return params


def net0_mac(config: dict) -> str:
    m = re.search(r"hwaddr=([0-9A-Fa-f:]{17})", str(config.get("net0", "")))
    return m.group(1).upper() if m else ""


def container_ipv4(api: PveClient, node: str, vmid: int) -> str:
    for iface in api.lxc_interfaces(node, vmid):
        if iface.get("name") in ("lo",):
            continue
        for addr in (iface.get("ip-addresses") or []):
            if addr.get("ip-address-type") == "inet" and not str(addr.get("ip-address", "")).startswith("127."):
                return addr["ip-address"]
        inet = iface.get("inet")
        if inet and not inet.startswith("127."):
            return inet.split("/")[0]
    return ""


# --------------------------------------------------------------------------
# overview data
# --------------------------------------------------------------------------
def overview(api: PveClient) -> dict:
    items = api.resources()
    guests, nodes, storage = [], [], []
    for it in items:
        t = it.get("type")
        if t in GUEST_TYPES:
            maxdisk = it.get("maxdisk") or 0
            guests.append({
                "vmid": it.get("vmid"), "name": it.get("name", ""), "type": t, "node": it.get("node", ""),
                "status": it.get("status", ""), "cpu": round((it.get("cpu") or 0) * 100, 1),
                "maxcpu": it.get("maxcpu") or 0, "mem": it.get("mem") or 0, "maxmem": it.get("maxmem") or 0,
                "disk": it.get("disk") or 0, "maxdisk": maxdisk,
                "disk_pct": round((it.get("disk") or 0) * 100 / maxdisk) if maxdisk and t == "lxc" else None,
                "uptime": it.get("uptime") or 0, "template": bool(it.get("template")), "tags": it.get("tags", ""),
                "lock": it.get("lock", ""), "pool": it.get("pool", ""),
                "netin": it.get("netin") or 0, "netout": it.get("netout") or 0,
            })
        elif t == "node":
            maxmem = it.get("maxmem") or 0
            nodes.append({"node": it.get("node"), "status": it.get("status"),
                          "cpu": round((it.get("cpu") or 0) * 100, 1), "maxcpu": it.get("maxcpu") or 0,
                          "mem": it.get("mem") or 0, "maxmem": maxmem,
                          "mem_pct": round((it.get("mem") or 0) * 100 / maxmem) if maxmem else 0,
                          "disk": it.get("disk") or 0, "maxdisk": it.get("maxdisk") or 0,
                          "uptime": it.get("uptime") or 0})
        elif t == "storage":
            maxdisk = it.get("maxdisk") or 0
            storage.append({"storage": it.get("storage"), "node": it.get("node"), "status": it.get("status"),
                            "shared": bool(it.get("shared")), "disk": it.get("disk") or 0, "maxdisk": maxdisk,
                            "pct": round((it.get("disk") or 0) * 100 / maxdisk) if maxdisk else 0,
                            "content": it.get("content", ""), "plugintype": it.get("plugintype", "")})
    guests.sort(key=lambda g: g["vmid"] or 0)
    nodes.sort(key=lambda n: n["node"] or "")
    storage.sort(key=lambda s: (s["storage"] or "", s["node"] or ""))
    version = api.version()
    cluster = next((c for c in api.cluster_status() if c.get("type") == "cluster"), None)
    return {"guests": guests, "nodes": nodes, "storage": storage,
            "version": version.get("version", ""), "release": version.get("release", ""),
            "cluster": {"name": cluster.get("name"), "quorate": bool(cluster.get("quorate")),
                        "nodes": cluster.get("nodes")} if cluster else None}


def alerts_for(server: PveServer, data: dict, disk_pct: int) -> list[dict]:
    out: list[dict] = []
    for n in data.get("nodes", []):
        if n.get("status") != "online":
            out.append({"key": f"node:{n['node']}", "severity": "crit", "text": f"Node {n['node']} ist offline"})
    cl = data.get("cluster")
    if cl and not cl.get("quorate"):
        out.append({"key": "cluster:quorum", "severity": "crit", "text": f"Cluster {cl.get('name')} hat kein Quorum"})
    watch = set(server.watch_list)
    for g in data.get("guests", []):
        label = f"{'CT' if g['type'] == 'lxc' else 'VM'} {g['vmid']} ({g['name']})"
        if g["vmid"] in watch and g["status"] != "running":
            out.append({"key": f"guest:{g['vmid']}:down", "severity": "crit",
                        "text": f"{label} läuft nicht (Status {g['status']})"})
        if g.get("disk_pct") is not None and g["status"] == "running" and disk_pct and g["disk_pct"] >= disk_pct:
            out.append({"key": f"guest:{g['vmid']}:disk", "severity": "warn",
                        "text": f"{label}: Root-Dateisystem zu {g['disk_pct']} % belegt"})
    for s in data.get("storage", []):
        if s.get("status") == "available" and disk_pct and s["pct"] >= disk_pct:
            out.append({"key": f"storage:{s['node']}:{s['storage']}", "severity": "warn",
                        "text": f"Storage {s['storage']} auf {s['node']} zu {s['pct']} % belegt"})
    return out
