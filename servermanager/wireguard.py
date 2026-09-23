"""WireGuard management network: keys, IP allocation, MikroTik peers, local tunnel."""
from __future__ import annotations

import base64
import ipaddress
import logging
import os
import re
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import settings
from .config import get_config
from .helper import HelperError, run_helper
from .mikrotik import MikroTik, MikroTikError
from .models import CONN_WIREGUARD, System

log = logging.getLogger(__name__)
IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
COMMENT_PREFIX = "servermanager:"


# --------------------------------------------------------------------------
# keys
# --------------------------------------------------------------------------
def generate_keypair() -> tuple[str, str]:
    key = X25519PrivateKey.generate()
    priv = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(priv).decode(), base64.b64encode(pub).decode()


def public_from_private(priv_b64: str) -> str:
    key = X25519PrivateKey.from_private_bytes(base64.b64decode(priv_b64))
    return base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw,
                                                          serialization.PublicFormat.Raw)).decode()


def valid_key(value: str) -> bool:
    try:
        return len(base64.b64decode(value or "", validate=True)) == 32
    except ValueError:
        return False


def ensure_sm_keypair(db: Session) -> str:
    priv = settings.get(db, "wg.sm_private_key")
    if not priv:
        priv, pub = generate_keypair()
        settings.set(db, "wg.sm_private_key", priv)
        settings.set(db, "wg.sm_public_key", pub)
        return pub
    pub = settings.get(db, "wg.sm_public_key") or public_from_private(priv)
    return pub


# --------------------------------------------------------------------------
# networks
# --------------------------------------------------------------------------
def parse_subnets(text: str) -> list[str]:
    out = []
    for item in re.split(r"[\s,;]+", text or ""):
        if not item:
            continue
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise ValueError(f"Ungültiges Netz: {item}") from exc
        if net.version != 4:
            raise ValueError(f"Nur IPv4-Netze werden unterstützt: {item}")
        out.append(str(net))
    return out


def mgmt_network(db: Session) -> ipaddress.IPv4Network:
    return ipaddress.ip_network(settings.get(db, "wg.network"), strict=False)  # type: ignore[return-value]


def used_ips(db: Session) -> set[str]:
    ips = {settings.get(db, "wg.router_ip"), settings.get(db, "wg.sm_ip")}
    for (ip,) in db.execute(select(System.wg_ip).where(System.wg_ip != "")).all():
        ips.add(ip)
    return {i for i in ips if i}


def allocate_ip(db: Session, extra_used: Optional[set[str]] = None) -> str:
    net = mgmt_network(db)
    used = used_ips(db) | (extra_used or set())
    start = int(settings.get(db, "wg.pool_start") or 10)
    for idx, host in enumerate(net.hosts(), start=1):
        if idx < start:
            continue
        if str(host) not in used:
            return str(host)
    raise ValueError(f"Keine freie IP-Adresse mehr im Management-Netz {net}")


def all_routed_subnets(db: Session) -> list[str]:
    nets: list[str] = []
    for (text,) in db.execute(select(System.routed_subnets).where(System.connection == CONN_WIREGUARD)).all():
        for n in parse_subnets(text or ""):
            if n not in nets:
                nets.append(n)
    return nets


# --------------------------------------------------------------------------
# MikroTik peers
# --------------------------------------------------------------------------
def api(db: Session) -> MikroTik:
    return MikroTik.from_settings(db)


def router_public_key(db: Session, refresh: bool = False) -> str:
    key = settings.get(db, "wg.router_public_key")
    if key and not refresh:
        return key
    iface = api(db).wg_interface(settings.get(db, "wg.mikrotik_interface"))
    if not iface:
        raise MikroTikError(f"WireGuard-Interface '{settings.get(db, 'wg.mikrotik_interface')}' "
                            "wurde auf dem MikroTik nicht gefunden")
    key = iface.get("public-key", "")
    settings.set(db, "wg.router_public_key", key)
    if not settings.get(db, "wg.listen_port") and iface.get("listen-port"):
        settings.set(db, "wg.listen_port", int(iface["listen-port"]))
    return key


def peer_ips(db: Session, mt: MikroTik) -> set[str]:
    ips = set()
    for p in mt.wg_peers(settings.get(db, "wg.mikrotik_interface")):
        for a in str(p.get("allowed-address", "")).split(","):
            a = a.strip()
            if a.endswith("/32"):
                ips.add(a[:-3])
    return ips


def provision_peer(db: Session, system: System, public_key: str, routed: list[str],
                   mt: Optional[MikroTik] = None) -> None:
    """Create peer, routes and address-list entry for ``system`` on the MikroTik."""
    mt = mt or api(db)
    iface = settings.get(db, "wg.mikrotik_interface")
    tag = f"{COMMENT_PREFIX}{system.id}:{system.name}"[:200]
    refs: dict = {"routes": []}
    allowed = [f"{system.wg_ip}/32"] + routed
    try:
        refs["peer"] = mt.add_peer(iface, public_key, allowed, tag)
        lst = settings.get(db, "wg.address_list")
        if lst:
            refs["addrlist"] = mt.add_address_list(lst, system.wg_ip, tag)
        for net in routed:
            refs["routes"].append(mt.add_route(net, iface, tag))
    except MikroTikError:
        remove_refs(mt, refs)
        raise
    system.mt_refs = refs
    system.wg_public_key = public_key


def remove_refs(mt: MikroTik, refs: dict) -> None:
    for rid in refs.get("routes", []) or []:
        try:
            mt.delete_checked("ip/route", rid, COMMENT_PREFIX)
        except MikroTikError as exc:
            log.warning("route cleanup failed: %s", exc)
    if refs.get("addrlist"):
        try:
            mt.delete_checked("ip/firewall/address-list", refs["addrlist"], COMMENT_PREFIX)
        except MikroTikError as exc:
            log.warning("address list cleanup failed: %s", exc)
    if refs.get("peer"):
        try:
            mt.delete_checked("interface/wireguard/peers", refs["peer"], COMMENT_PREFIX)
        except MikroTikError as exc:
            log.warning("peer cleanup failed: %s", exc)


def deprovision_peer(db: Session, system: System) -> None:
    refs = system.mt_refs or {}
    if not refs:
        return
    mt = api(db)
    remove_refs(mt, refs)
    system.mt_refs = {}


def peers_overview(db: Session) -> list[dict]:
    """MikroTik peers merged with the systems of the database."""
    mt = api(db)
    iface = settings.get(db, "wg.mikrotik_interface")
    peers = mt.wg_peers(iface)
    systems = {s.wg_public_key: s for s in db.execute(select(System).where(System.wg_public_key != "")).scalars()}
    rows = []
    seen = set()
    for p in peers:
        pk = p.get("public-key", "")
        s = systems.get(pk)
        seen.add(pk)
        rows.append({
            "id": p.get(".id"), "public_key": pk, "allowed": p.get("allowed-address", ""),
            "comment": p.get("comment", ""), "endpoint": p.get("current-endpoint-address", ""),
            "handshake": p.get("last-handshake", ""), "rx": p.get("rx", ""), "tx": p.get("tx", ""),
            "disabled": p.get("disabled") in ("true", True), "system": s,
            "ours": str(p.get("comment", "")).startswith(COMMENT_PREFIX),
            "is_sm": pk == settings.get(db, "wg.sm_public_key"),
        })
    missing = [s for pk, s in systems.items() if pk not in seen and s.connection == CONN_WIREGUARD]
    return rows + [{"missing": True, "system": s, "public_key": s.wg_public_key, "allowed": s.wg_ip}
                   for s in missing]


# --------------------------------------------------------------------------
# servermanager's own tunnel
# --------------------------------------------------------------------------
def render_sm_config(db: Session) -> str:
    priv = settings.get(db, "wg.sm_private_key")
    router_key = settings.get(db, "wg.router_public_key")
    endpoint = settings.get(db, "wg.sm_endpoint") or settings.get(db, "wg.endpoint")
    if not (priv and router_key and endpoint):
        raise ValueError("Für den Tunnel werden eigener Schlüssel, MikroTik-Public-Key und Endpoint benötigt.")
    allowed = [str(mgmt_network(db))] + [n for n in all_routed_subnets(db) if n != str(mgmt_network(db))]
    mtu = int(settings.get(db, "wg.mtu") or 1420)
    return "\n".join([
        "# Servermanager management tunnel - generated automatically, do not edit",
        "[Interface]",
        f"PrivateKey = {priv}",
        f"Address = {settings.get(db, 'wg.sm_ip')}/32",
        f"MTU = {mtu}",
        "",
        "[Peer]",
        f"PublicKey = {router_key}",
        f"Endpoint = {endpoint}",
        f"AllowedIPs = {', '.join(allowed)}",
        f"PersistentKeepalive = {int(settings.get(db, 'wg.keepalive') or 25)}",
        "",
    ])


def apply_local(db: Session) -> str:
    iface = settings.get(db, "wg.local_iface")
    if not IFACE_RE.match(iface or ""):
        raise ValueError("Ungültiger Interface-Name")
    text = render_sm_config(db)
    path = get_config().wireguard_dir / f"{iface}.conf"
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    return run_helper("wg-apply", iface, timeout=60)


def refresh_local_routes(db: Session) -> None:
    """Re-apply the local config if the tunnel is managed (e.g. new routed subnets)."""
    if not settings.get(db, "wg.enabled"):
        return
    try:
        apply_local(db)
    except (ValueError, HelperError) as exc:
        log.warning("updating local WireGuard config failed: %s", exc)


def local_status(db: Session) -> dict:
    iface = settings.get(db, "wg.local_iface")
    try:
        out = run_helper("wg-show", iface, timeout=20, check=False)
    except HelperError as exc:
        return {"up": False, "error": str(exc)}
    lines = [line.split("\t") for line in out.strip().splitlines() if line.strip()]
    if not lines or len(lines[0]) < 3:
        return {"up": False, "error": out.strip()[:200]}
    peers = []
    for parts in lines[1:]:
        if len(parts) >= 8:
            peers.append({"public_key": parts[0], "endpoint": parts[2], "allowed": parts[3],
                          "handshake": int(parts[4] or 0), "rx": int(parts[5] or 0), "tx": int(parts[6] or 0)})
    return {"up": True, "public_key": lines[0][1], "listen_port": lines[0][2], "peers": peers}


def routeros_script(db: Session) -> str:
    """RouterOS commands for the initial MikroTik setup."""
    g = lambda k: settings.get(db, k)  # noqa: E731
    net = mgmt_network(db)
    iface = g("wg.mikrotik_interface")
    sm_ip = g("wg.sm_ip")
    router_ip = g("wg.router_ip")
    port = int(g("wg.listen_port") or 13231)
    sm_pub = ensure_sm_keypair(db)
    lst = g("wg.address_list") or "servermanager-clients"
    user = g("wg.mikrotik_user") or "servermanager"
    return f"""# ---- Servermanager: MikroTik RouterOS 7 Einrichtung ----
# 1) WireGuard-Interface und Adresse des Management-Netzes
/interface wireguard add name={iface} listen-port={port} mtu={int(g('wg.mtu') or 1420)} comment="servermanager management"
/ip address add address={router_ip}/{net.prefixlen} interface={iface} comment="servermanager management"

# 2) Peer für den Servermanager selbst
/interface wireguard peers add interface={iface} public-key="{sm_pub}" allowed-address={sm_ip}/32 comment="servermanager:self"

# 3) Firewall (Regeln ggf. vor bestehende drop-Regeln verschieben!)
/ip firewall filter add chain=input protocol=udp dst-port={port} action=accept comment="servermanager: wireguard"
/ip firewall filter add chain=input in-interface={iface} src-address={sm_ip} protocol=tcp dst-port=443 action=accept comment="servermanager: REST API"
/ip firewall filter add chain=forward in-interface={iface} src-address={sm_ip} action=accept comment="servermanager: sm -> clients"
/ip firewall filter add chain=forward in-interface={iface} dst-address={sm_ip} connection-state=established,related action=accept comment="servermanager: replies"
/ip firewall filter add chain=forward in-interface={iface} action=drop comment="servermanager: clients isolieren"
# Adressliste '{lst}' wird automatisch mit den Client-IPs befüllt (für eigene Regeln nutzbar)

# 4) REST-API (HTTPS) mit eigenem Zertifikat
/certificate add name=servermanager-ca common-name=servermanager-ca key-usage=key-cert-sign,crl-sign
/certificate sign servermanager-ca
/certificate add name=servermanager-api common-name={router_ip} subject-alt-name=IP:{router_ip}
/certificate sign servermanager-api ca=servermanager-ca
/ip service set www-ssl certificate=servermanager-api disabled=no

# 5) API-Benutzer mit eingeschränkten Rechten (Passwort anpassen!)
#    Falls RouterOS die Policy "rest-api" nicht kennt: sie weglassen ("api" genügt dann).
/user group add name=servermanager policy=read,write,api,rest-api,!ftp,!reboot,!policy,!password,!sniff,!sensitive,!romon
/user add name={user} group=servermanager address={sm_ip}/32 password="BITTE-AENDERN"

# 6) Public Key des MikroTik anzeigen (im Servermanager eintragen oder per API abrufen):
/interface wireguard print where name={iface}
"""


def update_peer_routes(db: Session, system: System, routed: list[str]) -> None:
    """Re-create peer/routes on the MikroTik after the routed subnets of a system changed."""
    if not system.wg_public_key or not system.wg_ip:
        system.routed_subnets = " ".join(routed)
        return
    mt = api(db)
    remove_refs(mt, system.mt_refs or {})
    system.mt_refs = {}
    provision_peer(db, system, system.wg_public_key, routed, mt)
    system.routed_subnets = " ".join(routed)
