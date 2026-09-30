"""WireGuard / MikroTik management network."""
from __future__ import annotations

import ipaddress

from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from ... import settings, tlspin, wireguard
from ...core import audit
from ...helper import HelperError
from ...mikrotik import MikroTikError
from ...models import System
from ..auth import admin_required, client_ip

bp = Blueprint("wg", __name__, url_prefix="/wireguard")

FIELDS = ["wg.mikrotik_url", "wg.mikrotik_user", "wg.mikrotik_verify_tls", "wg.mikrotik_fingerprint",
          "wg.mikrotik_interface", "wg.network",
          "wg.router_ip", "wg.sm_ip", "wg.pool_start", "wg.listen_port", "wg.endpoint", "wg.sm_endpoint",
          "wg.router_public_key", "wg.local_iface", "wg.client_iface", "wg.keepalive", "wg.mtu", "wg.address_list"]


@bp.get("/")
@admin_required
def index():
    s = settings.get_many(g.db, "wg.")
    sm_pub = wireguard.ensure_sm_keypair(g.db)
    g.db.commit()
    peers, peer_error = [], None
    if s.get("wg.mikrotik_url") and request.args.get("peers", "1") == "1":
        try:
            peers = wireguard.peers_overview(g.db)
        except MikroTikError as exc:
            peer_error = str(exc)
    local = wireguard.local_status(g.db) if s.get("wg.enabled") else None
    try:
        script = wireguard.routeros_script(g.db)
    except ValueError as exc:
        script = f"# Fehler: {exc}"
    return render_template("wg/index.html", s=s, sm_pub=sm_pub, peers=peers, peer_error=peer_error, local=local,
                           script=script)


@bp.post("/settings")
@admin_required
def save():
    f = request.form
    errors = []
    values = {}
    for key in FIELDS:
        values[key] = settings.coerce(key, f.get(key.split(".", 1)[1], ""))
    try:
        net = ipaddress.ip_network(values["wg.network"], strict=False)
        values["wg.network"] = str(net)
        for k in ("wg.router_ip", "wg.sm_ip"):
            if ipaddress.ip_address(values[k]) not in net:
                errors.append(f"{k.split('.')[1]} liegt nicht im Management-Netz {net}.")
    except ValueError as exc:
        errors.append(f"Ungültige Netzangabe: {exc}")
    url = (values["wg.mikrotik_url"] or "").strip()
    if url and "://" not in url:
        url = values["wg.mikrotik_url"] = "https://" + url
    if f.get("fetch_fp") and url.startswith("https://"):
        from urllib.parse import urlsplit
        parts = urlsplit(url)
        try:
            values["wg.mikrotik_fingerprint"] = tlspin.fetch_fingerprint(parts.hostname, parts.port or 443)
            flash(f"Fingerabdruck abgerufen: {values['wg.mikrotik_fingerprint']} – bitte mit dem Zertifikat des "
                  "Routers vergleichen (/certificate print detail).", "info")
        except tlspin.PinError as exc:
            errors.append(str(exc))
    fp = (values["wg.mikrotik_fingerprint"] or "").strip()
    if fp:
        try:
            values["wg.mikrotik_fingerprint"] = tlspin.normalize_fingerprint(fp)
        except tlspin.PinError as exc:
            errors.append(str(exc))
    if url.startswith("https://") and not values["wg.mikrotik_fingerprint"] and not values["wg.mikrotik_verify_tls"]:
        errors.append("MikroTik-API: Zertifikats-Fingerabdruck hinterlegen („Abrufen“) oder die Prüfung über die "
                      "System-CAs aktivieren – sonst würden die Zugangsdaten ungeprüft übertragen.")
    if url.startswith("http://"):
        errors.append("MikroTik-API bitte über https (Dienst www-ssl) ansprechen – über http würden Benutzer und "
                      "Passwort unverschlüsselt übertragen.")
    for k in ("wg.local_iface", "wg.client_iface", "wg.mikrotik_interface"):
        if not wireguard.IFACE_RE.match(values[k] or ""):
            errors.append(f"Ungültiger Interface-Name: {values[k]}")
    if values["wg.router_public_key"] and not wireguard.valid_key(values["wg.router_public_key"]):
        errors.append("Der MikroTik-Public-Key ist ungültig.")
    ep = values["wg.endpoint"]
    if ep and (":" not in ep or not ep.rsplit(":", 1)[1].isdigit()):
        errors.append("Endpoint bitte als host:port angeben (z. B. vpn.example.com:13231).")
    if errors:
        for e in errors:
            flash(e, "danger")
        return redirect(url_for("wg.index"))
    for k, v in values.items():
        settings.set(g.db, k, v)
    if f.get("mikrotik_password"):
        settings.set(g.db, "wg.mikrotik_password", f["mikrotik_password"])
    settings.set(g.db, "wg.enabled", bool(f.get("enabled")))
    audit(g.db, g.user, "wg.settings", "", ip=client_ip())
    g.db.commit()
    flash("WireGuard-Einstellungen gespeichert.", "success")
    return redirect(url_for("wg.index"))


@bp.post("/test")
@admin_required
def test_api():
    try:
        mt = wireguard.api(g.db)
        res = mt.resource()
        ident = mt.identity()
        key = wireguard.router_public_key(g.db, refresh=True)
        g.db.commit()
        flash(f"Verbindung OK: {ident} - RouterOS {res.get('version', '?')} ({res.get('board-name', '')}). "
              f"WireGuard-Public-Key übernommen: {key[:12]}…", "success")
    except MikroTikError as exc:
        flash(str(exc), "danger")
    return redirect(url_for("wg.index", peers=0))


@bp.post("/self-peer")
@admin_required
def self_peer():
    """Create the peer of the servermanager itself on the MikroTik via API."""
    try:
        mt = wireguard.api(g.db)
        pub = wireguard.ensure_sm_keypair(g.db)
        iface = settings.get(g.db, "wg.mikrotik_interface")
        if any(p.get("public-key") == pub for p in mt.wg_peers(iface)):
            flash("Der Peer des Servermanagers existiert bereits.", "info")
        else:
            mt.add_peer(iface, pub, [f"{settings.get(g.db, 'wg.sm_ip')}/32"], "servermanager:self")
            flash("Peer für den Servermanager auf dem MikroTik angelegt.", "success")
        wireguard.router_public_key(g.db, refresh=True)
        g.db.commit()
    except MikroTikError as exc:
        flash(str(exc), "danger")
    return redirect(url_for("wg.index"))


@bp.post("/apply")
@admin_required
def apply():
    try:
        out = wireguard.apply_local(g.db)
        settings.set(g.db, "wg.enabled", True)
        audit(g.db, g.user, "wg.apply", settings.get(g.db, "wg.local_iface"), ip=client_ip())
        g.db.commit()
        flash("Tunnel-Konfiguration angewendet. " + out.strip()[:300], "success")
    except (ValueError, HelperError) as exc:
        flash(f"Tunnel konnte nicht aktiviert werden: {exc}", "danger")
    return redirect(url_for("wg.index"))


@bp.post("/regenerate-key")
@admin_required
def regenerate_key():
    priv, pub = wireguard.generate_keypair()
    settings.set(g.db, "wg.sm_private_key", priv)
    settings.set(g.db, "wg.sm_public_key", pub)
    audit(g.db, g.user, "wg.regenerate_key", "", ip=client_ip())
    g.db.commit()
    flash("Neues Schlüsselpaar erzeugt. Der Peer auf dem MikroTik muss mit dem neuen Public Key aktualisiert "
          "und der Tunnel neu angewendet werden.", "warning")
    return redirect(url_for("wg.index"))


@bp.post("/peers/remove")
@admin_required
def remove_peer():
    peer_id = request.form.get("peer_id", "")
    try:
        mt = wireguard.api(g.db)
        if mt.delete_checked("interface/wireguard/peers", peer_id, wireguard.COMMENT_PREFIX):
            flash("Peer entfernt.", "success")
            audit(g.db, g.user, "wg.peer_remove", peer_id, ip=client_ip())
            g.db.commit()
        else:
            flash("Peer nicht gefunden oder nicht vom Servermanager angelegt.", "warning")
    except MikroTikError as exc:
        flash(str(exc), "danger")
    return redirect(url_for("wg.index"))


@bp.post("/peers/recreate/<int:system_id>")
@admin_required
def recreate_peer(system_id: int):
    system = g.db.get(System, system_id)
    if system is None or not system.wg_public_key or not system.wg_ip:
        flash("System hat keinen WireGuard-Schlüssel.", "danger")
        return redirect(url_for("wg.index"))
    try:
        wireguard.update_peer_routes(g.db, system, system.routed_subnet_list)
        audit(g.db, g.user, "wg.peer_recreate", system.name, ip=client_ip())
        g.db.commit()
        flash(f"Peer für {system.name} neu angelegt.", "success")
    except (MikroTikError, ValueError) as exc:
        flash(str(exc), "danger")
    return redirect(url_for("wg.index"))
