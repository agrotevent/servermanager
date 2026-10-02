"""RouterOS (e.g. CHR) via REST API: overview, DHCP, NAT, routing, DNS, configuration analysis."""
from __future__ import annotations

import ipaddress
import re

from flask import Blueprint, Response, abort, flash, g, redirect, render_template, request, url_for

from ... import access, integrations, routeros, security, settings
from ...core import audit
from ...mikrotik import MikroTikError
from ...models import KIND_ROUTER, LEVEL_FULL, LEVEL_OPERATE, LEVEL_VIEW, PveServer, RouterDevice, utcnow
from ..auth import admin_required, client_ip, login_required
from . import _integration as common

bp = Blueprint("routers", __name__, url_prefix="/routeros")

ID_RE = re.compile(r"^\*[0-9A-Fa-f]{1,8}$")
MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")
NAME_RE = re.compile(r"^[A-Za-z0-9._<>-]{1,64}$")
DNSNAME_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9*_-]{1,63}(\.[A-Za-z0-9_-]{1,63})*$")
PORTS_RE = re.compile(r"^[0-9]{1,5}(-[0-9]{1,5})?(,[0-9]{1,5}(-[0-9]{1,5})?)*$")
TABS = {"overview": "Übersicht", "devices": "Geräte", "dhcp": "DHCP", "nat": "NAT", "routing": "Routing & Mangle",
        "firewall": "Firewall", "dns": "DNS", "analysis": "Konfigurationsanalyse"}


def _get(router_id: int, level: str) -> RouterDevice:
    return common.get_or_403(KIND_ROUTER, router_id, level)


def _mt(router: RouterDevice, timeout: int = 15):
    try:
        return integrations.router_client(router, timeout=timeout)
    except (MikroTikError, ValueError) as exc:
        abort(400, description=f"RouterOS-Verbindung unvollständig: {exc}")


def _ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address((value or "").strip()))
    except ValueError:
        raise ValueError(f"Ungültige IP-Adresse: {value}") from None


def _net(value: str) -> str:
    try:
        return str(ipaddress.ip_network((value or "").strip(), strict=False))
    except ValueError:
        raise ValueError(f"Ungültiges Netz: {value}") from None


def _comment(value: str) -> str:
    return re.sub(r"[\r\n\t]", " ", value or "").strip()[:200]


# --------------------------------------------------------------------------
# list / CRUD
# --------------------------------------------------------------------------
@bp.get("/")
@login_required
def index():
    routers = common.visible(KIND_ROUTER)
    if not routers and not g.user.is_admin:
        abort(403)
    return render_template("routers/index.html", routers=routers)


def _save(router: RouterDevice) -> list[str]:
    f = request.form
    errors = common.save_common(router, f, 443)
    router.username = (f.get("username") or "").strip()[:64]
    if not router.username:
        errors.append("Benutzername angeben.")
    if f.get("password"):
        router.password_enc = security.encrypt(f["password"])
    elif not router.password_enc:
        errors.append("Passwort angeben.")
    if router.api_url.startswith("http://"):
        flash("Achtung: unverschlüsselte Verbindung (http) – Zugangsdaten gehen im Klartext über das Netz. "
              "Nur über einen Tunnel verwenden.", "warning")
    return errors


def _form(router: RouterDevice, is_new: bool):
    allowed = request.form.get("allowed") if request.method == "POST" and "allowed" in request.form else None
    if allowed is None:
        allowed = settings.get(g.db, "wg.network") if settings.get(g.db, "wg.enabled") else ""
        if not allowed and router.api_url:
            src = integrations.source_ip_for(router.api_url)
            allowed = f"{src}/32" if src and ":" not in src else src
    return render_template("routers/form.html", r=router, is_new=is_new, allowed_default=allowed,
                           source_ip=integrations.source_ip_for(router.api_url) if router.api_url else "")


@bp.route("/new", methods=["GET", "POST"])
@admin_required
def new():
    router = RouterDevice(monitor=True, verify_ca=False, username="")
    if request.method == "POST":
        errors = _save(router)
        if request.form.get("fetch_fp"):
            fp, err = common.fetch_fp_from_form(443)
            flash(err or "Fingerabdruck abgerufen – bitte mit dem Zertifikat im Router vergleichen "
                         "(/certificate print detail) und speichern.", "danger" if err else "info")
            router.fingerprint = fp or router.fingerprint
            return _form(router, True)
        if errors:
            for e in errors:
                flash(e, "danger")
            return _form(router, True)
        # test the login before anything is stored
        try:
            integrations.router_client(router).identity()
            login_ok = True
        except MikroTikError as exc:
            login_ok = False
            if not request.form.get("save_anyway"):
                flash(f"{exc}. " + (integrations.router_login_hint(router) if exc.status == 401 else ""), "danger")
                return _form(router, True)
        if login_ok and request.form.get("create_api_user"):
            from ... import mgmt
            admin_user, admin_pw = router.username, security.decrypt(router.password_enc)
            try:
                mgmt.router_mgmt_user(router, admin_user, admin_pw, request.form.get("allowed", ""),
                                      with_backup=bool(request.form.get("with_backup")))
                flash(f"API-Benutzer „{router.username}“ angelegt – der Admin-Zugang wurde nicht gespeichert.",
                      "success")
            except mgmt.MgmtError as exc:
                router.username = admin_user
                router.password_enc = security.encrypt(admin_pw)
                flash(f"API-Benutzer konnte nicht angelegt werden: {exc}. {integrations.router_login_hint(router)}",
                      "danger")
                return _form(router, True)
        g.db.add(router)
        g.db.flush()
        audit(g.db, g.user, "router.create", router.name, router.api_url, ip=client_ip())
        integrations.poll(g.db, router)
        g.db.commit()
        flash("RouterOS-Verbindung angelegt. Tipp: unter „Konfigurationsanalyse“ die laufende Konfiguration "
              "importieren und prüfen.", "success" if login_ok else "warning")
        return redirect(url_for("routers.detail", router_id=router.id))
    return _form(router, True)


@bp.route("/<int:router_id>/edit", methods=["GET", "POST"])
@admin_required
def edit(router_id: int):
    router = _get(router_id, LEVEL_FULL)
    if request.method == "POST":
        if request.form.get("fetch_fp"):
            g.db.expunge(router)
            _save(router)
            fp, err = common.fetch_fp_from_form(443)
            flash(err or "Fingerabdruck abgerufen – bitte vergleichen und speichern.", "danger" if err else "info")
            router.fingerprint = fp or router.fingerprint
            return _form(router, False)
        errors = _save(router)
        if errors:
            g.db.rollback()
            for e in errors:
                flash(e, "danger")
            return redirect(url_for("routers.edit", router_id=router_id))
        audit(g.db, g.user, "router.update", router.name, ip=client_ip())
        integrations.poll(g.db, router)
        g.db.commit()
        flash("Gespeichert.", "success")
        return redirect(url_for("routers.detail", router_id=router.id))
    return _form(router, False)


@bp.post("/<int:router_id>/delete")
@admin_required
def delete(router_id: int):
    router = _get(router_id, LEVEL_FULL)
    for srv in g.db.query(PveServer).filter(PveServer.router_id == router.id):
        srv.router_id = None
    access.remove_integration(g.db, KIND_ROUTER, router.id)
    audit(g.db, g.user, "router.delete", router.name, ip=client_ip())
    g.db.delete(router)
    g.db.commit()
    flash("RouterOS-Verbindung entfernt (die Konfiguration des Routers bleibt unverändert).", "warning")
    return redirect(url_for("routers.index"))


@bp.post("/<int:router_id>/mgmt-user")
@admin_required
def mgmt_user(router_id: int):
    """Create a dedicated API user with a one-time admin login (the admin password is not stored)."""
    from ... import mgmt
    router = _get(router_id, LEVEL_FULL)
    f = request.form
    try:
        name = mgmt.router_mgmt_user(router, f.get("admin_user", "").strip(), f.get("admin_password", ""),
                                     f.get("allowed", ""), with_backup=bool(f.get("with_backup")))
    except mgmt.MgmtError as exc:
        g.db.rollback()
        flash(f"API-Benutzer konnte nicht angelegt werden: {exc}", "danger")
        return redirect(url_for("routers.edit", router_id=router_id))
    audit(g.db, g.user, "router.mgmt_user", router.name, name, ip=client_ip())
    integrations.poll(g.db, router)
    g.db.commit()
    flash(f"API-Benutzer „{name}“ mit zufälligem Passwort angelegt und hinterlegt. Das Admin-Passwort wurde nicht "
          "gespeichert.", "success")
    return redirect(url_for("routers.detail", router_id=router_id))


@bp.post("/<int:router_id>/refresh")
@login_required
def refresh(router_id: int):
    router = _get(router_id, LEVEL_VIEW)
    integrations.poll(g.db, router)
    g.db.commit()
    return redirect(url_for("routers.detail", router_id=router_id, tab=request.form.get("tab", "overview")))


# --------------------------------------------------------------------------
# detail
# --------------------------------------------------------------------------
TAB_MENUS = {
    "overview": ["interface", "ip/address", "ip/route", "ip/dhcp-client"],
    "dhcp": ["ip/dhcp-server", "ip/dhcp-server/network", "ip/dhcp-server/lease", "ip/pool"],
    "nat": ["ip/firewall/nat", "interface"],
    "routing": ["ip/route", "routing/table", "routing/rule", "ip/firewall/mangle"],
    "firewall": ["ip/firewall/filter", "ip/firewall/address-list"],
    "dns": ["ip/dns", "ip/dns/static"],
}


@bp.get("/<int:router_id>")
@login_required
def detail(router_id: int):
    router = _get(router_id, LEVEL_VIEW)
    tab = request.args.get("tab", "overview")
    if tab not in TABS:
        tab = "overview"
    ctx: dict = {"r": router, "tab": tab, "tabs": TABS, "d": {}, "error": None}
    if tab == "analysis":
        ctx.update(_analysis_ctx(router))
    elif tab == "devices":
        from ... import discovery
        try:
            ctx["devices"] = discovery.router_devices(g.db, router)
        except (MikroTikError, ValueError) as exc:
            ctx["error"] = str(exc)
    else:
        try:
            mt = _mt(router)
            for menu in TAB_MENUS[tab]:
                res = mt._req("GET", menu)
                ctx["d"][menu] = [res] if isinstance(res, dict) else (res or [])
        except MikroTikError as exc:
            ctx["error"] = str(exc)
    if tab == "overview" and request.args.get("live") != "0":
        integrations.poll(g.db, router)
        g.db.commit()
    return render_template("routers/detail.html", **ctx)


# --------------------------------------------------------------------------
# item actions
# --------------------------------------------------------------------------
ACTIONS = {
    "lease_static": LEVEL_OPERATE, "lease_comment": LEVEL_OPERATE, "lease_delete": LEVEL_FULL,
    "lease_add": LEVEL_FULL, "nat_toggle": LEVEL_OPERATE, "nat_delete": LEVEL_FULL, "nat_add": LEVEL_FULL,
    "dns_add": LEVEL_FULL, "dns_delete": LEVEL_FULL, "route_add": LEVEL_FULL, "route_delete": LEVEL_FULL,
    "ping": LEVEL_OPERATE,
}


@bp.post("/<int:router_id>/do")
@login_required
def do(router_id: int):
    action = request.form.get("action", "")
    if action not in ACTIONS:
        abort(400)
    router = _get(router_id, ACTIONS[action])
    f = request.form
    tab = {"lease": "dhcp", "nat": "nat", "dns": "dns", "route": "routing", "ping": "overview"}[action.split("_")[0]]
    item_id = f.get("id", "")
    needs_id = action in ("lease_static", "lease_comment", "lease_delete", "nat_toggle", "nat_delete",
                          "dns_delete", "route_delete")
    if (needs_id or "id" in f) and not ID_RE.match(item_id):
        abort(400)
    mt = _mt(router)
    try:
        msg = _do(mt, action, item_id, f)
        audit(g.db, g.user, f"router.{action}", router.name, (item_id + " " + msg)[:300], ip=client_ip())
        g.db.commit()
        flash(msg, "success")
    except (ValueError, MikroTikError) as exc:
        flash(f"Fehlgeschlagen: {exc}", "danger")
    return redirect(url_for("routers.detail", router_id=router_id, tab=tab))


def _do(mt, action: str, item_id: str, f) -> str:
    if action == "lease_static":
        mt.command("ip/dhcp-server/lease/make-static", {".id": item_id})
        if f.get("comment"):
            mt.patch("ip/dhcp-server/lease", item_id, {"comment": _comment(f["comment"])})
        return "Lease ist jetzt statisch."
    if action == "lease_comment":
        mt.patch("ip/dhcp-server/lease", item_id, {"comment": _comment(f.get("comment", ""))})
        return "Kommentar gespeichert."
    if action == "lease_delete":
        mt.delete("ip/dhcp-server/lease", item_id)
        return "Lease gelöscht."
    if action == "lease_add":
        mac = (f.get("mac") or "").strip().upper()
        if not MAC_RE.match(mac):
            raise ValueError("Ungültige MAC-Adresse")
        data = {"address": _ip(f.get("address", "")), "mac-address": mac, "comment": _comment(f.get("comment"))}
        server = (f.get("server") or "").strip()
        if server:
            if not NAME_RE.match(server):
                raise ValueError("Ungültiger DHCP-Server")
            data["server"] = server
        mt.create("ip/dhcp-server/lease", data)
        return f"Statische Lease {data['address']} angelegt."
    if action == "nat_toggle":
        disabled = "yes" if f.get("disabled") == "yes" else "no"
        mt.patch("ip/firewall/nat", item_id, {"disabled": disabled})
        return "Regel deaktiviert." if disabled == "yes" else "Regel aktiviert."
    if action == "nat_delete":
        mt.delete("ip/firewall/nat", item_id)
        return "NAT-Regel gelöscht."
    if action == "nat_add":
        proto = f.get("protocol", "tcp")
        if proto not in ("tcp", "udp"):
            raise ValueError("Protokoll tcp oder udp")
        dport = (f.get("dst_port") or "").strip()
        if not PORTS_RE.match(dport):
            raise ValueError("Ungültiger Port")
        iface = (f.get("in_interface") or "").strip()
        if not NAME_RE.match(iface):
            raise ValueError("Eingangs-Interface wählen")
        data = {"chain": "dstnat", "action": "dst-nat", "protocol": proto, "dst-port": dport,
                "in-interface": iface, "to-addresses": _ip(f.get("to_address", "")),
                "comment": "servermanager: " + (_comment(f.get("comment")) or f"Port {dport}")}
        to_ports = (f.get("to_ports") or "").strip()
        if to_ports:
            if not PORTS_RE.match(to_ports):
                raise ValueError("Ungültiger Ziel-Port")
            data["to-ports"] = to_ports
        mt.create("ip/firewall/nat", data)
        return f"Portweiterleitung {proto}/{dport} → {data['to-addresses']} angelegt."
    if action == "dns_add":
        name = (f.get("name") or "").strip().lower()
        if not DNSNAME_RE.match(name):
            raise ValueError("Ungültiger DNS-Name")
        mt.create("ip/dns/static", {"name": name, "address": _ip(f.get("address", "")),
                                    "comment": "servermanager: " + _comment(f.get("comment"))})
        return f"DNS-Eintrag {name} angelegt."
    if action == "dns_delete":
        mt.delete("ip/dns/static", item_id)
        return "DNS-Eintrag gelöscht."
    if action == "route_add":
        data = {"dst-address": _net(f.get("dst", "")), "gateway": _ip(f.get("gateway", "")),
                "comment": "servermanager: " + _comment(f.get("comment"))}
        table = (f.get("table") or "").strip()
        if table and table != "main":
            if not re.match(r"^[A-Za-z0-9_-]{1,32}$", table):
                raise ValueError("Ungültige Routing-Tabelle")
            data["routing-table"] = table
        mt.create("ip/route", data)
        return f"Route {data['dst-address']} via {data['gateway']} angelegt."
    if action == "route_delete":
        mt.delete("ip/route", item_id)
        return "Route gelöscht."
    if action == "ping":
        target = _ip(f.get("address", "") or "1.1.1.1")
        data = {"address": target, "count": "3"}
        if f.get("src"):
            data["src-address"] = _ip(f["src"])
        res = routeros.ping_result(mt.command("ping", data, timeout=30) or [])
        sent, recv = res["sent"], res["received"]
        via = f" (Quelle {data['src-address']})" if "src-address" in data else ""
        if recv in ("0", ""):
            why = ", ".join(routeros.PING_STATUS.get(x, x) for x in res["statuses"])
            hints = routeros.ping_diagnosis(mt, target, data.get("src-address", ""))
            raise ValueError(f"Keine Antwort von {target}{via} – {sent} gesendet" + (f" ({why})" if why else "")
                             + (". " + " ".join(hints) if hints else ""))
        return f"Ping {target}{via}: {recv}/{sent} Antworten, Ø {res['avg']}"
    raise ValueError("Unbekannte Aktion")


# --------------------------------------------------------------------------
# configuration analysis
# --------------------------------------------------------------------------
def _analysis_ctx(router: RouterDevice) -> dict:
    snap = router.snapshot or {}
    target = router.target_cfg
    findings = routeros.analyze(snap, target) if snap.get("menus") and target else []
    return {"snap": snap, "target": target, "findings": findings, "summary": routeros.summarize(findings),
            "areas": routeros.AREAS, "status_labels": routeros.STATUS_LABELS}


@bp.post("/<int:router_id>/import")
@login_required
def import_config(router_id: int):
    router = _get(router_id, LEVEL_FULL)
    source = request.form.get("source", "api")
    try:
        if source == "export":
            text = request.form.get("export", "")
            upload = request.files.get("export_file")
            if upload and upload.filename:
                text = upload.read(4 * 1024 * 1024).decode("utf-8", "replace")
            if "/" not in text:
                raise ValueError("Bitte die Ausgabe von /export einfügen oder als Datei hochladen.")
            snap = routeros.parse_export(text)
        else:
            snap = routeros.snapshot_from_api(_mt(router, timeout=30))
    except (ValueError, MikroTikError) as exc:
        flash(f"Import fehlgeschlagen: {exc}", "danger")
        return redirect(url_for("routers.detail", router_id=router_id, tab="analysis"))
    router.snapshot = snap
    router.snapshot_at = utcnow()
    router.snapshot_source = snap["source"]
    if not router.target_cfg or request.form.get("redetect"):
        mgmt = ",".join(x for x in [settings.get(g.db, "wg.network") if settings.get(g.db, "wg.enabled") else ""] if x)
        router.target = routeros.detect_target(snap, mgmt)
    audit(g.db, g.user, "router.import", router.name, snap["source"], ip=client_ip())
    g.db.commit()
    errs = snap.get("errors") or {}
    flash(f"Konfiguration importiert ({'API' if snap['source'] == 'api' else 'Export'})."
          + (f" {len(errs)} Menü(s) nicht lesbar (Rechte?)." if errs else ""), "warning" if errs else "success")
    return redirect(url_for("routers.detail", router_id=router_id, tab="analysis"))


@bp.post("/<int:router_id>/target")
@login_required
def save_target(router_id: int):
    router = _get(router_id, LEVEL_FULL)
    keys = ["wan_interface", "lan_interface", "lan_address", "dhcp_range", "dns_servers", "routing_table",
            "mgmt_addresses", "ntp_servers"]
    t = {k: (request.form.get(k) or "").strip() for k in keys}
    t["policy_routing"] = bool(request.form.get("policy_routing"))
    t["mss_clamp"] = bool(request.form.get("mss_clamp"))
    t, errors = routeros.validate_target(t)
    if errors:
        for e in errors:
            flash(e, "danger")
    else:
        router.target = t
        audit(g.db, g.user, "router.target", router.name, ip=client_ip())
        g.db.commit()
        flash("Sollwerte gespeichert – Analyse aktualisiert.", "success")
    return redirect(url_for("routers.detail", router_id=router_id, tab="analysis"))


@bp.get("/<int:router_id>/script.rsc")
@login_required
def script(router_id: int):
    router = _get(router_id, LEVEL_VIEW)
    ctx = _analysis_ctx(router)
    only = set(request.args.getlist("id"))
    findings = [f for f in ctx["findings"] if not only or f["id"] in only]
    text = routeros.full_script(findings)
    return Response(text, mimetype="text/plain",
                    headers={"Content-Disposition": f'attachment; filename="{re.sub(r"[^A-Za-z0-9_-]", "_", router.name)}-servermanager.rsc"'})


@bp.post("/<int:router_id>/apply")
@login_required
def apply(router_id: int):
    router = _get(router_id, LEVEL_FULL)
    selected = set(request.form.getlist("fid"))
    if not selected:
        flash("Keine Änderungen ausgewählt.", "warning")
        return redirect(url_for("routers.detail", router_id=router_id, tab="analysis"))
    mt = _mt(router, timeout=30)
    log: list[str] = []
    try:
        # always work on the live configuration, never on an older import
        snap = routeros.snapshot_from_api(mt)
        findings = [f for f in routeros.analyze(snap, router.target_cfg) if f["id"] in selected and f["applicable"]]
        if not findings:
            flash("Die ausgewählten Punkte sind inzwischen erledigt oder nicht automatisch anwendbar.", "info")
            router.snapshot, router.snapshot_source = snap, "api"
            g.db.commit()
            return redirect(url_for("routers.detail", router_id=router_id, tab="analysis"))
        if not request.form.get("skip_backup"):
            name = routeros.backup_before_change(mt)
            log.append(f"Sicherung auf dem Router: {name}.backup")
        ops = routeros.unique_ops(op for f in findings for op in f["ops"])
        done = routeros.apply_ops(mt, ops, log.append)
        router.snapshot = routeros.snapshot_from_api(mt)
        router.snapshot_source = "api"
        router.snapshot_at = utcnow()
        audit(g.db, g.user, "router.apply", router.name, "\n".join(log)[:2000], ip=client_ip())
        g.db.commit()
        flash(f"{done} Änderung(en) angewendet ({', '.join(f['title'] for f in findings)}).", "success")
    except (MikroTikError, routeros.RouterOSError) as exc:
        audit(g.db, g.user, "router.apply_failed", router.name, ("\n".join(log) + f"\n{exc}")[:2000], ip=client_ip())
        g.db.commit()
        flash(f"Abbruch: {exc}" + (f" – bereits angewendet: {len(log)} Schritt(e), siehe Audit-Log" if log else ""),
              "danger")
    return redirect(url_for("routers.detail", router_id=router_id, tab="analysis"))
