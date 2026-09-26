"""Telephony: Asterisk/FreePBX status, trunks, extensions; SIP via port forwarding, web UI via Pangolin."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from sqlalchemy import select

from ... import access, integrations, pbx
from ...core import audit
from ...models import KIND_PBX, LEVEL_FULL, LEVEL_OPERATE, LEVEL_VIEW, PbxServer, RouterDevice, System
from ...ssh import SSHError
from ..auth import admin_required, client_ip, login_required
from . import _integration as common
from .mailcow import primary_pangolin

bp = Blueprint("pbx", __name__, url_prefix="/telefonie")
TABS = {"overview": "Übersicht", "extensions": "Nebenstellen", "trunks": "Trunks", "network": "SIP & Erreichbarkeit"}


def _get(pbx_id: int, level: str) -> PbxServer:
    return common.get_or_403(KIND_PBX, pbx_id, level)


def _system(p: PbxServer) -> System:
    system = g.db.get(System, p.system_id) if p.system_id else None
    if system is None:
        abort(400, description="Der Telefonanlage ist kein System (SSH) zugeordnet.")
    return system


@bp.get("/")
@login_required
def index():
    items = common.visible(KIND_PBX)
    if not items and not g.user.is_admin:
        abort(403)
    return render_template("pbx/index.html", items=items)


def _ip(value: str, label: str, errors: list) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        errors.append(f"{label}: ungültige IP-Adresse")
        return ""


def _port(value, label: str, errors: list, default=None):
    raw = str(value or "").strip()
    if not raw:
        return default
    if not raw.isdigit() or not 0 < int(raw) < 65536:
        errors.append(f"{label}: ungültiger Port")
        return default
    return int(raw)


def _save(p: PbxServer) -> list[str]:
    f = request.form
    errors: list[str] = []
    p.name = (f.get("name") or "").strip()[:128]
    if not p.name:
        errors.append("Bitte einen Namen angeben.")
    p.description = (f.get("description") or "").strip()[:2000]
    p.monitor = bool(f.get("monitor"))
    raw = f.get("system_id", "")
    system = g.db.get(System, int(raw)) if raw.isdigit() else None
    if system is None:
        errors.append("Bitte das System (SSH) der Telefonanlage wählen.")
    p.system_id = system.id if system else None
    web = (f.get("web_url") or "").strip().rstrip("/")
    if web and not re.match(r"^https?://[A-Za-z0-9.:\[\]-]+$", web):
        errors.append("Interne Weboberfläche als https://10.20.0.40 angeben.")
    p.web_url = web or (f"http://{system.host}" if system and re.match(r"^[0-9.]+$", system.host) else "")
    pub = (f.get("public_url") or "").strip().rstrip("/")
    if pub and not re.match(r"^https://[A-Za-z0-9.-]+(:\d+)?$", pub):
        errors.append("Öffentliche Adresse als https://pbx.example.com angeben.")
    p.public_url = pub
    p.sip_public_ip = _ip(f.get("sip_public_ip"), "SIP-Public-IP", errors)
    internal = f.get("sip_internal_ip") or (system.host if system else "")
    p.sip_internal_ip = _ip(internal, "Interne Adresse", errors) if re.match(r"^[0-9a-f.:]+$", internal or "") \
        else ""
    if not p.sip_internal_ip and f.get("router_id"):
        errors.append("Für die Portweiterleitung die interne IP-Adresse der Telefonanlage angeben.")
    p.sip_port = _port(f.get("sip_port"), "SIP-Port", errors, 5060)
    p.sip_tls_port = _port(f.get("sip_tls_port"), "SIP-TLS-Port", errors, None)
    p.rtp_start = _port(f.get("rtp_start"), "RTP-Start", errors, 10000)
    p.rtp_end = _port(f.get("rtp_end"), "RTP-Ende", errors, 20000)
    if p.rtp_start and p.rtp_end and p.rtp_start >= p.rtp_end:
        errors.append("RTP-Bereich: Start muss kleiner als Ende sein.")
    sources = [x for x in re.split(r"[,\s]+", f.get("sip_sources") or "") if x]
    for s in sources:
        try:
            ipaddress.ip_network(s, strict=False)
        except ValueError:
            errors.append(f"Erlaubte SIP-Gegenstellen: {s} ist keine IP-Adresse oder kein Netz")
    p.sip_sources = ", ".join(sources)
    raw = f.get("router_id", "")
    p.router_id = int(raw) if raw.isdigit() and g.db.get(RouterDevice, int(raw)) else None
    return errors


def _form(p: PbxServer, is_new: bool):
    systems = g.db.execute(select(System).order_by(System.name)).scalars().all()
    return render_template("pbx/form.html", p=p, is_new=is_new, systems=systems,
                           routers=g.db.execute(select(RouterDevice).order_by(RouterDevice.name)).scalars().all(),
                           suggested=[s for s in systems if s.has_type("asterisk")])


@bp.route("/new", methods=["GET", "POST"])
@admin_required
def new():
    p = PbxServer(monitor=True, sip_port=5060, rtp_start=10000, rtp_end=20000)
    if request.method == "GET" and request.args.get("system", "").isdigit():
        p.system_id = int(request.args["system"])
        s = g.db.get(System, p.system_id)
        if s is not None:
            p.name = s.name
    if request.method == "POST":
        errors = _save(p)
        if errors:
            for e in errors:
                flash(e, "danger")
            return _form(p, True)
        g.db.add(p)
        g.db.flush()
        audit(g.db, g.user, "pbx.create", p.name, ip=client_ip())
        integrations.poll(g.db, p)
        g.db.commit()
        flash("Telefonanlage angelegt." + (f" Status: {p.status_message}" if p.status_message else ""),
              "success" if not p.status_message else "warning")
        return redirect(url_for("pbx.detail", pbx_id=p.id))
    return _form(p, True)


@bp.route("/<int:pbx_id>/edit", methods=["GET", "POST"])
@admin_required
def edit(pbx_id: int):
    p = _get(pbx_id, LEVEL_FULL)
    if request.method == "POST":
        errors = _save(p)
        if errors:
            g.db.rollback()
            for e in errors:
                flash(e, "danger")
            return redirect(url_for("pbx.edit", pbx_id=pbx_id))
        audit(g.db, g.user, "pbx.update", p.name, ip=client_ip())
        integrations.poll(g.db, p)
        g.db.commit()
        flash("Gespeichert.", "success")
        return redirect(url_for("pbx.detail", pbx_id=p.id))
    return _form(p, False)


@bp.post("/<int:pbx_id>/delete")
@admin_required
def delete(pbx_id: int):
    p = _get(pbx_id, LEVEL_FULL)
    access.remove_integration(g.db, KIND_PBX, p.id)
    audit(g.db, g.user, "pbx.delete", p.name, ip=client_ip())
    g.db.delete(p)
    g.db.commit()
    flash("Telefonanlage entfernt (die Anlage selbst bleibt unverändert).", "warning")
    return redirect(url_for("pbx.index"))


def _publish_args(p: PbxServer) -> dict:
    parts = urlsplit(p.web_url or "")
    return {"name": f"Telefonanlage {p.name}", "ip": parts.hostname or "",
            "port": parts.port or (443 if parts.scheme == "https" else 80), "method": parts.scheme or "http",
            "sso": "1", "subdomain": (urlsplit(p.public_url).hostname or "").split(".")[0] if p.public_url else ""}


def network_checks(p: PbxServer, data: dict, wan_ip: str = "") -> list[dict]:
    """What Asterisk itself needs for SIP behind NAT (external address, local networks, RTP range)."""
    out = []
    nat = data.get("nat") or {}
    public = p.sip_public_ip or wan_ip
    ext = nat.get("external_media_address") or nat.get("external_signaling_address") or ""
    if not ext:
        out.append({"ok": False, "title": "Externe Adresse nicht gesetzt",
                    "detail": "FreePBX: Einstellungen → Asterisk SIP Settings → External Address"
                              + (f" = {public}" if public else "") + ", sonst kommt bei Gesprächen von außen kein "
                              "Ton an (einseitige Audio)."})
    elif public and ext != public:
        out.append({"ok": False, "title": f"Externe Adresse {ext} ≠ öffentliche SIP-Adresse {public}",
                    "detail": "External Address in den Asterisk SIP Settings anpassen."})
    else:
        out.append({"ok": True, "title": f"Externe Adresse {ext}"})
    if not nat.get("local_net"):
        out.append({"ok": False, "title": "Lokale Netze fehlen",
                    "detail": "Asterisk SIP Settings → Local Networks: das interne Netz (z. B. 10.20.0.0/24) "
                              "eintragen, damit interne Telefone nicht über die öffentliche Adresse laufen."})
    else:
        out.append({"ok": True, "title": f"Lokale Netze {nat.get('local_net')}"})
    rtp = data.get("rtp") or {}
    if rtp.get("start") and (rtp["start"], rtp["end"]) != (p.rtp_start, p.rtp_end):
        out.append({"ok": False, "title": f"RTP-Bereich der Anlage {rtp['start']}–{rtp['end']} ≠ "
                                          f"Weiterleitung {p.rtp_start}–{p.rtp_end}",
                    "detail": "Beides muss übereinstimmen (FreePBX: Asterisk SIP Settings → RTP Port Ranges)."})
    ports = {t["port"] for t in data.get("transports", [])}
    if ports and p.sip_port not in ports:
        out.append({"ok": False, "title": f"SIP-Port {p.sip_port} wird von Asterisk nicht verwendet",
                    "detail": f"Asterisk lauscht auf {', '.join(str(x) for x in sorted(ports))} – den Port der "
                              "Weiterleitung anpassen oder in den SIP Settings ändern."})
    if not p.source_list:
        out.append({"ok": False, "title": "SIP ist für alle Absender freigegeben",
                    "detail": "Offene SIP-Ports werden ständig gescannt. Unter „Bearbeiten“ die Adressen des "
                              "SIP-Providers als erlaubte Gegenstellen eintragen (Remote-Telefone dann per VPN)."})
    return out


@bp.get("/<int:pbx_id>")
@login_required
def detail(pbx_id: int):
    p = _get(pbx_id, LEVEL_VIEW)
    tab = request.args.get("tab", "overview")
    if tab not in TABS:
        tab = "overview"
    error = None
    data = p.data
    if request.args.get("live", "1") != "0":
        try:
            data = pbx.status(_system(p))
        except (SSHError, pbx.PbxError, OSError) as exc:
            error = f"Live-Abfrage fehlgeschlagen: {exc} – angezeigt wird der letzte Stand."
    system = g.db.get(System, p.system_id) if p.system_id else None
    router = g.db.get(RouterDevice, p.router_id) if p.router_id else None
    wan_ip = ""
    if router is not None:
        wan_ip = next((a["address"].split("/")[0] for a in (router.snapshot or {}).get("menus", {})
                       .get("ip/address", []) if a.get("interface") == (router.target_cfg or {}).get("wan_interface")),
                      "")
    return render_template("pbx/detail.html", p=p, d=data or {}, tab=tab, tabs=TABS, error=error, system=system,
                           router=router, publish=_publish_args(p), pangolin=primary_pangolin(),
                           checks=network_checks(p, data or {}, wan_ip), wan_ip=wan_ip)


ACTIONS = {"reload": LEVEL_OPERATE, "ext_add": LEVEL_FULL, "ext_delete": LEVEL_FULL, "ext_secret": LEVEL_OPERATE}


@bp.post("/<int:pbx_id>/do")
@login_required
def do(pbx_id: int):
    action = request.form.get("action", "")
    if action not in ACTIONS:
        abort(400)
    p = _get(pbx_id, ACTIONS[action])
    system = _system(p)
    f = request.form
    tab = "overview" if action == "reload" else "extensions"
    try:
        if action == "reload":
            from ... import inventory
            with inventory.connect(system, timeout=15) as conn:
                pbx.run(conn, "reload", timeout=300)
            msg, target = "Konfiguration neu geladen.", ""
        else:
            ext = (f.get("ext") or "").strip()
            secret = ""
            if action in ("ext_add", "ext_secret"):
                secret = (f.get("secret") or "").strip() or pbx.sip_secret()
            env = pbx.validate_extension(ext, (f.get("name") or "").strip(), secret,
                                         (f.get("email") or "").strip(), (f.get("pin") or "").strip())
            task = {"ext_add": "ext_add", "ext_delete": "ext_delete", "ext_secret": "ext_secret"}[action]
            pbx.extension_task(system, task, env)
            target = ext
            shown = "" if f.get("secret") else f" SIP-Passwort (wird nur jetzt angezeigt): {secret}"
            msg = {"ext_add": f"Nebenstelle {ext} angelegt.{shown}",
                   "ext_delete": f"Nebenstelle {ext} gelöscht.",
                   "ext_secret": f"Neues SIP-Passwort für {ext} gesetzt.{shown} Das Telefon muss neu "
                                 "eingerichtet werden."}[action]
        audit(g.db, g.user, f"pbx.{action}", p.name, target, ip=client_ip())
        g.db.commit()
        flash(msg, "success")
    except (pbx.PbxError, SSHError, OSError) as exc:
        flash(f"Fehlgeschlagen: {exc}", "danger")
    return redirect(url_for("pbx.detail", pbx_id=pbx_id, tab=tab))
