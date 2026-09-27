"""Zabbix: connection, problems, managed hosts (agent 2 via SSH), ticket webhook."""
from __future__ import annotations

import re
import secrets

from flask import Blueprint, abort, flash, g, jsonify, redirect, render_template, request, url_for
from sqlalchemy import select

from ... import access, integrations, security, settings, tickets
from ...core import audit
from ...jobs import enqueue
from ...models import KIND_ZABBIX, LEVEL_FULL, LEVEL_OPERATE, LEVEL_VIEW, System, ZabbixHost, ZabbixServer
from ...zabbix import SEVERITIES, ZabbixError
from ..auth import admin_required, client_ip, login_required, throttled
from . import _integration as common

bp = Blueprint("zabbix", __name__)
TABS = {"overview": "Übersicht", "problems": "Probleme", "hosts": "Hosts & Agenten", "tickets": "Ticket-Schnittstelle"}


def _get(zid: int, level: str) -> ZabbixServer:
    return common.get_or_403(KIND_ZABBIX, zid, level)


def _client(z: ZabbixServer):
    try:
        return integrations.zabbix_client(z)
    except (ZabbixError, ValueError) as exc:
        abort(400, description=f"Zabbix-Verbindung unvollständig: {exc}")


def webhook_url(z: ZabbixServer) -> str:
    base = settings.base_url(g.db)
    return f"{base}/api/zabbix/{z.id}/event" if base else ""


@bp.get("/zabbix/")
@login_required
def index():
    items = common.visible(KIND_ZABBIX)
    if not items and not g.user.is_admin:
        abort(403)
    return render_template("zabbix/index.html", items=items, severities=SEVERITIES)


def _save(z: ZabbixServer) -> list[str]:
    f = request.form
    url = (f.get("api_url") or "").strip()
    errors = common.save_common(z, f, 443)
    if url and not url.rstrip("/").endswith("api_jsonrpc.php"):
        z.api_url = url.rstrip("/")
    if f.get("token"):
        z.token_enc = security.encrypt(f["token"].strip())
    elif not z.token_enc:
        errors.append("API-Token angeben (Zabbix → Benutzer → API-Token).")
    srv = (f.get("agent_server") or "").strip()
    if srv and not re.match(r"^[A-Za-z0-9.:,_-]+$", srv):
        errors.append("Server-Adresse für die Agenten: IP-Adresse oder Name, mehrere mit Komma")
    z.agent_server = srv
    grp = (f.get("host_group") or "Servermanager").strip()
    if not re.match(r"^[^\x00-\x1f/]{1,128}$", grp):
        errors.append("Ungültiger Name der Host-Gruppe")
    z.host_group = grp
    try:
        z.min_severity = max(0, min(5, int(f.get("min_severity", "2"))))
    except ValueError:
        z.min_severity = 2
    z.tickets = bool(f.get("tickets"))
    mail = (f.get("ticket_mail") or "").strip()
    if mail and not all(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", m.strip()) for m in mail.split(",")):
        errors.append("Ticket-System: ungültige E-Mail-Adresse")
    z.ticket_mail = mail
    raw = f.get("zammad_id", "")
    from ...models import ZammadServer
    z.zammad_id = int(raw) if raw.isdigit() and g.db.get(ZammadServer, int(raw)) else None
    return errors


def _form(z: ZabbixServer, is_new: bool):
    from ...models import ZammadServer
    zammads = g.db.execute(select(ZammadServer).order_by(ZammadServer.name)).scalars().all()
    return render_template("zabbix/form.html", z=z, is_new=is_new, severities=SEVERITIES, zammads=zammads)


@bp.route("/zabbix/new", methods=["GET", "POST"])
@admin_required
def new():
    z = ZabbixServer(monitor=True, verify_ca=True, host_group="Servermanager", min_severity=2, tickets=True)
    if request.method == "POST":
        errors = _save(z)
        if request.form.get("fetch_fp"):
            fp, err = common.fetch_fp_from_form(443)
            flash(err or "Fingerabdruck abgerufen – bitte vergleichen und speichern.", "danger" if err else "info")
            z.fingerprint = fp or z.fingerprint
            return _form(z, True)
        if errors:
            for e in errors:
                flash(e, "danger")
            return _form(z, True)
        g.db.add(z)
        g.db.flush()
        audit(g.db, g.user, "zabbix.create", z.name, z.api_url, ip=client_ip())
        integrations.poll(g.db, z)
        g.db.commit()
        flash("Zabbix-Verbindung angelegt. Nächster Schritt: unter „Ticket-Schnittstelle“ einrichten und unter "
              "„Hosts & Agenten“ die Systeme aufnehmen.", "success")
        return redirect(url_for("zabbix.detail", zid=z.id, tab="tickets"))
    return _form(z, True)


@bp.route("/zabbix/<int:zid>/edit", methods=["GET", "POST"])
@admin_required
def edit(zid: int):
    z = _get(zid, LEVEL_FULL)
    if request.method == "POST":
        if request.form.get("fetch_fp"):
            g.db.expunge(z)
            _save(z)
            fp, err = common.fetch_fp_from_form(443)
            flash(err or "Fingerabdruck abgerufen.", "danger" if err else "info")
            z.fingerprint = fp or z.fingerprint
            return _form(z, False)
        errors = _save(z)
        if errors:
            g.db.rollback()
            for e in errors:
                flash(e, "danger")
            return redirect(url_for("zabbix.edit", zid=zid))
        audit(g.db, g.user, "zabbix.update", z.name, ip=client_ip())
        integrations.poll(g.db, z)
        g.db.commit()
        flash("Gespeichert.", "success")
        return redirect(url_for("zabbix.detail", zid=z.id))
    return _form(z, False)


@bp.post("/zabbix/<int:zid>/delete")
@admin_required
def delete(zid: int):
    z = _get(zid, LEVEL_FULL)
    access.remove_integration(g.db, KIND_ZABBIX, z.id)
    audit(g.db, g.user, "zabbix.delete", z.name, ip=client_ip())
    g.db.delete(z)
    g.db.commit()
    flash("Zabbix-Verbindung entfernt (Zabbix selbst und die Tickets bleiben erhalten).", "warning")
    return redirect(url_for("zabbix.index"))


@bp.get("/zabbix/<int:zid>")
@login_required
def detail(zid: int):
    z = _get(zid, LEVEL_VIEW)
    tab = request.args.get("tab", "overview")
    if tab not in TABS:
        tab = "overview"
    ctx: dict = {"z": z, "tab": tab, "tabs": TABS, "error": None, "problems": [], "rows": [],
                 "severities": SEVERITIES, "webhook_url": webhook_url(z)}
    if tab in ("problems", "hosts"):
        try:
            zx = _client(z)
            if tab == "problems":
                ctx["problems"] = zx.problems(0)
            else:
                ctx["rows"] = _host_rows(z, zx.hosts())
        except ZabbixError as exc:
            ctx["error"] = str(exc)
            if tab == "hosts":
                ctx["rows"] = _host_rows(z, [])
    return render_template("zabbix/detail.html", **ctx)


def _host_rows(z: ZabbixServer, zhosts: list[dict]) -> list[dict]:
    by_host = {h["host"]: h for h in zhosts}
    by_id = {h["hostid"]: h for h in zhosts}
    managed = {m.system_id: m for m in g.db.execute(select(ZabbixHost).where(ZabbixHost.zabbix_id == z.id)).scalars()}
    ids = access.accessible_system_ids(g.db, g.user)
    rows = []
    for s in g.db.execute(select(System).order_by(System.name)).scalars():
        if ids is not None and s.id not in ids:
            continue
        m = managed.get(s.id)
        h = (by_id.get(m.hostid) if m and m.hostid else None) or by_host.get(s.name)
        rows.append({"system": s, "managed": m, "host": h})
    return rows


@bp.post("/zabbix/<int:zid>/agent")
@login_required
def agent(zid: int):
    """Set up agent 2 + Zabbix host for the selected systems (job per system)."""
    z = _get(zid, LEVEL_FULL)
    ids = [int(x) for x in request.form.getlist("system") if x.isdigit()]
    if not ids:
        flash("Keine Systeme ausgewählt.", "warning")
        return redirect(url_for("zabbix.detail", zid=zid, tab="hosts"))
    if not z.agent_server:
        flash("Zuerst unter „Bearbeiten“ die Adresse eintragen, unter der die Agenten den Zabbix-Server erreichen.",
              "danger")
        return redirect(url_for("zabbix.detail", zid=zid, tab="hosts"))
    jobs = []
    for sid in ids:
        system = g.db.get(System, sid)
        if system is None or access.system_level(g.db, g.user, sid) != LEVEL_FULL:
            continue
        ip = (request.form.get(f"ip_{sid}") or "").strip()
        if ip and not re.match(r"^[0-9a-fA-F.:]+$", ip):
            flash(f"{system.name}: ungültige Adresse {ip}", "danger")
            continue
        jobs.append(enqueue(g.db, kind="zabbix_agent", title=f"Zabbix-Agent: {system.name}", system=system,
                            user=g.user, payload={"zabbix_id": z.id, "ip": ip}))
    audit(g.db, g.user, "zabbix.agent", z.name, ",".join(str(j.system_id) for j in jobs), ip=client_ip())
    g.db.commit()
    if len(jobs) == 1:
        return redirect(url_for("jobs.detail", job_id=jobs[0].id))
    flash(f"{len(jobs)} Job(s) gestartet.", "success")
    return redirect(url_for("jobs.index"))


@bp.post("/zabbix/<int:zid>/webhook")
@admin_required
def setup_webhook(zid: int):
    """Create a new webhook token and set up media type, user group, user and action in Zabbix."""
    z = _get(zid, LEVEL_FULL)
    url = webhook_url(z)
    if not url:
        flash("Zuerst unter Einstellungen → Allgemein die öffentliche URL des Servermanagers setzen – Zabbix "
              "muss sie erreichen können.", "danger")
        return redirect(url_for("zabbix.detail", zid=zid, tab="tickets"))
    token = secrets.token_urlsafe(32)
    try:
        result = _client(z).setup_webhook(url, token, z.min_severity)
    except ZabbixError as exc:
        flash(f"Einrichtung fehlgeschlagen: {exc}", "danger")
        return redirect(url_for("zabbix.detail", zid=zid, tab="tickets"))
    z.webhook_hash = tickets.token_hash(token)
    z.setup = dict(result, url=url, at=integrations.utcnow().isoformat(timespec="minutes"))
    audit(g.db, g.user, "zabbix.webhook", z.name, url, ip=client_ip())
    g.db.commit()
    flash("Ticket-Schnittstelle in Zabbix eingerichtet (Medientyp, Benutzer, Aktion). Neue Probleme kommen ab "
          "jetzt sofort als Ticket an.", "success")
    return redirect(url_for("zabbix.detail", zid=zid, tab="tickets"))


@bp.post("/zabbix/<int:zid>/sync")
@login_required
def sync(zid: int):
    z = _get(zid, LEVEL_OPERATE)
    integrations.poll(g.db, z)
    g.db.commit()
    if z.status_message:
        flash(z.status_message, "danger")
    else:
        flash(f"Abgeglichen: {z.data.get('problems', 0)} offene Probleme"
              + (f", {z.data.get('tickets_created')} neue Tickets" if z.data.get("tickets_created") else "") + ".",
              "success")
    return redirect(common.safe_next(url_for("zabbix.detail", zid=zid)))


# --------------------------------------------------------------------------
# webhook (called by the Zabbix media type)
# --------------------------------------------------------------------------
@bp.post("/api/zabbix/<int:zid>/event")
def event(zid: int):
    ip = client_ip()
    if throttled(ip, limit=20):
        return jsonify({"error": "zu viele Anfragen"}), 429
    z = g.db.get(ZabbixServer, zid)
    auth = request.headers.get("Authorization", "")
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    if z is None or not tickets.token_ok(z, token):
        from ..auth import record_failure
        record_failure(ip)
        return jsonify({"error": "nicht berechtigt"}), 403
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "JSON erwartet"}), 400
    try:
        result = tickets.handle_event(g.db, z, {k: str(v)[:5000] for k, v in data.items()})
    except ValueError as exc:
        g.db.rollback()
        return jsonify({"error": str(exc)}), 400
    g.db.commit()
    return jsonify({"ok": True, **result})
