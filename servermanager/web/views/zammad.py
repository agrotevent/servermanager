"""Zammad: connection, ticket sync and the webhook for changes made in Zammad."""
from __future__ import annotations

import re
import secrets

from flask import Blueprint, abort, flash, g, jsonify, redirect, render_template, request, url_for
from sqlalchemy import select

from ... import access, integrations, security, settings, tickets
from ...core import audit
from ...models import (KIND_ZAMMAD, LEVEL_FULL, LEVEL_OPERATE, LEVEL_VIEW, TICKET_STATUSES, Ticket, ZabbixServer,
                       ZammadServer)
from ...zammad import ZammadError, normalize_url, signature_ok
from ..auth import admin_required, client_ip, login_required, record_failure, throttled
from . import _integration as common

bp = Blueprint("zammad", __name__)
TABS = {"overview": "Übersicht", "tickets": "Tickets", "setup": "Rückmeldung (Webhook)"}


def _get(zid: int, level: str) -> ZammadServer:
    return common.get_or_403(KIND_ZAMMAD, zid, level)


def webhook_url(z: ZammadServer) -> str:
    base = settings.base_url(g.db)
    return f"{base}/api/zammad/{z.id}/webhook" if base else ""


@bp.get("/zammad/")
@login_required
def index():
    items = common.visible(KIND_ZAMMAD)
    if not items and not g.user.is_admin:
        abort(403)
    return render_template("zammad/index.html", items=items)


def _save(z: ZammadServer) -> list[str]:
    f = request.form
    errors = common.save_common(z, f, 443)
    try:
        z.api_url = normalize_url(f.get("api_url", ""))
    except ZammadError as exc:
        errors.append(str(exc))
    if f.get("token"):
        z.token_enc = security.encrypt(f["token"].strip())
    elif not z.token_enc:
        errors.append("API-Token angeben (Zammad → Profil → Token-Zugriff, Berechtigung ticket.agent).")
    z.group_name = (f.get("group_name") or "Users").strip()[:128]
    customer = (f.get("customer") or "").strip().lower()
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", customer):
        errors.append("Kunde der Tickets: E-Mail-Adresse angeben (wird in Zammad bei Bedarf angelegt).")
    z.customer = customer
    z.close_on_resolve = bool(f.get("close_on_resolve"))
    return errors


def _form(z: ZammadServer, is_new: bool):
    zabbix = g.db.execute(select(ZabbixServer).order_by(ZabbixServer.name)).scalars().all()
    return render_template("zammad/form.html", z=z, is_new=is_new, zabbix=zabbix)


def _link_zabbix(z: ZammadServer) -> None:
    ids = {int(x) for x in request.form.getlist("zabbix") if x.isdigit()}
    for zbx in g.db.execute(select(ZabbixServer)).scalars():
        if zbx.id in ids:
            zbx.zammad_id = z.id
        elif zbx.zammad_id == z.id:
            zbx.zammad_id = None


@bp.route("/zammad/new", methods=["GET", "POST"])
@admin_required
def new():
    z = ZammadServer(monitor=True, verify_ca=True, group_name="Users", close_on_resolve=False)
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
        _link_zabbix(z)
        audit(g.db, g.user, "zammad.create", z.name, z.api_url, ip=client_ip())
        integrations.poll(g.db, z)
        g.db.commit()
        flash("Zammad angelegt. Nächster Schritt: unter „Rückmeldung“ den Webhook einrichten, damit Änderungen aus "
              "Zammad sofort ankommen.", "success" if not z.status_message else "warning")
        return redirect(url_for("zammad.detail", zid=z.id, tab="setup"))
    return _form(z, True)


@bp.route("/zammad/<int:zid>/edit", methods=["GET", "POST"])
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
            return redirect(url_for("zammad.edit", zid=zid))
        _link_zabbix(z)
        audit(g.db, g.user, "zammad.update", z.name, ip=client_ip())
        integrations.poll(g.db, z)
        g.db.commit()
        flash("Gespeichert.", "success")
        return redirect(url_for("zammad.detail", zid=z.id))
    return _form(z, False)


@bp.post("/zammad/<int:zid>/delete")
@admin_required
def delete(zid: int):
    z = _get(zid, LEVEL_FULL)
    access.remove_integration(g.db, KIND_ZAMMAD, z.id)
    for zbx in g.db.execute(select(ZabbixServer).where(ZabbixServer.zammad_id == z.id)).scalars():
        zbx.zammad_id = None
    audit(g.db, g.user, "zammad.delete", z.name, ip=client_ip())
    g.db.delete(z)
    g.db.commit()
    flash("Zammad-Verbindung entfernt (die Tickets in Zammad bleiben erhalten).", "warning")
    return redirect(url_for("zammad.index"))


@bp.get("/zammad/<int:zid>")
@login_required
def detail(zid: int):
    z = _get(zid, LEVEL_VIEW)
    tab = request.args.get("tab", "overview")
    if tab not in TABS:
        tab = "overview"
    rows = []
    if tab == "tickets":
        rows = g.db.execute(select(Ticket).where(Ticket.zammad_server_id == z.id)
                            .order_by(Ticket.id.desc()).limit(200)).scalars().all()
    zabbix = g.db.execute(select(ZabbixServer).where(ZabbixServer.zammad_id == z.id)).scalars().all()
    pending = g.db.execute(select(Ticket).where(Ticket.zabbix_id.in_([x.id for x in zabbix]),
                                                Ticket.zammad_ticket_id.is_(None), Ticket.zammad_error != "")
                           ).scalars().all() if zabbix else []
    return render_template("zammad/detail.html", z=z, tab=tab, tabs=TABS, rows=rows, zabbix=zabbix,
                           pending=pending, statuses=TICKET_STATUSES, webhook_url=webhook_url(z),
                           web=normalize_url(z.api_url) if z.api_url else "")


@bp.post("/zammad/<int:zid>/sync")
@login_required
def sync(zid: int):
    z = _get(zid, LEVEL_OPERATE)
    integrations.poll(g.db, z)
    g.db.commit()
    if z.status_message:
        flash(z.status_message, "danger")
    else:
        d = z.data
        flash(f"Abgeglichen: {d.get('created', 0)} Ticket(s) angelegt, {d.get('closed', 0)} geschlossen.", "success")
    return redirect(common.safe_next(url_for("zammad.detail", zid=zid)))


@bp.post("/zammad/<int:zid>/webhook")
@admin_required
def setup_webhook(zid: int):
    z = _get(zid, LEVEL_FULL)
    url = webhook_url(z)
    if not url:
        flash("Zuerst unter Einstellungen → Allgemein die öffentliche URL des Servermanagers setzen – Zammad muss "
              "sie erreichen können.", "danger")
        return redirect(url_for("zammad.detail", zid=zid, tab="setup"))
    secret = secrets.token_urlsafe(32)
    try:
        client = integrations.zammad_client(z)
        result = client.setup_webhook(url, secret, verify_ssl=url.startswith("https://"))
        me = client.me()
        states = {str(k): v for k, v in client.states().items()}
    except (ZammadError, ValueError) as exc:
        flash(f"Einrichtung fehlgeschlagen: {exc}", "danger")
        return redirect(url_for("zammad.detail", zid=zid, tab="setup"))
    z.webhook_secret_enc = security.encrypt(secret)
    z.agent_id = int(me["id"]) if me.get("id") else z.agent_id
    z.setup = dict(result, url=url, states=states, at=integrations.utcnow().isoformat(timespec="minutes"))
    audit(g.db, g.user, "zammad.webhook", z.name, url, ip=client_ip())
    g.db.commit()
    flash("Webhook und Trigger in Zammad eingerichtet. Schließen, Wiedereröffnen und neue Notizen in Zammad "
          "kommen jetzt sofort im Servermanager an.", "success")
    return redirect(url_for("zammad.detail", zid=zid, tab="setup"))


# --------------------------------------------------------------------------
# webhook (called by the Zammad trigger)
# --------------------------------------------------------------------------
@bp.post("/api/zammad/<int:zid>/webhook")
def webhook(zid: int):
    ip = client_ip()
    if throttled(ip, limit=20):
        return jsonify({"error": "zu viele Anfragen"}), 429
    z = g.db.get(ZammadServer, zid)
    raw = request.get_data(cache=True)
    secret = security.decrypt(z.webhook_secret_enc) if z is not None and z.webhook_secret_enc else ""
    if z is None or not signature_ok(secret, raw, request.headers.get("X-Hub-Signature", "")):
        record_failure(ip)
        return jsonify({"error": "nicht berechtigt"}), 403
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "JSON erwartet"}), 400
    try:
        result = tickets.handle_zammad(g.db, z, data)
    except ValueError as exc:
        g.db.rollback()
        return jsonify({"error": str(exc)}), 400
    g.db.commit()
    return jsonify({"ok": True, **result})
