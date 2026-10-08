"""easybell Cloud Telefonanlage (AMI): devices, active calls, call journal, calls to Zammad."""
from __future__ import annotations

import re
from datetime import timedelta

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from sqlalchemy import or_, select

from ... import access, integrations, security
from ...ami import DEFAULT_HOST, DEFAULT_PORT, HOST_RE, TRANSPORTS, USER_RE
from ...core import audit
from ...models import (KIND_EASYBELL, LEVEL_FULL, LEVEL_OPERATE, LEVEL_VIEW, EasybellAccount, EasybellCall,
                       ZammadServer, utcnow)
from ...zammad import CTI_TOKEN_RE
from ..auth import admin_required, client_ip, login_required
from . import _integration as common

bp = Blueprint("easybell", __name__, url_prefix="/easybell")
TABS = {"overview": "Übersicht", "calls": "Anrufe"}
CAUSES = {"normalClearing": "beendet", "busy": "besetzt", "noAnswer": "nicht angenommen", "cancel": "abgebrochen",
          "notFound": "nicht erreichbar", "congestion": "überlastet"}


def _get(aid: int, level: str) -> EasybellAccount:
    return common.get_or_403(KIND_EASYBELL, aid, level)


@bp.get("/")
@login_required
def index():
    items = common.visible(KIND_EASYBELL)
    if not items and not g.user.is_admin:
        abort(403)
    return render_template("easybell/index.html", items=items)


def _save(a: EasybellAccount) -> list[str]:
    f = request.form
    errors = []
    a.name = (f.get("name") or "").strip()[:128]
    if not a.name:
        errors.append("Bitte einen Namen angeben.")
    a.description = (f.get("description") or "").strip()[:2000]
    a.host = (f.get("host") or DEFAULT_HOST).strip().lower()
    if not HOST_RE.match(a.host):
        errors.append("Ungültiger Server.")
    try:
        a.port = int(f.get("port") or DEFAULT_PORT)
        if not 1 <= a.port <= 65535:
            raise ValueError
    except ValueError:
        errors.append("Ungültiger Port.")
    a.username = (f.get("username") or "").strip()
    if not USER_RE.match(a.username):
        errors.append("AMI-Benutzername angeben (Cloud Telefonanlage → Erweiterte Einstellungen → Integration).")
    if f.get("secret"):
        a.secret_enc = security.encrypt(f["secret"].strip())
    elif not a.secret_enc:
        errors.append("AMI-Passwort angeben.")
    a.allow_plain = bool(f.get("allow_plain"))
    a.transport = f.get("transport") if f.get("transport") in TRANSPORTS else "auto"
    cc = (f.get("country_code") or "49").strip().lstrip("+")
    if not re.match(r"^[1-9][0-9]{0,3}$", cc):
        errors.append("Ländervorwahl als Zahl angeben (z. B. 49).")
    a.country_code = cc
    pattern = (f.get("device_pattern") or r"^PJSIP/CPBX-").strip()[:128]
    try:
        re.compile(pattern)
    except re.error:
        errors.append("Muster für Endgeräte ist kein gültiger regulärer Ausdruck.")
    a.device_pattern = pattern
    a.listen = bool(f.get("listen"))
    a.monitor = bool(f.get("monitor"))
    a.watch_devices = bool(f.get("watch_devices"))
    try:
        a.journal_days = max(1, min(3650, int(f.get("journal_days") or 30)))
    except ValueError:
        errors.append("Aufbewahrung in Tagen angeben.")
    raw = f.get("zammad_id", "")
    a.zammad_id = int(raw) if raw.isdigit() and g.db.get(ZammadServer, int(raw)) else None
    token = (f.get("cti_token") or "").strip()
    if token:
        token = token.rstrip("/").rsplit("/", 1)[-1]  # the whole CTI URL may be pasted
        if not CTI_TOKEN_RE.match(token):
            errors.append("CTI-Token: die Endpunkt-Adresse aus Zammad (Admin → Integrationen → CTI (generisch)) "
                          "oder nur das Token am Ende einfügen.")
        else:
            a.cti_token_enc = security.encrypt(token)
    if f.get("cti_clear"):
        a.cti_token_enc = None
    if a.zammad_id and not a.cti_token_enc:
        errors.append("Für die Weitergabe an Zammad das CTI-Token angeben.")
    return errors


def _form(a: EasybellAccount, is_new: bool):
    zammads = g.db.execute(select(ZammadServer).order_by(ZammadServer.name)).scalars().all()
    return render_template("easybell/form.html", a=a, is_new=is_new, zammads=zammads, transports=TRANSPORTS)


@bp.route("/new", methods=["GET", "POST"])
@admin_required
def new():
    a = EasybellAccount(host=DEFAULT_HOST, port=DEFAULT_PORT, monitor=True, listen=True, country_code="49", transport="auto",
                        device_pattern=r"^PJSIP/CPBX-", journal_days=30)
    if request.method == "POST":
        errors = _save(a)
        if errors:
            for e in errors:
                flash(e, "danger")
            return _form(a, True)
        g.db.add(a)
        g.db.flush()
        audit(g.db, g.user, "easybell.create", a.name, f"{a.host}:{a.port}", ip=client_ip())
        integrations.poll(g.db, a)
        g.db.commit()
        flash("easybell angebunden." if not a.status_message else f"Gespeichert, aber: {a.status_message}",
              "success" if not a.status_message else "warning")
        return redirect(url_for("easybell.detail", aid=a.id))
    return _form(a, True)


@bp.route("/<int:aid>/edit", methods=["GET", "POST"])
@admin_required
def edit(aid: int):
    a = _get(aid, LEVEL_FULL)
    if request.method == "POST":
        errors = _save(a)
        if errors:
            g.db.rollback()
            for e in errors:
                flash(e, "danger")
            return redirect(url_for("easybell.edit", aid=aid))
        audit(g.db, g.user, "easybell.update", a.name, ip=client_ip())
        integrations.poll(g.db, a)
        g.db.commit()
        flash("Gespeichert. Die Ereignis-Verbindung übernimmt die Änderungen innerhalb einer Minute.", "success")
        return redirect(url_for("easybell.detail", aid=a.id))
    return _form(a, False)


@bp.post("/<int:aid>/delete")
@admin_required
def delete(aid: int):
    a = _get(aid, LEVEL_FULL)
    access.remove_integration(g.db, KIND_EASYBELL, a.id)
    audit(g.db, g.user, "easybell.delete", a.name, ip=client_ip())
    g.db.delete(a)
    g.db.commit()
    flash("easybell-Verbindung entfernt (das Anrufjournal wurde gelöscht).", "warning")
    return redirect(url_for("easybell.index"))


@bp.post("/<int:aid>/refresh")
@login_required
def refresh(aid: int):
    a = _get(aid, LEVEL_OPERATE)
    integrations.poll(g.db, a)
    g.db.commit()
    flash(a.status_message or "Aktualisiert.", "danger" if a.status_message else "success")
    return redirect(url_for("easybell.detail", aid=aid))


PUBLIC_IP_URL = "https://api.ipify.org"


@bp.post("/<int:aid>/public-ip")
@login_required
def public_ip(aid: int):
    """The address easybell sees: asked from an external service on request (for the IP allow list)."""
    import ipaddress

    import requests
    _get(aid, LEVEL_OPERATE)
    try:
        r = requests.get(PUBLIC_IP_URL, timeout=8)
        ip = str(ipaddress.ip_address(r.text.strip()))
        flash(f"Öffentliche IP des Servermanagers (laut {PUBLIC_IP_URL}): {ip} – diese Adresse muss in der "
              "IP-Freigabeliste der Cloud Telefonanlage stehen.", "info")
    except (requests.RequestException, ValueError) as exc:
        flash(f"Öffentliche IP nicht ermittelbar: {exc}", "danger")
    return redirect(url_for("easybell.detail", aid=aid))


@bp.get("/<int:aid>")
@login_required
def detail(aid: int):
    a = _get(aid, LEVEL_VIEW)
    tab = request.args.get("tab", "overview")
    if tab not in TABS:
        tab = "overview"
    calls, stats = [], {}
    q = (request.args.get("q") or "").strip()[:40]
    direction = request.args.get("dir", "")
    if tab == "calls":
        stmt = select(EasybellCall).where(EasybellCall.account_id == a.id)
        if direction in ("in", "out"):
            stmt = stmt.where(EasybellCall.direction == direction)
        if request.args.get("missed"):
            stmt = stmt.where(EasybellCall.answered_at.is_(None), EasybellCall.direction == "in")
        if q:
            like = f"%{re.sub(r'[^0-9A-Za-z*#+-]', '', q)}%"
            stmt = stmt.where(or_(EasybellCall.from_number.like(like), EasybellCall.to_number.like(like),
                                  EasybellCall.extension.like(like), EasybellCall.answered_by.like(like)))
        calls = g.db.execute(stmt.order_by(EasybellCall.started_at.desc()).limit(300)).scalars().all()
    else:
        since = utcnow() - timedelta(hours=24)
        day = g.db.execute(select(EasybellCall).where(EasybellCall.account_id == a.id,
                                                      EasybellCall.started_at >= since)).scalars().all()
        stats = {"total": len(day), "in": sum(1 for c in day if c.direction == "in"),
                 "out": sum(1 for c in day if c.direction == "out"),
                 "missed": sum(1 for c in day if c.direction == "in" and c.answered_at is None and c.ended_at),
                 "zammad_failed": sum(1 for c in day if c.zammad_ok is False)}
    zammad = g.db.get(ZammadServer, a.zammad_id) if a.zammad_id else None
    return render_template("easybell/detail.html", a=a, tab=tab, tabs=TABS, calls=calls, stats=stats, q=q,
                           direction=direction, causes=CAUSES, zammad=zammad, listener=a.listener or {})
