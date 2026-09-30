"""Tickets: list, detail, processing (take over, comment, close) with feedback to Zabbix."""
from __future__ import annotations

from typing import Optional

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from sqlalchemy import func, or_, select

from ... import access, integrations, tickets
from ...core import audit
from ...models import (KIND_ZABBIX, LEVEL_OPERATE, LEVEL_VIEW, TICKET_CLOSED, TICKET_OPEN, TICKET_PROGRESS,
                       TICKET_RESOLVED, TICKET_STATUSES, Ticket, User, ZabbixServer, utcnow)
from ...zabbix import ACK_ACK, ACK_CLOSE, SEVERITIES, SEVERITY_CLASS, ZabbixError
from ..auth import client_ip, login_required

bp = Blueprint("tickets", __name__, url_prefix="/tickets")


def _visible_query(user: User):
    q = select(Ticket)
    ids = access.accessible_system_ids(g.db, user)
    if ids is None:
        return q
    zids = list((access.integration_levels(g.db, user, KIND_ZABBIX) or {}).keys())
    return q.where(or_(Ticket.system_id.in_(ids), Ticket.zabbix_id.in_(zids)))


def level(t: Ticket) -> Optional[str]:
    """operate: may process the ticket; view: may read it."""
    if g.user.is_admin:
        return LEVEL_OPERATE
    lvl = None
    if t.zabbix_id:
        lvl = access.integration_level(g.db, g.user, KIND_ZABBIX, t.zabbix_id)
    if t.system_id:
        s = access.system_level(g.db, g.user, t.system_id)
        if s in ("operate", "full") or lvl in ("operate", "full"):
            return LEVEL_OPERATE
        lvl = lvl or s
    return LEVEL_OPERATE if lvl in ("operate", "full") else (LEVEL_VIEW if lvl else None)


def open_count(user: User) -> int:
    q = _visible_query(user).where(Ticket.status.in_([TICKET_OPEN, TICKET_PROGRESS]))
    return g.db.execute(select(func.count()).select_from(q.subquery())).scalar() or 0


@bp.get("/")
@login_required
def index():
    status = request.args.get("status", "active")
    q = _visible_query(g.user)
    if status == "active":
        q = q.where(Ticket.status.in_([TICKET_OPEN, TICKET_PROGRESS]))
    elif status == "mine":
        q = q.where(Ticket.assignee_id == g.user.id, Ticket.status.in_([TICKET_OPEN, TICKET_PROGRESS]))
    elif status in TICKET_STATUSES:
        q = q.where(Ticket.status == status)
    sev = request.args.get("severity", "")
    if sev.isdigit():
        q = q.where(Ticket.severity >= int(sev))
    rows = g.db.execute(q.order_by(Ticket.status.in_([TICKET_RESOLVED, TICKET_CLOSED]), Ticket.severity.desc(),
                                   Ticket.id.desc()).limit(500)).scalars().all()
    return render_template("tickets/index.html", rows=rows, status=status, severity=sev, statuses=TICKET_STATUSES,
                           severities=SEVERITIES, sev_class=SEVERITY_CLASS)


def _get(ticket_id: int) -> Ticket:
    t = g.db.get(Ticket, ticket_id)
    if t is None:
        abort(404)
    if level(t) is None:
        abort(403)
    return t


@bp.get("/<int:ticket_id>")
@login_required
def detail(ticket_id: int):
    t = _get(ticket_id)
    users = g.db.execute(select(User).where(User.active.is_(True)).order_by(User.username)).scalars().all() \
        if g.user.is_admin else []
    zbx = g.db.get(ZabbixServer, t.zabbix_id) if t.zabbix_id else None
    zs = tickets.zammad_of(g.db, t)
    zammad_url = ""
    if zs is not None and t.zammad_ticket_id:
        from ...zammad import normalize_url
        zammad_url = f"{normalize_url(zs.api_url)}/#ticket/zoom/{t.zammad_ticket_id}"
    return render_template("tickets/detail.html", t=t, can_edit=level(t) == LEVEL_OPERATE, users=users, zbx=zbx,
                           zs=zs, zammad_url=zammad_url,
                           statuses=TICKET_STATUSES, severities=SEVERITIES, sev_class=SEVERITY_CLASS)


def _zabbix(t: Ticket, action: int, message: str) -> str:
    """Feedback to Zabbix; returns an error text (empty on success or when not applicable)."""
    if not t.zabbix_id or not t.event_id or t.resolved_at:
        return ""
    z = g.db.get(ZabbixServer, t.zabbix_id)
    if z is None:
        return ""
    # actions in Zabbix (acknowledge, message, close) need rights on the Zabbix connection itself -
    # rights on the affected system alone are not enough
    if not g.user.is_admin and not access.has_integration_level(g.db, g.user, KIND_ZABBIX, z.id, LEVEL_OPERATE):
        return "keine Berechtigung für die Zabbix-Verbindung – nur im Servermanager gespeichert"
    try:
        integrations.zabbix_client(z).acknowledge(t.event_id, action, f"{tickets.OWN_PREFIX} {message}")
        return ""
    except (ZabbixError, ValueError) as exc:
        return str(exc)


@bp.post("/<int:ticket_id>")
@login_required
def act(ticket_id: int):
    t = _get(ticket_id)
    if level(t) != LEVEL_OPERATE:
        abort(403)
    op = request.form.get("op", "")
    text = (request.form.get("text") or "").strip()[:4000]
    who = g.user.label
    warn = ""
    zwarn = ""
    if op == "take":
        t.assignee_id = g.user.id
        if t.status == TICKET_OPEN:
            t.status = TICKET_PROGRESS
        tickets.add_comment(g.db, t, f"Übernommen von {who}." + (f"\n{text}" if text else ""), "event", g.user)
        warn = _zabbix(t, ACK_ACK, f"Übernommen von {who}" + (f": {text}" if text else ""))
        zwarn = tickets.zammad_owner(g.db, t, g.user) or tickets.zammad_note(
            g.db, t, f"Übernommen von {who}" + (f": {text}" if text else ""))
        msg = "Ticket übernommen" + (" und in Zabbix bestätigt." if t.zabbix_id and not warn else ".")
    elif op == "assign" and g.user.is_admin:
        uid = request.form.get("user_id", "")
        user = g.db.get(User, int(uid)) if uid.isdigit() else None
        t.assignee_id = user.id if user else None
        tickets.add_comment(g.db, t, f"Zugewiesen an {user.label if user else 'niemanden'} ({who}).", "event",
                            g.user)
        msg = "Zuweisung gespeichert."
    elif op == "comment":
        if not text:
            flash("Bitte einen Text eingeben.", "warning")
            return redirect(url_for("tickets.detail", ticket_id=t.id))
        tickets.add_comment(g.db, t, text, "comment", g.user)
        if request.form.get("to_zabbix"):
            warn = _zabbix(t, 0, f"{who}: {text}")
        if request.form.get("to_zammad"):
            zwarn = tickets.zammad_note(g.db, t, f"{who}: {text}", internal=not request.form.get("public"))
        msg = "Kommentar gespeichert."
    elif op == "close":
        close_zbx = bool(request.form.get("close_zabbix")) and not t.resolved_at
        if close_zbx:
            warn = _zabbix(t, ACK_CLOSE, f"Geschlossen von {who}" + (f": {text}" if text else ""))
            if warn:
                flash(f"In Zabbix nicht geschlossen: {warn}", "danger")
                return redirect(url_for("tickets.detail", ticket_id=t.id))
        t.status, t.closed_at = TICKET_CLOSED, utcnow()
        tickets.add_comment(g.db, t, f"Geschlossen von {who}." + (" Problem in Zabbix geschlossen." if close_zbx
                                                                  else "") + (f"\n{text}" if text else ""),
                            "event", g.user)
        tickets.send_mail(g.db, g.db.get(ZabbixServer, t.zabbix_id) if t.zabbix_id else None, t, "closed")
        zwarn = tickets.zammad_note(g.db, t, f"Geschlossen von {who}" + (f": {text}" if text else ""),
                                    internal=False, state="closed")
        msg = "Ticket geschlossen."
    elif op == "reopen":
        t.status, t.closed_at = TICKET_PROGRESS if t.assignee_id else TICKET_OPEN, None
        tickets.add_comment(g.db, t, f"Wieder geöffnet von {who}." + (f"\n{text}" if text else ""), "event",
                            g.user)
        zwarn = tickets.zammad_note(g.db, t, f"Wieder geöffnet von {who}", state="open")
        msg = "Ticket wieder geöffnet."
    elif op == "zammad":
        if not tickets.zammad_create(g.db, t):
            g.db.commit()
            flash(f"Nicht an Zammad übergeben: {t.zammad_error or 'keine Zammad-Verbindung zugeordnet'}", "danger")
            return redirect(url_for("tickets.detail", ticket_id=t.id))
        msg = f"In Zammad als Ticket #{t.zammad_number} angelegt."
    else:
        abort(400)
    audit(g.db, g.user, f"ticket.{op}", f"#{t.id}", t.title[:200], ip=client_ip())
    g.db.commit()
    flash(msg, "success")
    if warn:
        flash(f"Rückmeldung an Zabbix fehlgeschlagen: {warn}", "warning")
    if zwarn:
        flash(f"Übertragung an Zammad fehlgeschlagen: {zwarn}", "warning")
    return redirect(url_for("tickets.detail", ticket_id=t.id))


@bp.app_context_processor
def _ctx():
    def count() -> int:
        if "open_tickets" not in g:
            g.open_tickets = open_count(g.user) if g.get("user") else 0
        return g.open_tickets
    return {"open_tickets": count}
