"""Tickets from Zabbix problems: webhook events, reconciliation by polling, mail to people and ticket systems."""
from __future__ import annotations

import hashlib
import hmac
import logging
from typing import Optional

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from . import notify, settings
from .models import (TICKET_CLOSED, TICKET_OPEN, TICKET_PROGRESS, TICKET_RESOLVED, System, Ticket, TicketComment,
                     User, ZabbixHost, ZabbixServer, utcnow)
from .zabbix import SEVERITIES

log = logging.getLogger(__name__)
OWN_PREFIX = "[Servermanager]"


def token_hash(token: str) -> str:
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


def token_ok(zbx: ZabbixServer, token: str) -> bool:
    return bool(zbx.webhook_hash) and bool(token) and hmac.compare_digest(zbx.webhook_hash, token_hash(token))


def match_system(db: Session, zbx: Optional[ZabbixServer], host: str, ip: str = "") -> Optional[int]:
    if zbx is not None and host:
        zh = db.execute(select(ZabbixHost).where(ZabbixHost.zabbix_id == zbx.id, ZabbixHost.host == host)
                        ).scalars().first()
        if zh:
            return zh.system_id
    conds = []
    if host:
        conds += [System.name == host, System.hostname == host]
    if ip:
        conds.append(System.host == ip)
    if not conds:
        return None
    s = db.execute(select(System).where(or_(*conds)).order_by(System.id)).scalars().first()
    return s.id if s else None


def _find(db: Session, zbx: ZabbixServer, event_id: str) -> Optional[Ticket]:
    return db.execute(select(Ticket).where(Ticket.zabbix_id == zbx.id, Ticket.event_id == str(event_id))
                      ).scalars().first()


def add_comment(db: Session, ticket: Ticket, text: str, kind: str = "comment", user: Optional[User] = None) -> None:
    ticket.comments.append(TicketComment(text=text[:5000], kind=kind, user_id=user.id if user else None,
                                         created_at=utcnow()))
    ticket.updated_at = utcnow()


def open_ticket(db: Session, zbx: ZabbixServer, event_id: str, title: str, severity: int, host: str,
                host_ip: str = "", trigger_id: str = "", opdata: str = "", manual_close: bool = False,
                via: str = "") -> tuple[Ticket, bool]:
    t = _find(db, zbx, event_id)
    if t is not None:
        return t, False
    t = Ticket(source="zabbix", zabbix_id=zbx.id, event_id=str(event_id), trigger_id=str(trigger_id or ""),
               title=(title or "Problem")[:500], severity=max(0, min(5, int(severity or 0))), host=host[:255],
               host_ip=host_ip[:64], opdata=opdata or "", manual_close=manual_close,
               system_id=match_system(db, zbx, host, host_ip), status=TICKET_OPEN, opened_at=utcnow())
    db.add(t)
    add_comment(db, t, f"Problem in Zabbix gemeldet{via}.", "event")
    db.flush()
    send_mail(db, zbx, t, "new")
    return t, True


def resolve_ticket(db: Session, zbx: ZabbixServer, t: Ticket, text: str = "In Zabbix behoben.") -> bool:
    if t.status in (TICKET_RESOLVED, TICKET_CLOSED) and t.resolved_at:
        return False
    t.resolved_at = utcnow()
    if t.status != TICKET_CLOSED:
        t.status = TICKET_RESOLVED
    add_comment(db, t, text, "event")
    send_mail(db, zbx, t, "resolved")
    return True


def handle_event(db: Session, zbx: ZabbixServer, data: dict) -> dict:
    """Webhook from the Zabbix media type (problem, recovery or update of an event)."""
    event_id = str(data.get("event_id") or "").strip()
    if not event_id.isdigit():
        raise ValueError("event_id fehlt")
    value = str(data.get("event_value", "1"))
    update = str(data.get("event_update_status", "0")) == "1"
    t = _find(db, zbx, event_id)
    if update:
        msg = str(data.get("update_message") or "").strip()
        if t is not None and msg and not msg.startswith(OWN_PREFIX):
            add_comment(db, t, f"Zabbix ({data.get('update_user') or 'Benutzer'}): {msg}", "zabbix")
        return {"ticket": t.id if t else None, "action": "update"}
    if value == "0":
        if t is not None:
            resolve_ticket(db, zbx, t)
        return {"ticket": t.id if t else None, "action": "resolved"}
    if not zbx.tickets:
        return {"ticket": None, "action": "ignored"}
    try:
        severity = int(data.get("severity") or 0)
    except ValueError:
        severity = 0
    if severity < zbx.min_severity:
        return {"ticket": None, "action": "ignored"}
    t, created = open_ticket(db, zbx, event_id, str(data.get("event_name") or ""), severity,
                             str(data.get("host") or data.get("host_name") or ""), str(data.get("host_ip") or ""),
                             str(data.get("trigger_id") or ""), str(data.get("opdata") or ""), via=" (Webhook)")
    return {"ticket": t.id, "action": "created" if created else "exists"}


def sync_problems(db: Session, zbx: ZabbixServer, problems: list[dict]) -> dict:
    """Reconcile tickets with the current problems (catches missed webhooks and recoveries)."""
    created = resolved = 0
    current = {str(p["eventid"]) for p in problems}
    if zbx.tickets:
        for p in problems:
            if int(p.get("severity") or 0) < zbx.min_severity:
                continue
            t, new = open_ticket(db, zbx, str(p["eventid"]), p.get("name", ""), int(p.get("severity") or 0),
                                 p.get("host") or p.get("host_name") or "", "", str(p.get("objectid") or ""),
                                 p.get("opdata") or "", bool(p.get("manual_close")), via=" (Abgleich)")
            t.manual_close = bool(p.get("manual_close"))
            if p.get("opdata"):
                t.opdata = p["opdata"]
            created += int(new)
    for t in db.execute(select(Ticket).where(Ticket.zabbix_id == zbx.id, Ticket.resolved_at.is_(None),
                                             Ticket.status.in_([TICKET_OPEN, TICKET_PROGRESS, TICKET_CLOSED]))
                        ).scalars():
        if t.event_id and t.event_id not in current:
            resolved += int(resolve_ticket(db, zbx, t))
    return {"created": created, "resolved": resolved}


def send_mail(db: Session, zbx: Optional[ZabbixServer], t: Ticket, event: str) -> None:
    to: list[str] = []
    if settings.get(db, "integrations.notify"):
        to += notify.recipients(settings.get(db, "mail.admin_recipients") or "")
    if zbx is not None and zbx.ticket_mail:
        to += notify.recipients(zbx.ticket_mail)
    if t.assignee and t.assignee.email and event != "new":
        to.append(t.assignee.email)
    to = sorted(set(to))
    if not to:
        return
    label = {"new": "NEU", "resolved": "BEHOBEN", "closed": "GESCHLOSSEN"}.get(event, event.upper())
    base = settings.base_url(db)
    lines = [f"Ticket #{t.id}: {t.title}", "",
             f"Status:      {label}",
             f"Schweregrad: {SEVERITIES.get(t.severity, t.severity)}",
             f"Host:        {t.host}{f' ({t.host_ip})' if t.host_ip else ''}",
             f"Seit:        {t.opened_at:%d.%m.%Y %H:%M} UTC"]
    if t.opdata:
        lines.append(f"Messwerte:   {t.opdata}")
    if t.resolved_at:
        lines.append(f"Behoben:     {t.resolved_at:%d.%m.%Y %H:%M} UTC")
    if zbx is not None:
        lines.append(f"Zabbix:      {zbx.name}, Event {t.event_id}")
    if base:
        lines += ["", f"{base}/tickets/{t.id}"]
    notify.notify(db, to, f"[SM#{t.id}] {label}: {t.title}"[:250], "\n".join(lines))
