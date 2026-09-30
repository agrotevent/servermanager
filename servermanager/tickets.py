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
                     User, ZabbixHost, ZabbixServer, ZammadServer, utcnow)
from .zabbix import SEVERITIES
from .zammad import PRIORITY, ZammadError

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
    zammad_create(db, t, zbx)
    return t, True


def resolve_ticket(db: Session, zbx: ZabbixServer, t: Ticket, text: str = "In Zabbix behoben.") -> bool:
    if t.status in (TICKET_RESOLVED, TICKET_CLOSED) and t.resolved_at:
        return False
    t.resolved_at = utcnow()
    if t.status != TICKET_CLOSED:
        t.status = TICKET_RESOLVED
    add_comment(db, t, text, "event")
    send_mail(db, zbx, t, "resolved")
    zs = zammad_of(db, t)
    if zs is not None and t.zammad_ticket_id:
        fields = {"state": "closed"} if zs.close_on_resolve and t.status != TICKET_CLOSED else {}
        zammad_note(db, t, f"{text} ({t.resolved_at:%d.%m.%Y %H:%M} UTC)", internal=False, **fields)
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


# --------------------------------------------------------------------------
# Zammad
# --------------------------------------------------------------------------
ZAMMAD_CLOSED = ("closed", "merged", "removed")


def zammad_of(db: Session, t: Ticket, zbx: Optional[ZabbixServer] = None) -> Optional[ZammadServer]:
    """Zammad a ticket lives in (or will be created in)."""
    zid = t.zammad_server_id
    if zid is None:
        if zbx is None and t.zabbix_id:
            zbx = db.get(ZabbixServer, t.zabbix_id)
        zid = zbx.zammad_id if zbx is not None else None
    return db.get(ZammadServer, zid) if zid else None


def zammad_client(zs: ZammadServer):
    from . import integrations
    return integrations.zammad_client(zs)


def zammad_body(db: Session, t: Ticket, zbx: Optional[ZabbixServer]) -> str:
    base = settings.base_url(db)
    lines = [t.title, "",
             f"Schweregrad: {SEVERITIES.get(t.severity, t.severity)}",
             f"Host:        {t.host}{f' ({t.host_ip})' if t.host_ip else ''}",
             f"Seit:        {t.opened_at:%d.%m.%Y %H:%M} UTC"]
    if t.opdata:
        lines.append(f"Messwerte:   {t.opdata}")
    if zbx is not None:
        lines.append(f"Zabbix:      {zbx.name}, Event {t.event_id}")
    if t.system is not None:
        lines.append(f"System:      {t.system.name}")
    if base:
        lines += ["", f"Servermanager: {base}/tickets/{t.id}"]
    return "\n".join(lines)


def zammad_create(db: Session, t: Ticket, zbx: Optional[ZabbixServer] = None) -> bool:
    """Create the ticket in Zammad (errors are kept on the ticket and retried by the next sync)."""
    zs = zammad_of(db, t, zbx)
    if zs is None or t.zammad_ticket_id:
        return False
    try:
        if not zs.customer:
            raise ZammadError("In der Zammad-Verbindung ist kein Kunde (E-Mail) eingetragen")
        tags = tuple(x for x in ("zabbix" if t.source == "zabbix" else "", _tag(t.host)) if x)
        zt = zammad_client(zs).create_ticket(f"[SM#{t.id}] {t.title}", zs.group_name or "Users", zs.customer,
                                             zammad_body(db, t, zbx), PRIORITY.get(t.severity, "2 normal"), tags)
    except (ZammadError, ValueError) as exc:
        t.zammad_error = str(exc)[:1000]
        log.warning("zammad: ticket %s not created: %s", t.id, exc)
        return False
    t.zammad_server_id, t.zammad_ticket_id = zs.id, int(zt["id"])
    t.zammad_number, t.zammad_error = str(zt.get("number") or ""), ""
    add_comment(db, t, f"In Zammad als Ticket #{t.zammad_number} angelegt.", "event")
    return True


def _tag(host: str) -> str:
    import re
    return re.sub(r"[^a-z0-9._-]", "-", (host or "").lower())[:60]


def zammad_note(db: Session, t: Ticket, text: str, internal: bool = True, **fields) -> str:
    """Article (and optional ticket fields) in Zammad; returns an error text or ''."""
    zs = zammad_of(db, t)
    if zs is None or not t.zammad_ticket_id:
        return ""
    try:
        client = zammad_client(zs)
        if text:
            client.add_note(t.zammad_ticket_id, f"{OWN_PREFIX} {text}", internal=internal)
        if fields:
            client.update_ticket(t.zammad_ticket_id, **fields)
        return ""
    except (ZammadError, ValueError) as exc:
        return str(exc)


def zammad_owner(db: Session, t: Ticket, user: Optional[User]) -> str:
    """Set the Zammad owner to the agent with the user's e-mail (if there is one) and open the ticket."""
    zs = zammad_of(db, t)
    if zs is None or not t.zammad_ticket_id:
        return ""
    try:
        client = zammad_client(zs)
        fields: dict = {"state": "open"}
        agent = client.find_agent(user.email) if user is not None and user.email else None
        if agent:
            fields["owner_id"] = agent
        client.update_ticket(t.zammad_ticket_id, **fields)
        return ""
    except (ZammadError, ValueError) as exc:
        return str(exc)


def _plain(html: str) -> str:
    import re
    from html import unescape
    text = re.sub(r"<br\s*/?>|</p>|</div>", "\n", html or "", flags=re.I)
    return unescape(re.sub(r"<[^>]+>", "", text)).strip()


def handle_zammad(db: Session, zs: ZammadServer, data: dict) -> dict:
    """Webhook of the Zammad trigger: close/reopen and new articles written by people in Zammad."""
    ticket = data.get("ticket") or {}
    article = data.get("article") or {}
    try:
        zid = int(ticket.get("id") or 0)
    except (TypeError, ValueError):
        zid = 0
    if not zid:
        raise ValueError("ticket.id fehlt")
    t = db.execute(select(Ticket).where(Ticket.zammad_server_id == zs.id, Ticket.zammad_ticket_id == zid)
                   ).scalars().first()
    if t is None:
        return {"ticket": None, "action": "unknown"}
    # replay protection: a (signed) request that was captured and sent again must not act twice -
    # remember the last change time per ticket and the articles already taken over
    seen = dict(zs.setup or {})
    stamps = dict(seen.get("updated", {}))
    updated = str(ticket.get("updated_at") or "")
    key = str(zid)
    if updated and stamps.get(key) and updated <= stamps[key]:
        return {"ticket": t.id, "action": "replay"}
    articles = list(seen.get("articles", []))
    if updated:
        stamps[key] = updated
        if len(stamps) > 1000:
            stamps = dict(sorted(stamps.items(), key=lambda kv: kv[1])[-1000:])
    actions = []
    body = str(article.get("body") or "")
    by_us = zs.agent_id and str(article.get("created_by_id") or "") == str(zs.agent_id)
    aid = str(article.get("id") or "")
    if aid and body and not by_us and OWN_PREFIX not in body and aid not in articles:
        who = article.get("from") or article.get("created_by") or "Zammad"
        add_comment(db, t, f"Zammad ({who}): {_plain(body)[:4000]}", "zammad")
        actions.append("comment")
    if aid and aid not in articles:
        articles = (articles + [aid])[-500:]
    zs.setup = dict(seen, updated=stamps, articles=articles)
    state = str(ticket.get("state") or "")
    if not state and ticket.get("state_id"):
        state = (zs.setup or {}).get("states", {}).get(str(ticket["state_id"]), "")
    if state in ZAMMAD_CLOSED and t.status != TICKET_CLOSED:
        t.status, t.closed_at = TICKET_CLOSED, utcnow()
        add_comment(db, t, f"In Zammad geschlossen (#{t.zammad_number}).", "event")
        actions.append("closed")
    elif state in ("open", "new") and t.status == TICKET_CLOSED:
        t.status, t.closed_at = (TICKET_PROGRESS if t.assignee_id else TICKET_OPEN), None
        add_comment(db, t, f"In Zammad wieder geöffnet (#{t.zammad_number}).", "event")
        actions.append("reopened")
    return {"ticket": t.id, "action": ",".join(actions) or "none"}


def sync_zammad(db: Session, zs: ZammadServer) -> dict:
    """Create missing tickets in Zammad and take over closings (fallback for the webhook)."""
    created = closed = 0
    zbx_ids = [z.id for z in db.execute(select(ZabbixServer).where(ZabbixServer.zammad_id == zs.id)).scalars()]
    if zbx_ids:
        for t in db.execute(select(Ticket).where(Ticket.zabbix_id.in_(zbx_ids), Ticket.zammad_ticket_id.is_(None),
                                                 Ticket.status.in_([TICKET_OPEN, TICKET_PROGRESS]))
                            .limit(50)).scalars():
            created += int(zammad_create(db, t))
    client = zammad_client(zs)
    states: Optional[dict] = None
    for t in db.execute(select(Ticket).where(Ticket.zammad_server_id == zs.id, Ticket.zammad_ticket_id.is_not(None),
                                             Ticket.status.in_([TICKET_OPEN, TICKET_PROGRESS, TICKET_RESOLVED]))
                        .limit(200)).scalars():
        try:
            zt = client.ticket(t.zammad_ticket_id)
        except ZammadError as exc:
            if exc.status == 404:
                t.zammad_error = "Ticket in Zammad nicht mehr vorhanden"
                continue
            raise
        state = zt.get("state") or ""
        if not state and zt.get("state_id"):
            states = states if states is not None else client.states()
            state = states.get(int(zt["state_id"]), "")
        if state in ZAMMAD_CLOSED and t.status != TICKET_CLOSED:
            t.status, t.closed_at = TICKET_CLOSED, utcnow()
            add_comment(db, t, f"In Zammad geschlossen (#{t.zammad_number}, Abgleich).", "event")
            closed += 1
    return {"created": created, "closed": closed}
