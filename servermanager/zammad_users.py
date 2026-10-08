"""Servermanager users and their own Zammad accounts.

People log in to Zammad through authentik (OpenID Connect, see sso.py). The servermanager finds the Zammad
account of each of its users - by login (= authentik user name) or by e-mail address - and lets Zammad carry out
the user's requests as that account (header X-On-Behalf-Of): notes are written by the person, the owner is the
person, and lists show only what the person may see in Zammad. Background work (tickets from Zabbix, the
regular sync) keeps using the account of the API token.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import User, ZammadServer, ZammadUserLink, utcnow
from .zammad import Zammad, ZammadError

STALE = timedelta(hours=24)   # automatic links are checked again after this time
FIXED = ("manual", "none")    # set by an administrator, never changed automatically
CLOSED_STATES = ("closed", "merged", "removed")


def cached(db: Session, zs: ZammadServer, user: User) -> Optional[ZammadUserLink]:
    return db.execute(select(ZammadUserLink).where(ZammadUserLink.zammad_id == zs.id,
                                                   ZammadUserLink.user_id == user.id)).scalars().first()


def _fill(row: ZammadUserLink, zu: Optional[dict], how: str) -> None:
    roles = [str(x) for x in (zu or {}).get("roles") or []]
    row.zammad_user_id = int((zu or {}).get("id") or 0)
    row.login = str((zu or {}).get("login") or "")[:255]
    row.email = str((zu or {}).get("email") or "")[:255]
    row.name = " ".join(x for x in (str((zu or {}).get("firstname") or ""), str((zu or {}).get("lastname") or ""))
                        if x)[:255]
    row.agent = "Agent" in roles
    row.how = how if zu else ""
    row.checked_at = utcnow()


def link_for(db: Session, zs: ZammadServer, user: User, client: Zammad, refresh: bool = False
             ) -> Optional[ZammadUserLink]:
    """The link of the user (looked up in Zammad when missing or outdated). None if Zammad is not reachable
    and nothing is known yet."""
    row = cached(db, zs, user)
    if row is not None and (row.how in FIXED or (not refresh and utcnow() - row.checked_at < STALE)):
        return row
    try:
        zu, how = client.find_user(login=user.username, email=user.email)
    except ZammadError:
        return row
    if row is None:
        row = ZammadUserLink(zammad_id=zs.id, user_id=user.id)
        db.add(row)
    _fill(row, zu, how)
    db.flush()
    return row


def set_manual(db: Session, zs: ZammadServer, user: User, client: Zammad, value: str) -> ZammadUserLink:
    """Administrator: link to the Zammad user with this login/e-mail ("" = no Zammad account)."""
    row = cached(db, zs, user)
    if row is None:
        row = ZammadUserLink(zammad_id=zs.id, user_id=user.id)
        db.add(row)
    if not value:
        _fill(row, None, "")
        row.how = "none"
    else:
        zu, _how = client.find_user(login=value, email=value)
        if zu is None:
            raise ZammadError(f"In Zammad gibt es keinen aktiven Benutzer „{value}“")
        _fill(row, zu, "manual")
    db.flush()
    return row


def reset(db: Session, zs: ZammadServer, user: User) -> None:
    row = cached(db, zs, user)
    if row is not None:
        db.delete(row)
        db.flush()


def acting(db: Session, zs: ZammadServer, client: Zammad, user: Optional[User]
           ) -> tuple[Zammad, Optional[ZammadUserLink]]:
    """Client acting as the user's Zammad account (if switched on and linked), else the API token's account."""
    if user is None or not zs.on_behalf:
        return client, None
    row = link_for(db, zs, user, client)
    if row is None or not row.zammad_user_id:
        return client, None
    return client.as_user(row.zammad_user_id), row


def my_tickets(client: Zammad, zammad_user_id: int, limit: int = 50) -> dict:
    """Open tickets of the acting user and open unassigned ones, as Zammad shows them to that user."""
    out: dict = {"mine": [], "unassigned": []}
    states = client.states()
    closed = [str(i) for i, name in states.items() if name in CLOSED_STATES]
    conds = {"mine": {"ticket.owner_id": {"operator": "is", "pre_condition": "current_user.id", "value": []}},
             "unassigned": {"ticket.owner_id": {"operator": "is", "pre_condition": "not_set", "value": []}}}
    for key, cond in conds.items():
        if closed:
            cond["ticket.state_id"] = {"operator": "is not", "value": closed}
        rows = client.tickets_where(cond, limit)
        # the condition is checked again here, in case an older Zammad ignores parts of it
        owner_ok = (lambda t: int(t.get("owner_id") or 0) == int(zammad_user_id)) if key == "mine" else \
            (lambda t: int(t.get("owner_id") or 1) == 1)
        out[key] = [t for t in rows if owner_ok(t) and str(t.get("state") or states.get(int(t.get("state_id") or 0), ""))
                    not in CLOSED_STATES]
    return out
