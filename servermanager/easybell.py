"""easybell Cloud Telefonanlage: permanent AMI connection for the call journal and Zammad CTI.

The worker keeps one listener thread per account with ``listen`` enabled. Each call becomes an
``EasybellCall`` row; with a Zammad connection and a CTI token the events newCall / answer / hangup are
forwarded to Zammad (caller pop-up, caller log, customer lookup by phone number).
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from sqlalchemy import delete, select

from . import integrations, security
from .ami import AmiError, Call, CallTracker
from .db import session_scope
from .models import EasybellAccount, EasybellCall, ZammadServer, utcnow
from .zammad import ZammadError

log = logging.getLogger(__name__)
BACKOFF = (5, 15, 30, 60, 120, 300)


def _ts(t: Optional[float]) -> Optional[datetime]:
    return datetime.fromtimestamp(t, tz=timezone.utc).replace(tzinfo=None) if t else None


def cti_payload(event: str, call: Call) -> dict:
    data = {"event": event, "from": call.from_number, "to": call.to_number, "direction": call.direction,
            "callId": call.call_id}
    if event == "answer" and call.answered_by:
        data["answeringNumber"] = call.answered_by
    if event == "hangup":
        data["cause"] = call.cause
    if call.direction == "out" and call.extension:
        data["user"] = call.extension
    return data


class Sink:
    """Stores the calls of one account and forwards them to Zammad."""

    def __init__(self, account_id: int):
        self.account_id = account_id
        self.zammad = None
        self.token = ""
        with session_scope() as db:
            acc = db.get(EasybellAccount, account_id)
            zs = db.get(ZammadServer, acc.zammad_id) if acc and acc.zammad_id else None
            if zs is not None and acc.cti_token_enc:
                try:
                    self.zammad = integrations.zammad_client(zs, timeout=8)
                    self.token = security.decrypt(acc.cti_token_enc)
                except (ZammadError, ValueError) as exc:
                    log.warning("easybell %s: Zammad CTI not available: %s", account_id, exc)

    def __call__(self, event: str, call: Call) -> None:
        ok: Optional[bool] = None
        if self.zammad is not None:
            try:
                self.zammad.cti(self.token, cti_payload(event, call))
                ok = True
            except ZammadError as exc:
                log.warning("easybell %s: Zammad CTI %s failed: %s", self.account_id, event, exc)
                ok = False
        with session_scope() as db:
            row = db.execute(select(EasybellCall).where(EasybellCall.account_id == self.account_id,
                                                        EasybellCall.call_id == call.call_id[:64])).scalar_one_or_none()
            if row is None:
                row = EasybellCall(account_id=self.account_id, call_id=call.call_id[:64], direction=call.direction,
                                   started_at=_ts(call.started) or utcnow())
                db.add(row)
            row.from_number, row.to_number = call.from_number[:64], call.to_number[:64]
            row.extension, row.answered_by = call.extension[:64], call.answered_by[:64]
            row.answered_at, row.ended_at, row.cause = _ts(call.answered), _ts(call.ended), call.cause[:32]
            if ok is not None:
                row.zammad_ok = ok if row.zammad_ok is None else (row.zammad_ok and ok)


def _state(account_id: int, **state) -> None:
    with session_scope() as db:
        acc = db.get(EasybellAccount, account_id)
        if acc is not None:
            acc.listener = {**(acc.listener or {}), **state, "at": utcnow().isoformat(timespec="seconds")}


def listen(account_id: int, stop: threading.Event, sink_factory: Callable[[int], Sink] = Sink) -> None:
    """Runs until ``stop`` is set or listening is switched off; reconnects with backoff."""
    attempt = 0
    while not stop.is_set():
        with session_scope() as db:
            acc = db.get(EasybellAccount, account_id)
            if acc is None or not acc.listen or not acc.secret_enc:
                return
            client = integrations.easybell_client(acc)
            country, pattern = acc.country_code or "49", acc.device_pattern
            signature = (acc.host, acc.port, acc.username, acc.secret_enc, acc.zammad_id, acc.cti_token_enc,
                         country, pattern, acc.allow_plain)
        try:
            client.connect()
            attempt = 0
            _state(account_id, connected=True, error="", since=utcnow().isoformat(timespec="seconds"))
            tracker = CallTracker(sink_factory(account_id), country=country, device_pattern=pattern)

            def changed() -> bool:
                if stop.is_set():
                    return True
                with session_scope() as db:
                    acc = db.get(EasybellAccount, account_id)
                    return acc is None or not acc.listen or signature != (
                        acc.host, acc.port, acc.username, acc.secret_enc, acc.zammad_id, acc.cti_token_enc,
                        acc.country_code or "49", acc.device_pattern, acc.allow_plain)
            checker = _Every(30, changed)
            for ev in client.events(stop=lambda: stop.is_set() or checker()):
                tracker.feed(ev)
            _state(account_id, connected=False, error="")
        except AmiError as exc:
            _state(account_id, connected=False, error=str(exc)[:500])
            log.info("easybell %s: event connection: %s", account_id, exc)
        except Exception as exc:  # noqa: BLE001 - the thread must survive
            _state(account_id, connected=False, error=f"interner Fehler: {exc}"[:500])
            log.exception("easybell %s: listener failed", account_id)
        finally:
            client.close()
        if stop.is_set():
            return
        stop.wait(BACKOFF[min(attempt, len(BACKOFF) - 1)])
        attempt += 1


class _Every:
    """Calls ``fn`` at most every ``seconds``; between calls the last answer is reused."""

    def __init__(self, seconds: float, fn: Callable[[], bool]):
        import time
        self.time = time.monotonic
        self.seconds, self.fn, self.last, self.value = seconds, fn, self.time(), False

    def __call__(self) -> bool:
        if self.time() - self.last >= self.seconds:
            self.last, self.value = self.time(), self.fn()
        return self.value


def prune(db, now: Optional[datetime] = None) -> int:
    now = now or utcnow()
    n = 0
    for acc in db.execute(select(EasybellAccount)).scalars():
        days = max(1, int(acc.journal_days or 30))
        n += db.execute(delete(EasybellCall).where(EasybellCall.account_id == acc.id,
                                                   EasybellCall.started_at < now - timedelta(days=days))).rowcount
    return n
