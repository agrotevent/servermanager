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
from .ami import AmiError, Call, CallTracker, channel_row, endpoint_row
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


class StatusQuery:
    """Devices, channels and version queried over the listener's own connection.

    easybell allows one AMI connection per access: while the listener is connected, the periodic status
    poll must not open a second one, so the listener asks itself and stores a snapshot.
    """

    INTERVAL = 300
    TIMEOUT = 60
    LISTS = {"endpoints": ("EndpointList", "PeerEntry"), "channels": ("CoreShowChannel",)}

    def __init__(self, client, save: Callable[[dict], None], clock: Callable[[], float] = None):
        import time
        self.client, self.save = client, save
        self.clock = clock or time.monotonic
        self.last = -1e9
        self.pending: dict[str, str] = {}      # action id -> kind
        self.result: dict = {}
        self.started = 0.0

    def tick(self) -> None:
        now = self.clock()
        if self.pending and now - self.started > self.TIMEOUT:
            for kind in set(self.pending.values()):
                self.result["errors"][kind] = "keine Antwort vom Server (Abfrage wird vermutlich nicht unterstützt)"
            self.pending.clear()
            self._finish()
        if not self.pending and now - self.last >= self.INTERVAL:
            self.last, self.started = now, now
            self.result = {"version": "", "endpoints": [], "channels": [], "errors": {}}
            self.pending = {self.client.send("CoreSettings"): "version",
                            self.client.send("PJSIPShowEndpoints"): "endpoints",
                            self.client.send("CoreShowChannels"): "channels"}

    def feed(self, m: dict) -> bool:
        """True if the message belonged to a status query (and must not be treated as a call event)."""
        aid = m.get("ActionID", "")
        kind = self.pending.get(aid)
        if kind is None:
            return False
        if "Response" in m:
            if m["Response"].lower() == "error":
                if kind == "endpoints" and not self.result.get("_peers"):
                    self.result["_peers"] = True  # chan_sip instead of PJSIP
                    del self.pending[aid]
                    self.pending[self.client.send("SIPpeers")] = "endpoints"
                    return True
                self.result["errors"][kind] = m.get("Message", "Fehler")
                del self.pending[aid]
            elif kind == "version":
                self.result["version"] = m.get("AsteriskVersion", "")
                del self.pending[aid]
        elif m.get("Event") in self.LISTS.get(kind, ()):
            self.result[kind].append(endpoint_row(m) if kind == "endpoints" else channel_row(m))
        elif str(m.get("Event", "")).endswith("Complete") or m.get("EventList") == "Complete":
            del self.pending[aid]
        if not self.pending:
            self._finish()
        return True

    def _finish(self) -> None:
        self.result.pop("_peers", None)
        self.result["endpoints"].sort(key=lambda x: x["name"])
        self.save({**self.result, "at": utcnow().isoformat(timespec="seconds")})


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
                         country, pattern, acc.allow_plain, acc.transport)
        try:
            client.connect()
            attempt = 0
            _state(account_id, connected=True, error="", since=utcnow().isoformat(timespec="seconds"),
                   transport=client.transport_used)
            tracker = CallTracker(sink_factory(account_id), country=country, device_pattern=pattern)

            def changed() -> bool:
                if stop.is_set():
                    return True
                with session_scope() as db:
                    acc = db.get(EasybellAccount, account_id)
                    return acc is None or not acc.listen or signature != (
                        acc.host, acc.port, acc.username, acc.secret_enc, acc.zammad_id, acc.cti_token_enc,
                        acc.country_code or "49", acc.device_pattern, acc.allow_plain, acc.transport)
            checker = _Every(30, changed)
            status = StatusQuery(client, lambda snap: _state(account_id, status=snap))

            def done() -> bool:
                status.tick()
                return stop.is_set() or checker()
            for ev in client.events(stop=done):
                if not status.feed(ev):
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
