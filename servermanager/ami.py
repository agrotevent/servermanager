"""Asterisk Manager Interface (AMI) – used for the easybell Cloud Telefonanlage.

easybell offers AMI (``jarvis.easybell.de:5039``) as its programming interface, without TLS and secured by
an IP allow list. The password is therefore never sent: the login uses the MD5 challenge of AMI
(``Action: Challenge`` + ``Key = md5(challenge + secret)``); a plain-text login has to be allowed explicitly.

``CallTracker`` turns the event stream into calls (journal and Zammad CTI events). It is a pure state machine
so that it can be tested without a server.
"""
from __future__ import annotations

import hashlib
import itertools
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Callable, Iterator, Optional

DEFAULT_HOST = "jarvis.easybell.de"
DEFAULT_PORT = 5039
DEFAULT_DEVICE_PATTERN = r"^PJSIP/CPBX-"
HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
USER_RE = re.compile(r"^[A-Za-z0-9._@+-]{1,128}$")


class AmiError(Exception):
    pass


def _msg(fields: dict) -> bytes:
    lines = []
    for k, v in fields.items():
        v = str(v)
        if "\r" in v or "\n" in v:
            raise AmiError("Ungültiger Wert (Zeilenumbruch)")
        lines.append(f"{k}: {v}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8")


class Ami:
    def __init__(self, host: str, port: int, username: str, secret: str, allow_plain: bool = False,
                 timeout: float = 15.0):
        if not HOST_RE.match(host or ""):
            raise AmiError("Ungültiger Server")
        if not USER_RE.match(username or ""):
            raise AmiError("Ungültiger AMI-Benutzername")
        if not secret:
            raise AmiError("Kein AMI-Passwort hinterlegt")
        self.host, self.port = host, int(port)
        self.username, self.secret, self.allow_plain = username, secret, allow_plain
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self.buf = b""
        self.banner = ""
        self.ids = itertools.count(1)
        self.pending_events: list[dict] = []

    # ------------------------------------------------------------------ connection
    def __enter__(self) -> "Ami":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def connect(self) -> None:
        where = f"{self.host}:{self.port}"
        try:
            self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except socket.timeout:
            raise AmiError(f"AMI {where}: keine Antwort – ist die öffentliche IP des Servermanagers in der "
                           "IP-Freigabeliste der Cloud Telefonanlage eingetragen?") from None
        except OSError as exc:
            raise AmiError(f"AMI {where} nicht erreichbar: {exc}") from exc
        try:
            self.banner = self._line()
        except AmiError as exc:
            self.close()
            if "Zeitüberschreitung" not in str(exc):
                raise
            raise AmiError(f"AMI {where}: Verbindung steht, aber keine Begrüßung vom Server. Mögliche Ursachen: "
                           "die öffentliche IP des Servermanagers fehlt in der IP-Freigabeliste, die AMI-Schnittstelle "
                           "ist nicht aktiviert, oder der Zugang ist bereits anderweitig verbunden (easybell lässt "
                           "je Zugang nur eine AMI-Verbindung zu)") from None
        if not self.banner.startswith("Asterisk Call Manager"):
            self.close()
            raise AmiError(f"AMI {where}: unerwartete Begrüßung ({self.banner[:80]!r})")
        self.login()

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.sendall(_msg({"Action": "Logoff"}))
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def _fill(self) -> None:
        try:
            chunk = self.sock.recv(65536) if self.sock else b""
        except socket.timeout:
            raise AmiError("AMI: Zeitüberschreitung beim Lesen") from None
        except OSError as exc:
            raise AmiError(f"AMI: Verbindung unterbrochen ({exc})") from exc
        if not chunk:
            raise AmiError("AMI: Verbindung vom Server beendet")
        # tolerate bare \n line endings (not every AMI implementation sends \r\n)
        self.buf += chunk.replace(b"\r", b"")
        if len(self.buf) > 4 * 1024 * 1024:
            raise AmiError("AMI: Antwort zu groß")

    def _line(self) -> str:
        while b"\n" not in self.buf:
            self._fill()
        line, self.buf = self.buf.split(b"\n", 1)
        return line.decode("utf-8", "replace")

    def read_message(self) -> dict:
        while b"\n\n" not in self.buf:
            self._fill()
        raw, self.buf = self.buf.split(b"\n\n", 1)
        out: dict = {}
        for line in raw.decode("utf-8", "replace").split("\n"):
            k, sep, v = line.partition(":")
            if sep:
                out.setdefault(k.strip(), v.strip())
        return out

    def send(self, action: str, **fields) -> str:
        if self.sock is None:
            raise AmiError("AMI: nicht verbunden")
        aid = f"sm-{next(self.ids)}"
        try:
            self.sock.sendall(_msg({"Action": action, "ActionID": aid, **fields}))
        except OSError as exc:
            raise AmiError(f"AMI: Senden fehlgeschlagen ({exc})") from exc
        return aid

    def _response(self, aid: str) -> dict:
        while True:
            m = self.read_message()
            if m.get("ActionID") == aid and "Response" in m:
                return m
            if "Event" in m:
                self.pending_events.append(m)

    def action(self, action: str, **fields) -> dict:
        resp = self._response(self.send(action, **fields))
        if resp.get("Response", "").lower() == "error":
            msg = resp.get("Message", "Fehler")
            if "permission" in msg.lower() or "denied" in msg.lower():
                raise AmiError(f"AMI {action}: keine Berechtigung ({msg})")
            raise AmiError(f"AMI {action}: {msg}")
        return resp

    def action_list(self, action: str, item_events: tuple[str, ...], **fields) -> list[dict]:
        """Actions that answer with a list of events terminated by '...Complete'."""
        aid = self.send(action, **fields)
        resp = self._response(aid)
        if resp.get("Response", "").lower() == "error":
            raise AmiError(f"AMI {action}: {resp.get('Message', 'Fehler')}")
        items = []
        while True:
            m = self.read_message()
            if m.get("ActionID") != aid:
                if "Event" in m:
                    self.pending_events.append(m)
                continue
            ev = m.get("Event", "")
            if ev in item_events:
                items.append(m)
            elif ev.endswith("Complete") or m.get("EventList") == "Complete":
                return items

    def login(self) -> None:
        try:
            ch = self.action("Challenge", AuthType="MD5")
            challenge = ch.get("Challenge", "")
        except AmiError:
            challenge = ""
        if challenge:
            key = hashlib.md5((challenge + self.secret).encode("utf-8")).hexdigest()  # noqa: S324 - AMI protocol
            try:
                self.action("Login", AuthType="MD5", Username=self.username, Key=key, Events="on")
                return
            except AmiError as exc:
                raise AmiError(f"AMI-Anmeldung fehlgeschlagen ({exc}) – Benutzername/Passwort aus den "
                               "erweiterten Einstellungen der Cloud Telefonanlage (Integration → AMI) prüfen") from exc
        if not self.allow_plain:
            raise AmiError("AMI: der Server bietet keine MD5-Anmeldung an – die Anmeldung mit Klartext-Passwort "
                           "(unverschlüsselt) müsste ausdrücklich erlaubt werden")
        try:
            self.action("Login", Username=self.username, Secret=self.secret, Events="on")
        except AmiError as exc:
            raise AmiError(f"AMI-Anmeldung fehlgeschlagen ({exc})") from exc

    # ------------------------------------------------------------------ reads
    def version(self) -> str:
        try:
            r = self.action("CoreSettings")
            return r.get("AsteriskVersion", "")
        except AmiError:
            return ""

    def endpoints(self) -> list[dict]:
        """Registered phones/devices: PJSIP (Asterisk 13+), falls back to chan_sip."""
        try:
            return [endpoint_row(r) for r in self.action_list("PJSIPShowEndpoints", ("EndpointList",))]
        except AmiError as first:
            try:
                rows = self.action_list("SIPpeers", ("PeerEntry",))
            except AmiError:
                raise first from None
            return [endpoint_row(r) for r in rows]

    def channels(self) -> list[dict]:
        return [channel_row(r) for r in self.action_list("CoreShowChannels", ("CoreShowChannel",))]

    def events(self, keepalive: float = 30.0, stop: Optional[Callable[[], bool]] = None) -> Iterator[dict]:
        """Yields events and action responses forever (pings when idle); stops when ``stop()`` is true."""
        while self.pending_events:
            yield self.pending_events.pop(0)
        last = time.monotonic()
        if self.sock:
            self.sock.settimeout(min(keepalive, 5.0))
        while not (stop and stop()):
            try:
                while b"\n\n" not in self.buf:
                    self._fill()
            except AmiError as exc:
                if "Zeitüberschreitung" not in str(exc):
                    raise
                if time.monotonic() - last >= keepalive:
                    self.send("Ping")
                    last = time.monotonic()
                continue
            m = self.read_message()
            if "Event" in m or ("Response" in m and m.get("ActionID")):
                yield m


# ----------------------------------------------------------------------------- list rows
def endpoint_row(r: dict) -> dict:
    """EndpointList (PJSIP) or PeerEntry (chan_sip) -> {name, state, contacts}."""
    if r.get("Event") == "PeerEntry":
        return {"name": r.get("ObjectName", ""), "state": r.get("Status", ""), "contacts": r.get("IPaddress", "")}
    return {"name": r.get("ObjectName", ""), "state": r.get("DeviceState", ""), "contacts": r.get("Contacts", "")}


def channel_row(r: dict) -> dict:
    return {"channel": r.get("Channel", ""), "caller": r.get("CallerIDNum", ""),
            "connected": r.get("ConnectedLineNum", ""), "exten": r.get("Exten", ""),
            "state": r.get("ChannelStateDesc", ""), "duration": r.get("Duration", ""),
            "linkedid": r.get("Linkedid", "")}


# ----------------------------------------------------------------------------- numbers
def normalize_number(num: str, country: str = "49") -> str:
    """Digits in international format without '+' (as Zammad's CTI expects); short extensions unchanged."""
    raw = (num or "").strip()
    digits = re.sub(r"\D", "", raw)
    if not digits or raw.lower() in ("anonymous", "unknown", "<unknown>"):
        return ""
    if raw.startswith("+"):
        return digits
    if digits.startswith("00"):
        return digits[2:]
    if digits.startswith("0"):
        return country + digits[1:]
    return digits


# ----------------------------------------------------------------------------- calls
HANGUP_CAUSES = {17: "busy", 18: "noAnswer", 19: "noAnswer", 21: "cancel", 1: "notFound", 3: "notFound",
                 34: "congestion", 38: "congestion"}


@dataclass
class Call:
    call_id: str
    direction: str            # in | out
    from_number: str
    to_number: str
    extension: str = ""       # device/extension involved
    started: float = field(default_factory=time.time)
    answered: Optional[float] = None
    answered_by: str = ""
    ended: Optional[float] = None
    cause: str = ""

    @property
    def duration(self) -> int:
        if self.answered and self.ended:
            return int(self.ended - self.answered)
        return 0


class CallTracker:
    """Event stream -> call lifecycle. ``on`` receives (event, call): newCall, answer, hangup."""

    def __init__(self, on: Callable[[str, Call], None], country: str = "49",
                 device_pattern: str = DEFAULT_DEVICE_PATTERN, max_open: int = 500):
        self.on = on
        self.country = country
        self.device = re.compile(device_pattern or DEFAULT_DEVICE_PATTERN)
        self.calls: dict[str, Call] = {}
        self.max_open = max_open

    def _ext(self, channel: str) -> str:
        m = re.match(r"^[A-Za-z]+/(.+?)(-[0-9a-f]{6,})?$", channel or "")
        return m.group(1) if m else ""

    def feed(self, ev: dict) -> None:
        name = ev.get("Event", "")
        uid, linked = ev.get("Uniqueid", ""), ev.get("Linkedid") or ev.get("Uniqueid", "")
        if name == "Newchannel" and uid and uid == linked and linked not in self.calls:
            channel = ev.get("Channel", "")
            outbound = bool(self.device.search(channel))
            caller = normalize_number(ev.get("CallerIDNum", ""), self.country)
            exten = ev.get("Exten", "")
            if outbound:
                call = Call(linked, "out", caller or self._ext(channel), normalize_number(exten, self.country),
                            extension=self._ext(channel))
            else:
                call = Call(linked, "in", caller, normalize_number(exten, self.country))
            if len(self.calls) >= self.max_open:  # stale calls (missed hangups) must not pile up
                self.calls.pop(next(iter(self.calls)))
            self.calls[linked] = call
            self.on("newCall", call)
        elif name == "DialEnd" and ev.get("DialStatus") == "ANSWER":
            call = self.calls.get(linked)
            if call and call.answered is None:
                call.answered = time.time()
                dest = ev.get("DestChannel", "")
                call.answered_by = (ev.get("DestCallerIDNum") or self._ext(dest) or "")[:64]
                if call.direction == "in" and self.device.search(dest):
                    call.extension = self._ext(dest)
                self.on("answer", call)
        elif name == "Hangup" and uid and uid == linked:
            call = self.calls.pop(linked, None)
            if call is None:
                return
            call.ended = time.time()
            try:
                code = int(ev.get("Cause", "0") or 0)
            except ValueError:
                code = 0
            if call.answered:
                call.cause = "normalClearing"
            else:
                call.cause = HANGUP_CAUSES.get(code, "cancel" if call.direction == "in" else "noAnswer")
            self.on("hangup", call)
