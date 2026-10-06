"""easybell Cloud Telefonanlage via AMI: client, call tracking, journal, Zammad CTI, web pages."""
import hashlib
import socket
import threading
import time

import pytest

from servermanager import security
from servermanager.ami import Ami, AmiError, CallTracker, normalize_number
from tests import mock_apis as m
from tests.test_web import login, make_user

AMI_USER, AMI_SECRET = "cpbx-4711", "geheimes-ami-passwort"


class MockAmi:
    """Minimal AMI server: MD5 challenge, a few list actions, pushes queued events after login."""

    def __init__(self, md5: bool = True, newline: str = "\r\n", silent: bool = False):
        self.md5, self.nl, self.silent = md5, newline, silent
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.received: list[dict] = []
        self.events: list[dict] = []
        self.logins = 0
        self.stop = False
        threading.Thread(target=self._accept, daemon=True).start()

    def close(self):
        self.stop = True
        self.sock.close()

    def _accept(self):
        while not self.stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _send(self, conn, fields):
        nl = self.nl
        conn.sendall(("".join(f"{k}: {v}{nl}" for k, v in fields.items()) + nl).encode())

    def _serve(self, conn):
        if self.silent:  # accepts the connection but never greets (e.g. second connection, IP not allowed)
            while not self.stop:
                time.sleep(0.1)
            return
        conn.sendall(f"Asterisk Call Manager/7.0.3{self.nl}".encode())
        buf, challenge, authed = b"", "", False
        conn.settimeout(0.2)
        while not self.stop:
            if authed and self.events:
                self._send(conn, self.events.pop(0))
                continue
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            if not chunk:
                return
            buf += chunk
            while b"\r\n\r\n" in buf:
                raw, buf = buf.split(b"\r\n\r\n", 1)
                msg = dict(line.split(": ", 1) for line in raw.decode().split("\r\n") if ": " in line)
                self.received.append(msg)
                aid = msg.get("ActionID", "")
                act = msg.get("Action")
                ok = {"Response": "Success", "ActionID": aid}
                if act == "Challenge":
                    if not self.md5:
                        self._send(conn, {"Response": "Error", "ActionID": aid, "Message": "Invalid action"})
                        continue
                    challenge = "123456789"
                    self._send(conn, {**ok, "Challenge": challenge})
                elif act == "Login":
                    good = (msg.get("Key") == hashlib.md5((challenge + AMI_SECRET).encode()).hexdigest()
                            if msg.get("AuthType") == "MD5" else msg.get("Secret") == AMI_SECRET)
                    if good and msg.get("Username") == AMI_USER:
                        authed = True
                        self.logins += 1
                        self._send(conn, {**ok, "Message": "Authentication accepted"})
                    else:
                        self._send(conn, {"Response": "Error", "ActionID": aid, "Message": "Authentication failed"})
                elif not authed:
                    self._send(conn, {"Response": "Error", "ActionID": aid, "Message": "Permission denied"})
                elif act == "CoreSettings":
                    self._send(conn, {**ok, "AsteriskVersion": "20.5.0"})
                elif act == "PJSIPShowEndpoints":
                    self._send(conn, {**ok, "EventList": "start", "Message": "A listing of Endpoints follows"})
                    for name, st in (("CPBX-100", "Not in use"), ("CPBX-101", "Unavailable")):
                        self._send(conn, {"Event": "EndpointList", "ActionID": aid, "ObjectName": name,
                                          "DeviceState": st, "Contacts": f"{name}/sip:x"})
                    self._send(conn, {"Event": "EndpointListComplete", "ActionID": aid, "EventList": "Complete"})
                elif act == "CoreShowChannels":
                    self._send(conn, {**ok, "EventList": "start"})
                    self._send(conn, {"Event": "CoreShowChannel", "ActionID": aid, "Channel": "PJSIP/CPBX-100-0000001",
                                      "CallerIDNum": "100", "ConnectedLineNum": "030123456", "Exten": "030123456",
                                      "ChannelStateDesc": "Up", "Duration": "00:01:02", "Linkedid": "1.1"})
                    self._send(conn, {"Event": "CoreShowChannelsComplete", "ActionID": aid, "EventList": "Complete"})
                elif act == "Ping":
                    self._send(conn, {**ok, "Ping": "Pong"})
                elif act == "Logoff":
                    self._send(conn, {"Response": "Goodbye", "ActionID": aid})
                    conn.close()
                    return
                else:
                    self._send(conn, {"Response": "Error", "ActionID": aid, "Message": "Invalid/unknown command"})


INBOUND = [
    {"Event": "Newchannel", "Channel": "PJSIP/trunk-00000001", "CallerIDNum": "030123456", "Exten": "+4940999000",
     "Uniqueid": "1.10", "Linkedid": "1.10"},
    {"Event": "Newchannel", "Channel": "PJSIP/CPBX-100-00000002", "CallerIDNum": "100", "Uniqueid": "1.11",
     "Linkedid": "1.10"},
    {"Event": "DialEnd", "DialStatus": "ANSWER", "DestChannel": "PJSIP/CPBX-100-00000002", "DestCallerIDNum": "100",
     "Uniqueid": "1.10", "Linkedid": "1.10"},
    {"Event": "Hangup", "Uniqueid": "1.11", "Linkedid": "1.10", "Cause": "16"},
    {"Event": "Hangup", "Uniqueid": "1.10", "Linkedid": "1.10", "Cause": "16"},
]
OUTBOUND_BUSY = [
    {"Event": "Newchannel", "Channel": "PJSIP/CPBX-101-00000003", "CallerIDNum": "101", "Exten": "0049301111",
     "Uniqueid": "1.20", "Linkedid": "1.20"},
    {"Event": "Hangup", "Uniqueid": "1.20", "Linkedid": "1.20", "Cause": "17"},
]
MISSED = [
    {"Event": "Newchannel", "Channel": "PJSIP/trunk-00000004", "CallerIDNum": "+491701234567", "Exten": "4940999000",
     "Uniqueid": "1.30", "Linkedid": "1.30"},
    {"Event": "Hangup", "Uniqueid": "1.30", "Linkedid": "1.30", "Cause": "16"},
]


@pytest.fixture()
def ami():
    srv = MockAmi()
    yield srv
    srv.close()


# --------------------------------------------------------------------------
def test_normalize_number():
    assert normalize_number("030 123456") == "4930123456"
    assert normalize_number("+49 30 123") == "4930123"
    assert normalize_number("0043123") == "43123"
    assert normalize_number("100") == "100"
    assert normalize_number("anonymous") == "" and normalize_number("") == ""
    assert normalize_number("0123", country="43") == "43123"


def test_call_tracker():
    seen = []
    t = CallTracker(lambda ev, c: seen.append((ev, c.call_id, c.direction, c.from_number, c.to_number, c.cause,
                                               c.extension)))
    for ev in INBOUND + OUTBOUND_BUSY + MISSED:
        t.feed(ev)
    assert seen == [
        ("newCall", "1.10", "in", "4930123456", "4940999000", "", ""),
        ("answer", "1.10", "in", "4930123456", "4940999000", "", "CPBX-100"),
        ("hangup", "1.10", "in", "4930123456", "4940999000", "normalClearing", "CPBX-100"),
        ("newCall", "1.20", "out", "101", "49301111", "", "CPBX-101"),
        ("hangup", "1.20", "out", "101", "49301111", "busy", "CPBX-101"),
        ("newCall", "1.30", "in", "491701234567", "4940999000", "", ""),
        ("hangup", "1.30", "in", "491701234567", "4940999000", "cancel", ""),
    ]
    assert not t.calls
    # stale calls (missed hangups) do not pile up
    t = CallTracker(lambda *a: None, max_open=3)
    for i in range(10):
        t.feed({"Event": "Newchannel", "Channel": "PJSIP/trunk-1", "Uniqueid": f"9.{i}", "Linkedid": f"9.{i}"})
    assert len(t.calls) == 3


def test_ami_client_md5_login(ami):
    with Ami("127.0.0.1", ami.port, AMI_USER, AMI_SECRET) as c:
        assert c.version() == "20.5.0"
        eps = c.endpoints()
        assert [e["name"] for e in eps] == ["CPBX-100", "CPBX-101"] and eps[1]["state"] == "Unavailable"
        ch = c.channels()
        assert ch[0]["caller"] == "100" and ch[0]["duration"] == "00:01:02"
    # the password itself never goes over the (unencrypted) connection
    assert all(AMI_SECRET not in str(msg) for msg in ami.received)
    assert any(msg.get("AuthType") == "MD5" for msg in ami.received if msg.get("Action") == "Login")
    with pytest.raises(AmiError, match="Anmeldung fehlgeschlagen"):
        Ami("127.0.0.1", ami.port, AMI_USER, "falsch").connect()
    with Ami("127.0.0.1", ami.port, AMI_USER, AMI_SECRET) as c:
        with pytest.raises(AmiError, match="Zeilenumbruch"):
            c.send("Ping", X="a\r\nAction: Originate")


def test_ami_bare_newlines_and_silent_server():
    srv = MockAmi(newline="\n")
    try:
        with Ami("127.0.0.1", srv.port, AMI_USER, AMI_SECRET) as c:
            assert c.version() == "20.5.0" and len(c.endpoints()) == 2
    finally:
        srv.close()
    srv = MockAmi(silent=True)
    try:
        with pytest.raises(AmiError, match="keine Begrüßung.*IP-Freigabeliste.*nur eine AMI-Verbindung"):
            Ami("127.0.0.1", srv.port, AMI_USER, AMI_SECRET, timeout=1).connect()
    finally:
        srv.close()


def test_status_query_over_the_event_connection():
    from servermanager.easybell import StatusQuery
    sent, saved, now = [], [], [0.0]

    class Fake:
        def send(self, action, **kw):
            sent.append(action)
            return f"id{len(sent)}"
    q = StatusQuery(Fake(), saved.append, clock=lambda: now[0])
    q.tick()
    assert sent == ["CoreSettings", "PJSIPShowEndpoints", "CoreShowChannels"]
    assert q.feed({"Response": "Success", "ActionID": "id1", "AsteriskVersion": "18.0"})
    assert q.feed({"Response": "Error", "ActionID": "id2", "Message": "Invalid/unknown command"})
    assert sent[-1] == "SIPpeers"  # chan_sip instead of PJSIP
    q.feed({"Event": "PeerEntry", "ActionID": "id4", "ObjectName": "101", "Status": "UNREACHABLE"})
    q.feed({"Event": "PeerlistComplete", "ActionID": "id4", "EventList": "Complete"})
    assert not q.feed({"Event": "Newchannel", "Uniqueid": "1"})  # call events are not swallowed
    assert not saved  # channels still open
    now[0] = 61  # no answer for CoreShowChannels within a minute
    q.tick()
    snap = saved[-1]
    assert snap["version"] == "18.0" and snap["endpoints"] == [{"name": "101", "state": "UNREACHABLE", "contacts": ""}]
    assert "keine Antwort" in snap["errors"]["channels"]
    now[0] = 400
    q.tick()
    assert sent[-1] == "CoreShowChannels"  # next round after five minutes


def test_ami_plain_login_only_when_allowed():
    srv = MockAmi(md5=False)
    try:
        with pytest.raises(AmiError, match="Klartext"):
            Ami("127.0.0.1", srv.port, AMI_USER, AMI_SECRET).connect()
        assert all(AMI_SECRET not in str(msg) for msg in srv.received)
        with Ami("127.0.0.1", srv.port, AMI_USER, AMI_SECRET, allow_plain=True) as c:
            assert c.version() == "20.5.0"
    finally:
        srv.close()
    with pytest.raises(AmiError, match="nicht erreichbar|keine Antwort"):
        Ami("127.0.0.1", 1, AMI_USER, AMI_SECRET, timeout=2).connect()


@pytest.fixture(scope="module")
def https():
    srv = m.MockServer().start()
    yield srv
    srv.stop()


@pytest.fixture()
def account(db, ami, https):
    from servermanager.models import EasybellAccount, EasybellCall, ZammadServer
    zs = ZammadServer(name="zam-eb", api_url=https.url, token_enc=security.encrypt(m.ZAM_TOKEN),
                      fingerprint=https.fingerprint, customer="x@example.com", group_name="Users")
    db.add(zs)
    db.flush()
    acc = EasybellAccount(name="eb", host="127.0.0.1", port=ami.port, username=AMI_USER,
                          secret_enc=security.encrypt(AMI_SECRET), watch_devices=True, listen=True,
                          zammad_id=zs.id, cti_token_enc=security.encrypt("cti-token-123"))
    db.add(acc)
    db.commit()
    yield acc
    db.query(EasybellCall).filter_by(account_id=acc.id).delete()
    db.delete(acc)
    db.delete(zs)
    db.commit()


def test_poll_and_alerts(db, account):
    from servermanager import integrations
    integrations.poll(db, account)
    assert account.status == "online", account.status_message
    assert account.data["version"] == "20.5.0" and account.data["offline"] == ["CPBX-101"]
    assert [a["key"] for a in account.alerts] == ["dev:CPBX-101"]


def test_listener_journal_and_zammad_cti(db, ami, https, account):
    from servermanager import easybell
    from servermanager.models import EasybellAccount, EasybellCall
    https.state.__dict__["cti"] = []
    ami.events = [dict(e) for e in INBOUND + MISSED]
    stop = threading.Event()
    t = threading.Thread(target=easybell.listen, args=(account.id, stop), daemon=True)
    t.start()
    deadline = time.time() + 15
    while time.time() < deadline:
        db.expire_all()
        rows = db.query(EasybellCall).filter_by(account_id=account.id).all()
        if len(rows) == 2 and all(r.ended_at for r in rows):
            break
        time.sleep(0.2)
    stop.set()
    t.join(10)
    assert not t.is_alive()
    rows = {r.call_id: r for r in db.query(EasybellCall).filter_by(account_id=account.id)}
    answered, missed = rows["1.10"], rows["1.30"]
    assert answered.answered_at and answered.extension == "CPBX-100" and answered.cause == "normalClearing"
    assert missed.answered_at is None and missed.from_number == "491701234567" and missed.zammad_ok is True
    cti = https.state.cti
    assert [c["event"] for c in cti] == ["newCall", "answer", "hangup", "newCall", "hangup"]
    assert cti[0] == {"event": "newCall", "from": "4930123456", "to": "4940999000", "direction": "in",
                      "callId": "1.10"}
    assert cti[2]["cause"] == "normalClearing" and cti[1]["answeringNumber"] == "100"
    db.expire_all()
    assert db.get(EasybellAccount, account.id).listener["connected"] is False
    # journal retention
    from datetime import timedelta
    from servermanager.models import utcnow
    answered.started_at = utcnow() - timedelta(days=40)
    db.commit()
    assert easybell.prune(db) == 1


def test_poll_uses_the_event_connection(db, ami, account):
    """easybell allows one AMI connection per access: while listening, the poll must not log in again."""
    from servermanager import easybell, integrations
    from servermanager.models import EasybellAccount
    stop = threading.Event()
    t = threading.Thread(target=easybell.listen, args=(account.id, stop), daemon=True)
    t.start()
    try:
        deadline = time.time() + 10
        while time.time() < deadline:
            db.expire_all()
            if (db.get(EasybellAccount, account.id).listener or {}).get("status"):
                break
            time.sleep(0.2)
        acc = db.get(EasybellAccount, account.id)
        assert acc.listener["status"]["version"] == "20.5.0"
        logins = ami.logins
        integrations.poll(db, acc)
        assert ami.logins == logins == 1  # no second connection
        assert acc.status == "online" and acc.data["via"] == "Ereignis-Verbindung"
        assert [x["name"] for x in acc.data["endpoints"]] == ["CPBX-100", "CPBX-101"]
        assert acc.data["offline"] == ["CPBX-101"] and len(acc.data["channels"]) == 1
    finally:
        stop.set()
        t.join(10)


def test_listener_stops_when_switched_off(db, account):
    from servermanager import easybell
    account.listen = False
    db.commit()
    stop = threading.Event()
    t = threading.Thread(target=easybell.listen, args=(account.id, stop), daemon=True)
    t.start()
    t.join(5)
    assert not t.is_alive()


def test_pages_and_permissions(app, db, ami, account):
    from servermanager.models import LEVEL_VIEW, EasybellAccount, EasybellCall, IntegrationAccess
    make_user(db, "eb-admin", "admin")
    admin = login(app, "eb-admin")
    r = admin.post("/easybell/new", data={
        "name": "eb-neu", "host": "127.0.0.1", "port": ami.port, "username": AMI_USER, "secret": AMI_SECRET,
        "country_code": "+49", "device_pattern": "^PJSIP/CPBX-", "journal_days": "14", "monitor": "1",
        "cti_token": "https://zammad.example.com/api/v1/cti/abcdefgh1234", "csrf_token": admin.csrf})
    assert r.status_code == 302, r.text[:500]
    new = db.query(EasybellAccount).filter_by(name="eb-neu").one()
    assert new.status == "online" and security.decrypt(new.cti_token_enc) == "abcdefgh1234"
    assert new.country_code == "49" and AMI_SECRET not in (new.secret_enc or "")
    db.add(EasybellCall(account_id=account.id, call_id="x1", direction="in", from_number="4930123456",
                        to_number="4940999000"))
    db.commit()
    assert "4930123456" in admin.get(f"/easybell/{account.id}?tab=calls&q=0123").text
    assert "Endgeräte" in admin.get(f"/easybell/{account.id}").text
    assert "eb-neu" in admin.get("/easybell/").text
    r = admin.post("/easybell/new", data={"name": "x", "host": "a b", "username": "", "csrf_token": admin.csrf})
    assert "Ungültiger Server" in r.text
    u = make_user(db, "eb-view")
    db.add(IntegrationAccess(user_id=u.id, kind="easybell", obj_id=account.id, level=LEVEL_VIEW))
    db.commit()
    viewer = login(app, "eb-view")
    assert viewer.get(f"/easybell/{account.id}").status_code == 200
    assert viewer.get(f"/easybell/{new.id}").status_code == 403
    assert viewer.post(f"/easybell/{account.id}/refresh", data={"csrf_token": viewer.csrf}).status_code == 403
    assert viewer.get(f"/easybell/{account.id}/edit").status_code == 403
    db.delete(new)
    db.commit()
