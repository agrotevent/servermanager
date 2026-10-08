"""Zammad: tickets from Zabbix problems in Zammad, processing in both directions, signed webhook."""
import json

import pytest

from servermanager import security, tickets
from servermanager.zammad import Zammad, ZammadError, normalize_url, signature
from tests import mock_apis as m
from tests.test_web import login, make_user


@pytest.fixture(scope="module")
def mock():
    srv = m.MockServer().start()
    yield srv
    srv.stop()


@pytest.fixture()
def env(db, mock):
    from servermanager.models import System, Ticket, ZabbixServer, ZammadServer
    Zammad(mock.url, m.ZAM_TOKEN, fingerprint=mock.fingerprint).me()  # creates the mock state
    zs = ZammadServer(name="Helpdesk", api_url=mock.url, token_enc=security.encrypt(m.ZAM_TOKEN),
                      fingerprint=mock.fingerprint, group_name="Technik", customer="monitoring@example.com")
    system = System(name="web01", host="10.20.0.60", types=["debian"])
    db.add_all([zs, system])
    db.flush()
    zbx = ZabbixServer(name="Zabbix", api_url=f"{mock.url}/zabbix", token_enc=security.encrypt("x"),
                       fingerprint=mock.fingerprint, min_severity=2, tickets=True, zammad_id=zs.id,
                       webhook_hash=tickets.token_hash("hook"))
    db.add(zbx)
    db.commit()
    yield {"zs": zs, "zbx": zbx, "system": system}
    for t in db.query(Ticket).all():
        db.delete(t)
    for o in (zbx, zs, system):
        db.delete(o)
    db.commit()


def test_client_basics(mock):
    assert normalize_url("support.example.com/api/v1/") == "https://support.example.com"
    with pytest.raises(ZammadError, match="Token-Zugriff"):
        Zammad(mock.url, "falsch", fingerprint=mock.fingerprint).me()
    zc = Zammad(mock.url, m.ZAM_TOKEN, fingerprint=mock.fingerprint)
    assert zc.me()["id"] == 3 and zc.find_agent("tk-admin@example.com") == 5 and zc.find_agent("x@y.z") is None


def _event(app, zbx, **kw):
    ev = {"event_id": "8001", "event_value": "1", "event_update_status": "0", "event_name": "Dienst nginx gestoppt",
          "severity": "4", "host": "web01", "host_ip": "10.20.0.60", "trigger_id": "t1"}
    ev.update(kw)
    return app.test_client().post(f"/api/zabbix/{zbx.id}/event", json=ev, headers={"Authorization": "Bearer hook"})


def test_problem_creates_zammad_ticket_and_resolves(app, db, mock, env):
    from servermanager.models import Ticket
    assert _event(app, env["zbx"]).get_json()["action"] == "created"
    t = db.query(Ticket).filter_by(event_id="8001").one()
    zt = mock.state.zam["tickets"][t.zammad_ticket_id]
    assert t.zammad_number == zt["number"] and t.zammad_server_id == env["zs"].id and not t.zammad_error
    assert zt["title"] == f"[SM#{t.id}] Dienst nginx gestoppt" and zt["priority"] == "3 high"
    assert zt["group"] == "Technik" and zt["customer_id"] == "guess:monitoring@example.com"
    art = next(a for a in mock.state.zam["articles"] if a.get("ticket_id") == t.zammad_ticket_id)
    assert "web01 (10.20.0.60)" in art["body"] and art["type"] == "note"
    assert {(t.zammad_ticket_id, "servermanager"), (t.zammad_ticket_id, "zabbix"),
            (t.zammad_ticket_id, "web01")} <= set(mock.state.zam["tags"])
    # recovery: note, ticket stays open unless configured
    _event(app, env["zbx"], event_value="0")
    assert mock.state.zam["articles"][-1]["body"].startswith(f"{tickets.OWN_PREFIX} In Zabbix behoben")
    assert zt["state"] == "new"


def test_close_on_resolve(app, db, mock, env):
    from servermanager.models import Ticket
    env["zs"].close_on_resolve = True
    db.commit()
    _event(app, env["zbx"], event_id="8002")
    _event(app, env["zbx"], event_id="8002", event_value="0")
    t = db.query(Ticket).filter_by(event_id="8002").one()
    assert mock.state.zam["tickets"][t.zammad_ticket_id]["state"] == "closed"


def test_processing_in_servermanager(app, db, mock, env):
    from servermanager.models import Ticket
    _event(app, env["zbx"], event_id="8003")
    t = db.query(Ticket).filter_by(event_id="8003").one()
    zt = mock.state.zam["tickets"][t.zammad_ticket_id]
    user = make_user(db, "tk-admin", "admin")
    user.email = "tk-admin@example.com"
    db.commit()
    c = login(app, "tk-admin")
    assert f"Zammad #{t.zammad_number}" in c.get(f"/tickets/{t.id}").text
    c.post(f"/tickets/{t.id}", data={"op": "take", "csrf_token": c.csrf})
    assert zt["state"] == "open" and zt["owner_id"] == 5
    c.post(f"/tickets/{t.id}", data={"op": "comment", "text": "nginx neu gestartet", "to_zammad": "1",
                                     "csrf_token": c.csrf})
    art = mock.state.zam["articles"][-1]
    assert "nginx neu gestartet" in art["body"] and art["internal"] is True
    c.post(f"/tickets/{t.id}", data={"op": "close", "text": "erledigt", "csrf_token": c.csrf})
    assert zt["state"] == "closed" and mock.state.zam["articles"][-1]["internal"] is False
    c.post(f"/tickets/{t.id}", data={"op": "reopen", "csrf_token": c.csrf})
    assert zt["state"] == "open"


def test_webhook_from_zammad(app, db, mock, env):
    from servermanager.models import Ticket
    _event(app, env["zbx"], event_id="8004")
    t = db.query(Ticket).filter_by(event_id="8004").one()
    zs = env["zs"]
    zs.webhook_secret_enc = security.encrypt("geheim")
    zs.agent_id = 3
    db.commit()
    c = app.test_client()
    url = f"/api/zammad/{zs.id}/webhook"

    def send(payload, secret="geheim"):
        raw = json.dumps(payload).encode()
        return c.post(url, data=raw, content_type="application/json",
                      headers={"X-Hub-Signature": signature(secret, raw)})
    ticket = {"id": t.zammad_ticket_id, "number": t.zammad_number, "state": "open"}
    assert send({"ticket": ticket}, secret="falsch").status_code == 403
    r = send({"ticket": ticket, "article": {"id": 1, "body": "<p>Kunde meldet: <b>wieder da</b></p>",
                                            "from": "Eva Agentin", "created_by_id": 5}})
    assert r.status_code == 200 and r.get_json()["action"] == "comment"
    # own articles and our marker are ignored (no ping-pong)
    send({"ticket": ticket, "article": {"id": 2, "body": "x", "created_by_id": 3}})
    send({"ticket": ticket, "article": {"id": 3, "body": f"{tickets.OWN_PREFIX} y", "created_by_id": 5}})
    db.expire_all()
    zammad_comments = [x.text for x in t.comments if x.kind == "zammad"]
    assert zammad_comments == ["Zammad (Eva Agentin): Kunde meldet: wieder da"]
    assert send({"ticket": dict(ticket, state="closed")}).get_json()["action"] == "closed"
    db.expire_all()
    assert t.status == "closed"
    assert send({"ticket": dict(ticket, state="open")}).get_json()["action"] == "reopened"
    assert send({"ticket": {"id": 999999}}).get_json()["action"] == "unknown"


def test_poll_retries_and_takes_over_closing(db, mock, env):
    from servermanager import integrations
    from servermanager.models import Ticket
    zs = env["zs"]
    zs.group_name = "Gibtsnicht"
    db.commit()
    t, _ = tickets.open_ticket(db, env["zbx"], "8005", "Backup fehlt", 3, "web01")
    db.commit()
    assert t.zammad_ticket_id is None and "No such group" in t.zammad_error
    integrations.poll(db, zs)
    assert any("Gibtsnicht" in a["text"] for a in zs.alert_list)
    zs.group_name = "Users"
    integrations.poll(db, zs)
    db.commit()
    db.refresh(t)
    assert t.zammad_ticket_id and not t.zammad_error and zs.data["created"] == 1
    mock.state.zam["tickets"][t.zammad_ticket_id]["state"] = "closed"
    integrations.poll(db, zs)
    db.commit()
    db.refresh(t)
    assert t.status == "closed" and zs.data["closed"] == 1
    assert db.query(Ticket).filter_by(zammad_server_id=zs.id).count() >= 1


def test_pages_and_setup(app, db, mock, env):
    from servermanager import settings
    make_user(db, "tk-admin", "admin")
    c = login(app, "tk-admin")
    zid = env["zs"].id
    for tab in ("overview", "tickets", "setup"):
        assert c.get(f"/zammad/{zid}?tab={tab}").status_code == 200
    assert c.get("/zammad/").status_code == 200 and c.get("/zammad/new").status_code == 200
    assert "Tickets in Zammad anlegen" in c.get(f"/zabbix/{env['zbx'].id}/edit").text
    settings.set(db, "general.base_url", "https://sm.example.com")
    db.commit()
    for _ in range(2):  # idempotent
        r = c.post(f"/zammad/{zid}/webhook", data={"csrf_token": c.csrf}, follow_redirects=True)
        assert "Webhook und Trigger in Zammad eingerichtet" in r.text
    z = mock.state.zam
    assert len(z["webhooks"]) == 1 and len(z["triggers"]) == 1
    hook, trig = z["webhooks"][0], z["triggers"][0]
    db.expire_all()
    assert hook["endpoint"] == f"https://sm.example.com/api/zammad/{zid}/webhook"
    assert hook["signature_token"] == security.decrypt(env["zs"].webhook_secret_enc)
    assert trig["perform"]["notification.webhook"]["webhook_id"] == hook["id"]
    assert trig["condition"]["ticket.tags"]["value"] == "servermanager"
    assert env["zs"].agent_id == 3 and env["zs"].setup["states"]["4"] == "closed"
    settings.set(db, "general.base_url", "")
    db.commit()


def test_migration_v4_to_v5(tmp_path):
    """1.9/1.10 created tickets and zabbix_servers without the Zammad columns."""
    from sqlalchemy import MetaData, Table, create_engine, inspect, text
    from servermanager import migrations
    from servermanager.db import Base
    eng = create_engine(f"sqlite:///{tmp_path / 'v4.db'}")
    new_cols = {"zammad_server_id", "zammad_ticket_id", "zammad_number", "zammad_error", "zammad_id"}
    old = MetaData()
    for t in Base.metadata.sorted_tables:
        if t.name != "zammad_servers":
            Table(t.name, old, *[c._copy() for c in t.columns if c.name not in new_cols])
    old.create_all(eng)
    with eng.begin() as conn:
        conn.execute(text("INSERT INTO meta(key, value) VALUES ('schema_version', '4')"))
        conn.execute(text("INSERT INTO tickets(source, event_id, trigger_id, title, severity, host, host_ip, opdata, "
                          "status, manual_close, opened_at, updated_at) VALUES ('zabbix', '1', '', 'alt', 3, 'h', "
                          "'', '', 'open', 0, '2026-09-26 10:00:00', '2026-09-26 10:00:00')"))
    assert migrations.migrate(eng) == migrations.SCHEMA_VERSION
    insp = inspect(eng)
    assert new_cols - {"zammad_id"} <= {c["name"] for c in insp.get_columns("tickets")}
    assert "zammad_id" in {c["name"] for c in insp.get_columns("zabbix_servers")}
    assert "zammad_servers" in insp.get_table_names()
    with eng.connect() as conn:
        assert conn.execute(text("SELECT zammad_number, zammad_error FROM tickets")).one() == ("", "")


def test_actions_as_the_users_own_zammad_account(app, db, mock, env):
    from servermanager.models import KIND_ZAMMAD, LEVEL_FULL, IntegrationAccess, Ticket, ZammadUserLink
    zam, zs = mock.state.zam, env["zs"]
    assert zs.on_behalf   # on by default
    u = make_user(db, "zm-anna", "admin")
    u.email = "anna@example.com"   # Zammad login is anna.b: found through the e-mail address
    db.commit()
    c = login(app, "zm-anna")
    _event(app, env["zbx"], event_id="8010")
    t = db.query(Ticket).filter_by(event_id="8010").one()
    zt = zam["tickets"][t.zammad_ticket_id]
    zam["on_behalf"].clear()
    c.post(f"/tickets/{t.id}", data={"op": "take", "csrf_token": c.csrf})
    assert zt["owner_id"] == 7 and ("PUT", f"tickets/{t.zammad_ticket_id}", 7) in zam["on_behalf"]
    c.post(f"/tickets/{t.id}", data={"op": "comment", "text": "schaue ich mir an", "to_zammad": "1",
                                     "csrf_token": c.csrf})
    assert zam["articles"][-1]["created_by_id"] == 7 and tickets.OWN_PREFIX in zam["articles"][-1]["body"]
    assert "anna.b" in c.get(f"/tickets/{t.id}").text
    # my tickets: as Zammad shows them to anna.b
    page = c.get(f"/zammad/{zs.id}?tab=mine").text
    assert "Angemeldet in Zammad als <strong>anna.b</strong>" in page and f"#{t.zammad_number}" in page
    assert ("POST", "tickets/search", 7) in zam["on_behalf"]
    page = c.get(f"/zammad/{zs.id}?tab=users").text
    assert "zm-anna" in page and "anna.b" in page and ">E-Mail<" in page
    # set by hand: a customer account (no agent); "without account" falls back to the API account
    c.post(f"/zammad/{zs.id}/users", data={"action": "manual", "user_id": u.id, "value": "kunde", "csrf_token": c.csrf})
    link = db.query(ZammadUserLink).filter_by(zammad_id=zs.id, user_id=u.id).one()
    assert link.zammad_user_id == 8 and link.how == "manual" and not link.agent
    assert "kein Agent" in c.get(f"/zammad/{zs.id}?tab=mine").text
    r = c.post(f"/zammad/{zs.id}/users", data={"action": "manual", "user_id": u.id, "value": "gibtsnicht",
                                                "csrf_token": c.csrf}, follow_redirects=True)
    assert "keinen aktiven Benutzer" in r.text
    c.post(f"/zammad/{zs.id}/users", data={"action": "none", "user_id": u.id, "csrf_token": c.csrf})
    zam["on_behalf"].clear()
    c.post(f"/tickets/{t.id}", data={"op": "reopen", "csrf_token": c.csrf})
    assert zam["on_behalf"] == [] and "kein Zammad-Konto" in c.get(f"/tickets/{t.id}").text
    c.post(f"/zammad/{zs.id}/users", data={"action": "auto", "user_id": u.id, "csrf_token": c.csrf})
    db.expire_all()
    assert db.query(ZammadUserLink).filter_by(zammad_id=zs.id, user_id=u.id).one().zammad_user_id == 7
    # the token lacks admin.user: a clear message
    zam["no_admin_user"] = True
    r = c.post(f"/tickets/{t.id}", data={"op": "comment", "text": "x", "to_zammad": "1", "csrf_token": c.csrf},
               follow_redirects=True)
    assert "admin.user" in r.text
    zam["no_admin_user"] = False
    # switched off: everything runs as the API account
    zs.on_behalf = False
    db.commit()
    zam["on_behalf"].clear()
    c.post(f"/tickets/{t.id}", data={"op": "comment", "text": "y", "to_zammad": "1", "csrf_token": c.csrf})
    assert zam["on_behalf"] == [] and zam["articles"][-1]["created_by_id"] == 3
    assert "ausgeschaltet" in c.get(f"/zammad/{zs.id}?tab=mine").text
    zs.on_behalf = True
    db.commit()
    # full access without being administrator: look up again yes, decide by hand no
    op = make_user(db, "zm-op")
    db.add(IntegrationAccess(user_id=op.id, kind=KIND_ZAMMAD, obj_id=zs.id, level=LEVEL_FULL))
    db.commit()
    c2 = login(app, "zm-op")
    assert c2.post(f"/zammad/{zs.id}/users", data={"action": "manual", "user_id": u.id, "value": "kunde",
                                                    "csrf_token": c2.csrf}).status_code == 403
    r = c2.post(f"/zammad/{zs.id}/users", data={"action": "refresh", "csrf_token": c2.csrf}, follow_redirects=True)
    assert "haben ein Zammad-Konto" in r.text
    db.query(IntegrationAccess).filter_by(user_id=op.id).delete()
    db.query(ZammadUserLink).delete()
    db.commit()
