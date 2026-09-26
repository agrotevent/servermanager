"""Zabbix: API client, ticket webhook, reconciliation, ticket processing, agent setup."""
import os
import subprocess
from pathlib import Path

import pytest

from servermanager import security, tickets
from servermanager.zabbix import Zabbix, ZabbixError, normalize_url
from tests import mock_apis as m
from tests.test_web import login, make_user

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "servermanager" / "modules" / "scripts"


@pytest.fixture(scope="module")
def mock():
    srv = m.MockServer().start()
    yield srv
    srv.stop()


def _client(mock) -> Zabbix:
    return Zabbix(f"{mock.url}/zabbix/", m.ZBX_TOKEN, fingerprint=mock.fingerprint)


def _problem(mock, eventid: str, name: str, severity: int, host: str, manual_close: bool = False):
    z = mock.state.zbx
    trig = f"t{eventid}"
    z["triggers"][trig] = {"triggerid": trig, "manual_close": "1" if manual_close else "0",
                           "hosts": [{"hostid": "1", "host": host, "name": host}]}
    z["problems"].append({"eventid": eventid, "objectid": trig, "name": name, "severity": str(severity),
                          "clock": "1790000000", "acknowledged": "0", "opdata": "CPU 97 %", "r_eventid": "0"})


@pytest.fixture()
def zbx(db, mock):
    from servermanager.models import System, Ticket, ZabbixServer
    _client(mock).version()  # creates the mock state
    mock.state.zbx["problems"].clear()
    system = System(name="web01", host="10.20.0.60", types=["debian", "docker"])
    z = ZabbixServer(name="Zabbix", api_url=f"{mock.url}/zabbix", token_enc=security.encrypt(m.ZBX_TOKEN),
                     fingerprint=mock.fingerprint, agent_server="10.20.0.5", min_severity=2, tickets=True,
                     webhook_hash=tickets.token_hash("hook-secret"))
    db.add_all([system, z])
    db.commit()
    yield {"z": z, "system": system}
    for t in db.query(Ticket).all():
        db.delete(t)
    db.delete(z)
    db.delete(system)
    db.commit()


def test_url_and_auth(mock):
    assert normalize_url("zabbix.example.com") == "https://zabbix.example.com/api_jsonrpc.php"
    assert normalize_url("https://z.example.com/zabbix/") == "https://z.example.com/zabbix/api_jsonrpc.php"
    assert _client(mock).version() == "7.0.5"
    with pytest.raises(ZabbixError, match="API-Token prüfen"):
        Zabbix(f"{mock.url}/zabbix", "falsch", fingerprint=mock.fingerprint).hostgroups()


def test_legacy_auth_field(mock):
    mock.state.zbx["version"] = "6.0.30"
    try:
        zx = _client(mock)
        with pytest.raises(ZabbixError):  # 6.0 sends the token in the body, the mock only accepts the header
            zx.hostgroups()
    finally:
        mock.state.zbx["version"] = "7.0.5"


def test_webhook_setup_is_idempotent(mock):
    zx = _client(mock)
    a = zx.setup_webhook("https://sm.example.com/api/zabbix/1/event", "tok1", 3)
    b = zx.setup_webhook("https://sm.example.com/api/zabbix/1/event", "tok2", 2)
    assert a == b
    z = mock.state.zbx
    assert len(z["mediatypes"]) == len(z["users"]) == len(z["actions"]) == len(z["usergroups"]) == 1
    media = z["mediatypes"][0]
    params = {p["name"]: p["value"] for p in media["parameters"]}
    assert params["Token"] == "tok2" and params["event_id"] == "{EVENT.ID}" and media["type"] == 4
    assert "HttpRequest" in media["script"]
    user = z["users"][0]
    assert user["username"] == "servermanager-tickets" and user["roleid"] == "1"
    assert user["medias"][0]["mediatypeid"] == a["mediatypeid"]
    assert z["usergroups"][0]["gui_access"] == 3 and z["usergroups"][0]["hostgroup_rights"]
    action = z["actions"][0]
    assert action["filter"]["conditions"][0] == {"conditiontype": 4, "operator": 5, "value": "2"}
    assert action["operations"][0]["opmessage_usr"] == [{"userid": a["userid"]}]


def test_webhook_endpoint(app, db, zbx):
    from servermanager.models import Ticket
    c = app.test_client()
    zid = zbx["z"].id
    url = f"/api/zabbix/{zid}/event"
    ev = {"event_id": "5001", "event_value": "1", "event_update_status": "0", "event_name": "Hohe CPU-Last",
          "severity": "4", "host": "web01", "host_ip": "10.20.0.60", "trigger_id": "t1", "opdata": "97 %"}
    assert c.post(url, json=ev, headers={"Authorization": "Bearer falsch"}).status_code == 403
    r = c.post(url, json=ev, headers={"Authorization": "Bearer hook-secret"})
    assert r.status_code == 200 and r.get_json()["action"] == "created"
    t = db.query(Ticket).filter_by(event_id="5001").one()
    assert t.system_id == zbx["system"].id and t.severity == 4 and t.status == "open" and t.opdata == "97 %"
    assert c.post(url, json=ev, headers={"Authorization": "Bearer hook-secret"}).get_json()["action"] == "exists"
    upd = dict(ev, event_update_status="1", update_message="Schaue ich mir an", update_user="Eva")
    c.post(url, json=upd, headers={"Authorization": "Bearer hook-secret"})
    own = dict(upd, update_message=f"{tickets.OWN_PREFIX} Übernommen")
    c.post(url, json=own, headers={"Authorization": "Bearer hook-secret"})
    db.expire_all()
    texts = [x.text for x in t.comments]
    assert any("Eva" in x and "Schaue ich mir an" in x for x in texts)
    assert not any("Übernommen" in x for x in texts)
    low = dict(ev, event_id="5002", severity="1")
    assert c.post(url, json=low, headers={"Authorization": "Bearer hook-secret"}).get_json()["action"] == "ignored"
    rec = dict(ev, event_value="0")
    assert c.post(url, json=rec, headers={"Authorization": "Bearer hook-secret"}).get_json()["action"] == "resolved"
    db.expire_all()
    assert t.status == "resolved" and t.resolved_at is not None
    assert c.post(url, data="kein json", headers={"Authorization": "Bearer hook-secret"}).status_code == 400


def test_poll_reconciles_tickets(db, mock, zbx):
    from servermanager import integrations
    from servermanager.models import Ticket
    _problem(mock, "6001", "Dienst nginx gestoppt", 3, "web01", manual_close=True)
    _problem(mock, "6002", "Info-Meldung", 1, "web01")
    z = zbx["z"]
    integrations.poll(db, z)
    db.commit()
    assert z.status == "online", z.status_message
    assert z.data["problems"] == 2 and z.data["by_severity"]["3"] == 1
    t = db.query(Ticket).filter_by(event_id="6001").one()
    assert t.manual_close and t.system_id == zbx["system"].id
    assert db.query(Ticket).filter_by(event_id="6002").count() == 0
    mock.state.zbx["problems"] = [p for p in mock.state.zbx["problems"] if p["eventid"] != "6001"]
    integrations.poll(db, z)
    db.commit()
    db.refresh(t)
    assert t.status == "resolved" and "behoben" in t.comments[-1].text


def test_ticket_processing(app, db, mock, zbx):
    from servermanager.models import SystemAccess, Ticket
    _problem(mock, "7001", "Festplatte voll", 4, "web01", manual_close=True)
    _problem(mock, "7002", "Backup fehlt", 3, "web01", manual_close=False)
    from servermanager import integrations
    integrations.poll(db, zbx["z"])
    db.commit()
    t1 = db.query(Ticket).filter_by(event_id="7001").one()
    t2 = db.query(Ticket).filter_by(event_id="7002").one()
    make_user(db, "tk-admin", "admin")
    c = login(app, "tk-admin")
    assert "Festplatte voll" in c.get("/tickets/").text
    assert "Tickets" in c.get("/").text
    r = c.post(f"/tickets/{t1.id}", data={"op": "take", "csrf_token": c.csrf}, follow_redirects=True)
    assert "in Zabbix bestätigt" in r.text
    ack = mock.state.zbx["acks"][-1]
    assert ack["eventids"] == ["7001"] and ack["action"] == 2 | 4 and ack["message"].startswith(tickets.OWN_PREFIX)
    c.post(f"/tickets/{t1.id}", data={"op": "comment", "text": "Logs rotiert", "to_zabbix": "1",
                                      "csrf_token": c.csrf})
    assert mock.state.zbx["acks"][-1]["action"] == 4 and "Logs rotiert" in mock.state.zbx["acks"][-1]["message"]
    r = c.post(f"/tickets/{t2.id}", data={"op": "close", "close_zabbix": "1", "csrf_token": c.csrf},
               follow_redirects=True)
    assert "In Zabbix nicht geschlossen" in r.text
    r = c.post(f"/tickets/{t1.id}", data={"op": "close", "close_zabbix": "1", "text": "Platz geschaffen",
                                          "csrf_token": c.csrf}, follow_redirects=True)
    assert "Ticket geschlossen" in r.text
    assert not any(p["eventid"] == "7001" for p in mock.state.zbx["problems"])
    db.expire_all()
    assert t1.status == "closed" and t1.assignee.username == "tk-admin"
    assert t2.status == "open"
    # rights: view on the system -> read only; nothing -> 403
    viewer = make_user(db, "tk-viewer")
    db.add(SystemAccess(user_id=viewer.id, system_id=zbx["system"].id, level="view"))
    db.commit()
    v = login(app, "tk-viewer")
    page = v.get(f"/tickets/{t2.id}").text
    assert "Backup fehlt" in page and "Übernehmen" not in page
    assert v.post(f"/tickets/{t2.id}", data={"op": "take", "csrf_token": v.csrf}).status_code == 403
    make_user(db, "tk-none")
    n = login(app, "tk-none")
    assert n.get(f"/tickets/{t2.id}").status_code == 403
    assert "Backup fehlt" not in n.get("/tickets/?status=all").text


def test_zabbix_pages(app, db, mock, zbx):
    make_user(db, "tk-admin", "admin")
    c = login(app, "tk-admin")
    zid = zbx["z"].id
    for tab in ("overview", "problems", "hosts", "tickets"):
        r = c.get(f"/zabbix/{zid}?tab={tab}")
        assert r.status_code == 200, (tab, r.text[:300])
    assert "web01" in c.get(f"/zabbix/{zid}?tab=hosts").text
    assert c.get("/zabbix/").status_code == 200 and c.get("/zabbix/new").status_code == 200
    from servermanager import settings
    old_hash = zbx["z"].webhook_hash
    settings.set(db, "general.base_url", "https://sm.example.com")
    db.commit()
    r = c.post(f"/zabbix/{zid}/webhook", data={"csrf_token": c.csrf}, follow_redirects=True)
    assert "Ticket-Schnittstelle in Zabbix eingerichtet" in r.text
    db.expire_all()
    assert zbx["z"].webhook_hash != old_hash and zbx["z"].setup["url"] == f"https://sm.example.com/api/zabbix/{zid}/event"
    params = {p["name"]: p["value"] for p in mock.state.zbx["mediatypes"][0]["parameters"]}
    assert tickets.token_ok(zbx["z"], params["Token"])
    settings.set(db, "general.base_url", "")
    db.commit()


def test_agent_job(db, mock, zbx, monkeypatch):
    from servermanager.jobs import enqueue, log_path
    from servermanager.models import Job, ZabbixHost
    from servermanager.worker import Worker
    seen = {}

    class FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def run_script(self, body, env=None, root=False, on_output=None, cancel=None, timeout=0):
            seen.update(env)
            on_output(f"configured with {env['SM_ZBX_PSK']}\nSM_OK\n")
            return 0
    monkeypatch.setattr(Worker, "_connect", lambda self, ctx, system: FakeConn())
    job = enqueue(db, kind="zabbix_agent", title="agent", system=zbx["system"],
                  payload={"zabbix_id": zbx["z"].id, "ip": "10.30.0.60"})
    db.commit()
    from tests.test_integrations import _run
    _run(job.id)
    db.expire_all()
    job = db.get(Job, job.id)
    log = log_path(job.id).read_text()
    assert job.status == "success", log
    assert seen["SM_ZBX_PSK"] not in log and "***" in log
    zh = db.query(ZabbixHost).filter_by(system_id=zbx["system"].id).one()
    host = next(h for h in mock.state.zbx["hosts"] if h["hostid"] == zh.hostid)
    assert host["tls_psk"] == security.decrypt(zh.psk_enc) == seen["SM_ZBX_PSK"]
    assert host["tls_connect"] == 2 and host["interfaces"][0]["ip"] == "10.30.0.60"
    assert host["templates"] == [{"templateid": "10001"}]
    assert seen["SM_ZBX_SERVER"] == "10.20.0.5" and seen["SM_ZBX_VERSION"] == "7.0"
    assert "Docker by Zabbix agent 2: nicht gefunden" in log
    # second run: same PSK, host updated instead of created
    job2 = enqueue(db, kind="zabbix_agent", title="agent", system=zbx["system"],
                   payload={"zabbix_id": zbx["z"].id, "ip": ""})
    db.commit()
    _run(job2.id)
    db.expire_all()
    assert db.get(Job, job2.id).status == "success" and "aktualisiert" in db.get(Job, job2.id).summary
    assert len([h for h in mock.state.zbx["hosts"] if h["host"] == "web01"]) == 1


def test_agent_script(tmp_path):
    b = tmp_path / "bin"
    b.mkdir()
    for name, body in {"zabbix_agent2": "echo 'zabbix_agent2 (Zabbix) 7.0.5'", "systemctl": "exit 0",
                       "chown": "exit 0", "usermod": "exit 0", "journalctl": "exit 0"}.items():
        (b / name).write_text(f"#!/bin/bash\n{body}\n")
        (b / name).chmod(0o755)
    zdir = tmp_path / "zabbix"
    zdir.mkdir()
    (zdir / "zabbix_agent2.conf").write_text("Server=127.0.0.1\nServerActive=127.0.0.1\nHostname=Zabbix server\n"
                                             "LogFile=/var/log/zabbix/zabbix_agent2.log\n")
    env = {**os.environ, "PATH": f"{b}:{os.environ['PATH']}", "SM_ZBX_DIR": str(zdir), "SM_ZBX_WAIT": "0",
           "SM_ZBX_SERVER": "10.20.0.5", "SM_ZBX_HOSTNAME": "web01", "SM_ZBX_PSK_ID": "servermanager-1",
           "SM_ZBX_PSK": "ab" * 32}
    body = (SCRIPTS / "lib.sh").read_text() + "\n" + (SCRIPTS / "zabbix_agent.sh").read_text()
    res = subprocess.run(["bash", "-c", body], capture_output=True, text=True, env=env)
    assert res.returncode == 0 and "SM_OK" in res.stdout, res.stdout + res.stderr
    main = (zdir / "zabbix_agent2.conf").read_text()
    assert "# servermanager: Server=127.0.0.1" in main and f"Include={zdir}/servermanager-agent2.conf" in main
    assert "LogFile=" in main and "\nServer=" not in main
    own = (zdir / "servermanager-agent2.conf").read_text()
    assert "Server=10.20.0.5" in own and "TLSPSKIdentity=servermanager-1" in own and "Hostname=web01" in own
    assert (zdir / "servermanager.psk").read_text().strip() == "ab" * 32
    assert oct((zdir / "servermanager.psk").stat().st_mode)[-3:] == "640"
    # repeated run keeps a single include line
    subprocess.run(["bash", "-c", body], capture_output=True, text=True, env=env, check=True)
    assert (zdir / "zabbix_agent2.conf").read_text().count("Include=") == 1
    bad = dict(env, SM_ZBX_PSK="nicht-hex")
    res = subprocess.run(["bash", "-c", body], capture_output=True, text=True, env=bad)
    assert res.returncode == 1 and "Ungültiger PSK" in res.stdout
