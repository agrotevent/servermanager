"""Hetzner Cloud: client, synchronisation, rights (Auswerten / Neustarten / Ändern) per project and server."""
import pytest

from servermanager import hcloud, security
from servermanager.hcloud import Cloud, CloudError
from tests import mock_apis as m
from tests.test_web import login, make_user


@pytest.fixture(scope="module")
def mock():
    srv = m.MockServer().start()
    yield srv
    srv.stop()


def cloud(mock, token=m.HC_TOKEN):
    return Cloud(token, base=f"{mock.url}/hcloud/v1", fingerprint=mock.fingerprint)


@pytest.fixture()
def project(db, mock):
    from servermanager.models import HcloudProject, HcloudServer
    p = HcloudProject(name="hc", token_enc=security.encrypt(m.HC_TOKEN), api_url=f"{mock.url}/hcloud/v1",
                      fingerprint=mock.fingerprint, traffic_alert_pct=90)
    db.add(p)
    db.commit()
    yield p
    db.query(HcloudServer).filter_by(project_id=p.id).delete()
    db.delete(p)
    db.commit()


def test_client_and_helpers(mock):
    c = cloud(mock)
    servers = c.servers()  # one per page in the mock: pagination is followed
    assert [s["id"] for s in servers] == [1001, 1002]
    floating = c.floating_ips()
    rows = hcloud.addresses(servers[0], floating)
    assert [(r["ip"], r["kind"]) for r in rows] == [("49.12.0.10", "primary"), ("2a01:4f8:c0c:1::1", "primary"),
                                                    ("78.46.0.5", "floating")]
    assert hcloud.owner_of("2a01:4f8:c0c:1::abc", servers[0], floating) == 0
    assert hcloud.owner_of("78.46.0.5", servers[0], floating) == 77
    assert hcloud.owner_of("49.12.0.11", servers[0], floating) is None  # other server
    assert hcloud.owner_of("2a01:4f8:c0c:2::1", servers[0], floating) is None
    with pytest.raises(CloudError, match="Lesen & Schreiben"):
        cloud(mock, m.HC_RO_TOKEN).power(1001, "reboot")
    with pytest.raises(CloudError, match="ungültig"):
        cloud(mock, "wrong").servers()
    with pytest.raises(CloudError, match="Servername"):
        c.rename(1001, "kein name")
    with pytest.raises(CloudError, match="https"):
        Cloud("x", base="http://api.example.com")


def test_sync_and_alerts(db, mock, project):
    from servermanager import integrations
    from servermanager.models import HcloudServer, System
    sys_ = System(name="web-1-sys", host="49.12.0.10")
    db.add(sys_)
    db.commit()
    try:
        integrations.poll(db, project)
        db.commit()
        assert project.status == "online", project.status_message
        rows = {r.cloud_id: r for r in db.query(HcloudServer).filter_by(project_id=project.id)}
        web, dbs = rows[1001], rows[1002]
        assert web.system_id == sys_.id and web.server_type == "cx32" and web.location == "Falkenstein"
        assert dbs.status == "off" and project.data["running"] == 1
        assert {r["ip"] for r in web.info["ips"]} == {"49.12.0.10", "2a01:4f8:c0c:1::1", "78.46.0.5"}
        keys = {a["key"]: a for a in project.alerts}
        over = keys["traffic:1002"]  # 19 of 20 TB = 95 %
        assert over["severity"] == "warn" and "95 %" in over["text"]
        assert "traffic:1001" not in keys
        gone = mock.state.hc_servers.pop()
        try:
            integrations.poll(db, project)
            db.commit()
            assert {r.cloud_id for r in db.query(HcloudServer).filter_by(project_id=project.id)} == {1001}
        finally:
            mock.state.hc_servers.append(gone)
    finally:
        db.delete(sys_)
        db.commit()


def test_rights_per_project_and_server(app, db, mock, project):
    from servermanager import integrations
    from servermanager.models import HcloudServer, IntegrationAccess
    integrations.poll(db, project)
    db.commit()
    rows = {r.cloud_id: r for r in db.query(HcloudServer).filter_by(project_id=project.id)}
    web, dbs = rows[1001], rows[1002]
    viewer, rebooter, changer = make_user(db, "hc-view"), make_user(db, "hc-reboot"), make_user(db, "hc-change")
    db.add_all([IntegrationAccess(user_id=viewer.id, kind="hcloud_srv", obj_id=web.id, level="view"),
                IntegrationAccess(user_id=rebooter.id, kind="hcloud_srv", obj_id=web.id, level="operate"),
                IntegrationAccess(user_id=changer.id, kind="hcloud", obj_id=project.id, level="full")])
    db.commit()
    st = mock.state
    try:
        c = login(app, "hc-view")
        page = c.get("/hetzner/").text
        assert "web-1" in page and "db-1" not in page
        page = c.get(f"/hetzner/cloud/server/{web.id}").text
        assert "web-1.example.com" in page and "Für Neustarts fehlt" in page and "CPU-Auslastung" in page
        assert c.get(f"/hetzner/cloud/server/{dbs.id}").status_code == 403
        assert c.post(f"/hetzner/cloud/server/{web.id}/power", data={"action": "reboot",
                                                                     "csrf_token": c.csrf}).status_code == 403
        c = login(app, "hc-reboot")
        n = len(st.hc_actions)
        for action in ("reboot", "reset"):
            assert c.post(f"/hetzner/cloud/server/{web.id}/power",
                          data={"action": action, "csrf_token": c.csrf}).status_code == 302
        assert st.hc_actions[n:] == [(1001, "reboot"), (1001, "reset")]
        assert c.post(f"/hetzner/cloud/server/{web.id}/ptr", data={"ip": "49.12.0.10", "ptr": "x.example.com",
                                                                   "csrf_token": c.csrf}).status_code == 403
        assert c.post(f"/hetzner/cloud/server/{web.id}/rename", data={"name": "x",
                                                                      "csrf_token": c.csrf}).status_code == 403
        c = login(app, "hc-change")
        assert "db-1" in c.get("/hetzner/").text
        c.post(f"/hetzner/cloud/server/{web.id}/ptr", data={"ip": "49.12.0.10", "ptr": "Web.Example.com",
                                                            "csrf_token": c.csrf})
        assert st.hc_actions[-1] == (1001, "ptr", "49.12.0.10", "web.example.com")
        c.post(f"/hetzner/cloud/server/{web.id}/ptr", data={"ip": "2a01:4f8:c0c:1::25", "ptr": "v6.example.com",
                                                            "csrf_token": c.csrf})
        assert st.hc_actions[-1] == (1001, "ptr", "2a01:4f8:c0c:1::25", "v6.example.com")
        c.post(f"/hetzner/cloud/server/{web.id}/ptr", data={"ip": "78.46.0.5", "ptr": "", "csrf_token": c.csrf})
        assert st.hc_actions[-1] == (77, "fptr", "78.46.0.5", None)  # floating IP endpoint, reset to default
        r = c.post(f"/hetzner/cloud/server/{web.id}/ptr", data={"ip": "49.12.0.11", "ptr": "steal.example.com",
                                                                "csrf_token": c.csrf})
        assert r.status_code == 400  # address of another server
        c.post(f"/hetzner/cloud/server/{web.id}/rename", data={"name": "web-01", "csrf_token": c.csrf})
        assert st.hc_servers[0]["name"] == "web-01"
        st.hc_servers[0]["name"] = "web-1"
        assert c.get(f"/hetzner/cloud/project/{project.id}/edit").status_code == 403
        # a power-off server only offers "Einschalten"
        page = c.get(f"/hetzner/cloud/server/{dbs.id}").text
        assert 'value="poweron"' in page and 'value="reboot"' not in page
    finally:
        for u in (viewer, rebooter, changer):
            db.query(IntegrationAccess).filter_by(user_id=u.id).delete()
            db.delete(u)
        db.commit()


def test_read_only_token_and_admin_pages(app, db, mock, project, monkeypatch):
    from servermanager import integrations
    from servermanager.models import HcloudProject, HcloudServer
    project.token_enc = security.encrypt(m.HC_RO_TOKEN)
    db.commit()
    integrations.poll(db, project)
    db.commit()
    assert project.status == "online"  # reading works with a read-only token
    make_user(db, "hc-admin", "admin")
    c = login(app, "hc-admin")
    web = db.query(HcloudServer).filter_by(project_id=project.id, cloud_id=1001).one()
    c.post(f"/hetzner/cloud/server/{web.id}/power", data={"action": "reboot", "csrf_token": c.csrf})
    assert "Lesen &amp; Schreiben" in c.get(f"/hetzner/cloud/server/{web.id}").text

    def offline(self, *a, **k):
        raise CloudError("Hetzner Cloud nicht erreichbar: Testumgebung")
    monkeypatch.setattr(Cloud, "request", offline)  # never call the real API from tests
    assert "API-Tokens" in c.get("/hetzner/cloud/new").text
    r = c.post("/hetzner/cloud/new", data={"name": "hc-neu", "token": "abc", "traffic_alert_pct": "90",
                                           "monitor": "1", "csrf_token": c.csrf})
    assert r.status_code == 302
    p = db.query(HcloudProject).filter_by(name="hc-neu").one()
    assert p.status == "error" and security.decrypt(p.token_enc) == "abc"
    assert "Hetzner Cloud-Server" in c.get("/users/new").text
    c.post(f"/hetzner/cloud/project/{p.id}/delete", data={"csrf_token": c.csrf})
    assert not db.query(HcloudProject).filter_by(name="hc-neu").first()
