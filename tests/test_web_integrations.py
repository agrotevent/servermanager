"""Web pages and permissions of the Proxmox / RouterOS / Pangolin integration."""
import pytest

from servermanager import security
from servermanager.models import (IntegrationAccess, Job, PangolinServer, PveServer, RouterDevice, System,
                                  SystemAccess)
from tests import mock_apis as m
from tests.test_web import login, make_user


@pytest.fixture(scope="module")
def mock():
    srv = m.MockServer().start()
    yield srv
    srv.stop()


@pytest.fixture(scope="module")
def env(app, mock, data_dir):
    from servermanager.db import new_session
    db = new_session()
    make_user(db, "i-admin", "admin")
    viewer = make_user(db, "i-viewer", "user")
    operator = make_user(db, "i-op", "user")
    make_user(db, "i-none", "user")
    router = RouterDevice(name="chr-web", api_url=mock.url, username=m.ROS_USER,
                          password_enc=security.encrypt(m.ROS_PASS), fingerprint=mock.fingerprint)
    pg = PangolinServer(name="pg-web", api_url=mock.url, org_id=m.PG_ORG, api_key_enc=security.encrypt(m.PG_KEY),
                        fingerprint=mock.fingerprint, default_site_id=1, default_domain_id="dom1")
    db.add_all([router, pg])
    db.flush()
    srv = PveServer(name="pve-web", api_url=mock.url, token_id=m.PVE_TOKEN,
                    token_secret_enc=security.encrypt(m.PVE_SECRET), fingerprint=mock.fingerprint,
                    router_id=router.id, pangolin_id=pg.id)
    db.add(srv)
    db.flush()
    system = System(name="newt-sys", host="10.20.0.100", types=["debian"], pve_server_id=srv.id, pve_vmid=100)
    db.add(system)
    db.flush()
    db.add_all([
        IntegrationAccess(user_id=viewer.id, kind="pve", obj_id=srv.id, level="view"),
        IntegrationAccess(user_id=viewer.id, kind="router", obj_id=router.id, level="view"),
        IntegrationAccess(user_id=operator.id, kind="pve", obj_id=srv.id, level="operate"),
        SystemAccess(user_id=operator.id, system_id=system.id, level="operate"),
    ])
    db.commit()
    ids = {"pve": srv.id, "router": router.id, "pg": pg.id, "system": system.id}
    db.close()
    return ids


def test_admin_pages_render(app, env):
    c = login(app, "i-admin")
    pid, rid, gid = env["pve"], env["router"], env["pg"]
    pages = ["/proxmox/", f"/proxmox/{pid}", f"/proxmox/{pid}?tab=qemu", f"/proxmox/{pid}?tab=nodes",
             f"/proxmox/{pid}?tab=jobs", f"/proxmox/{pid}/guest/pve1/lxc/100", f"/proxmox/{pid}/guest/pve1/lxc/100?tf=day",
             f"/proxmox/{pid}/guest/pve1/qemu/200", f"/proxmox/{pid}/create", f"/proxmox/{pid}/edit", "/proxmox/new",
             "/routeros/", "/routeros/new", f"/routeros/{rid}/edit",
             *[f"/routeros/{rid}?tab={t}" for t in ("overview", "dhcp", "nat", "routing", "firewall", "dns", "analysis")],
             "/pangolin/", "/pangolin/new", f"/pangolin/{gid}", f"/pangolin/{gid}/edit", f"/pangolin/{gid}/publish",
             f"/systems/{env['system']}", f"/systems/{env['system']}/edit", "/users/new", "/settings"]
    for url in pages:
        r = c.get(url)
        assert r.status_code == 200, (url, r.status_code, r.text[:300])
    r = c.get(f"/proxmox/{pid}/guest/pve1/lxc/100")
    assert "data-points" in r.text and "CPU-Auslastung" in r.text
    assert "Proxmox" in c.get("/").text  # navigation


def test_router_analysis_import_and_apply(app, env, mock):
    c = login(app, "i-admin")
    rid = env["router"]
    r = c.post(f"/routeros/{rid}/import", data={"source": "export", "export": m.EXPORT, "csrf_token": c.csrf},
               follow_redirects=True)
    assert "Konfiguration importiert" in r.text and "Masquerade ohne Ausgangs-Interface" in r.text
    r = c.get(f"/routeros/{rid}/script.rsc")
    assert r.status_code == 200 and "/ip firewall filter" in r.text
    r = c.post(f"/routeros/{rid}/apply", data={"fid": ["lan.network", "dns.remote"], "csrf_token": c.csrf},
               follow_redirects=True)
    assert "Änderung(en) angewendet" in r.text, r.text[:2000]
    net = next(n for n in mock.state.ros["ip/dhcp-server/network"] if n["address"] == "10.20.0.0/24")
    assert net["dns-server"] == "10.20.0.1"
    assert mock.state.ros["ip/dns"][0]["allow-remote-requests"] == "true"


def test_viewer_is_read_only(app, env):
    c = login(app, "i-viewer")
    pid, rid = env["pve"], env["router"]
    assert c.get(f"/proxmox/{pid}").status_code == 200
    assert c.get(f"/routeros/{rid}?tab=dhcp").status_code == 200
    assert c.post(f"/proxmox/{pid}/guest/pve1/lxc/100/op", data={"op": "start", "csrf_token": c.csrf}).status_code == 403
    assert c.get(f"/proxmox/{pid}/create").status_code == 403
    assert c.post(f"/routeros/{rid}/do", data={"action": "lease_static", "id": "*1", "csrf_token": c.csrf}).status_code == 403
    assert c.post(f"/routeros/{rid}/import", data={"source": "api", "csrf_token": c.csrf}).status_code == 403
    assert c.get(f"/pangolin/{env['pg']}").status_code == 403
    assert c.get(f"/proxmox/{pid}/edit").status_code == 403


def test_no_access(app, env):
    c = login(app, "i-none")
    assert c.get("/proxmox/").status_code == 403
    assert c.get(f"/proxmox/{env['pve']}").status_code == 403
    assert c.get(f"/routeros/{env['router']}").status_code == 403
    assert "Proxmox" not in c.get("/").text.split("<main")[0]


def test_operator_can_start_but_not_delete(app, env, db):
    c = login(app, "i-op")
    pid = env["pve"]
    r = c.post(f"/proxmox/{pid}/guest/pve1/qemu/200/op", data={"op": "start", "csrf_token": c.csrf})
    assert r.status_code == 302
    job = db.query(Job).filter(Job.pve_id == pid).order_by(Job.id.desc()).first()
    assert job.payload["op"] == "start" and job.payload["vmid"] == 200
    assert c.get(f"/jobs/{job.id}").status_code == 200
    r = c.post(f"/proxmox/{pid}/guest/pve1/qemu/200/op",
               data={"op": "destroy", "confirm_vmid": "200", "csrf_token": c.csrf})
    assert r.status_code == 403
    # suspend is a VM-only operation
    assert c.post(f"/proxmox/{pid}/guest/pve1/lxc/100/op", data={"op": "suspend", "csrf_token": c.csrf}).status_code == 400


def test_power_control_via_system_permission(app, env, db):
    from servermanager import integrations
    srv = db.get(PveServer, env["pve"])
    integrations.poll(db, srv)
    db.commit()
    c = login(app, "i-op")
    r = c.post(f"/proxmox/system/{env['system']}/op", data={"op": "reboot", "csrf_token": c.csrf})
    assert r.status_code == 302
    job = db.query(Job).filter(Job.system_id == env["system"]).order_by(Job.id.desc()).first()
    assert job.kind == "pve" and job.payload["op"] == "reboot" and job.payload["vmid"] == 100
    assert c.post(f"/proxmox/system/{env['system']}/op", data={"op": "destroy", "csrf_token": c.csrf}).status_code == 400
    v = login(app, "i-viewer")
    assert v.post(f"/proxmox/system/{env['system']}/op", data={"op": "reboot", "csrf_token": v.csrf}).status_code == 403


def test_only_admin_links_systems_to_guests(app, env, db):
    """Linking grants power control - a manager must not be able to link his system to a foreign guest."""
    make_user(db, "i-mgr", "manager")
    c = login(app, "i-mgr")
    r = c.post("/systems/new", data={"name": "mgr-sys", "host": "10.1.1.1", "port": "22", "username": "root",
                                     "auth_method": "password", "password": "x" * 12, "pve_server_id": str(env["pve"]),
                                     "pve_vmid": "200", "csrf_token": c.csrf})
    assert r.status_code == 302
    s = db.query(System).filter_by(name="mgr-sys").one()
    assert s.pve_server_id is None and s.pve_vmid is None


def test_create_form_validation(app, env):
    c = login(app, "i-admin")
    r = c.post(f"/proxmox/{env['pve']}/create", data={"node": "pve1", "hostname": "bad host", "csrf_token": c.csrf})
    assert r.status_code == 200 and "Ungültiger Hostname" in r.text


def test_pangolin_publish_page(app, env, mock):
    c = login(app, "i-admin")
    r = c.post(f"/pangolin/{env['pg']}/publish", data={
        "name": "Cloud", "protocol": "http", "subdomain": "cloud", "domain_id": "dom1", "site_id": "1",
        "ip": "10.20.0.100", "port": "443", "method": "https", "sso": "1", "csrf_token": c.csrf},
        follow_redirects=True)
    assert "Veröffentlicht: cloud.example.com" in r.text
    res = next(x for x in mock.state.resources.values() if x["name"] == "Cloud")
    assert res["sso"] is True
    t = next(x for x in mock.state.targets.values() if x["resourceId"] == res["resourceId"])
    assert t["method"] == "https" and t["port"] == 443


def test_user_form_assigns_integration_access(app, env, db):
    c = login(app, "i-admin")
    u = make_user(db, "i-new", "user")
    r = c.post(f"/users/{u.id}", data={"display_name": "", "email": "", "role": "user", "active": "1",
                                       f"int_router_{env['router']}": "operate", "csrf_token": c.csrf})
    assert r.status_code == 302
    rows = db.query(IntegrationAccess).filter_by(user_id=u.id).all()
    assert [(x.kind, x.obj_id, x.level) for x in rows] == [("router", env["router"], "operate")]


def test_no_open_redirect_and_id_required(app, env):
    c = login(app, "i-admin")
    r = c.post(f"/proxmox/{env['pve']}/guest/100/watch", data={"next": "https://evil.example/", "csrf_token": c.csrf})
    assert r.status_code == 302 and "evil" not in r.headers["Location"]
    r = c.post(f"/proxmox/{env['pve']}/guest/100/watch", data={"next": "//evil.example/", "csrf_token": c.csrf})
    assert "evil" not in r.headers["Location"]
    assert c.post(f"/routeros/{env['router']}/do", data={"action": "lease_delete", "csrf_token": c.csrf}).status_code == 400


def test_operator_sees_and_cancels_pve_jobs(app, env, db):
    from servermanager.jobs import enqueue
    from servermanager.models import User
    admin = db.query(User).filter_by(username="i-admin").one()
    job = enqueue(db, kind="pve", title="admin-job", user=admin, pve_id=env["pve"],
                  payload={"op": "start", "node": "pve1", "type": "qemu", "vmid": 200, "params": {}})
    db.commit()
    c = login(app, "i-op")
    assert "admin-job" in c.get("/jobs/").text
    r = c.post(f"/jobs/{job.id}/cancel", data={"csrf_token": c.csrf})
    assert r.status_code == 302
    v = login(app, "i-viewer")
    assert v.post(f"/jobs/{job.id}/cancel", data={"csrf_token": v.csrf}).status_code == 403


def test_update_branch_missing_and_switch(app, db, monkeypatch):
    import dataclasses
    from servermanager import config, selfupdate
    from servermanager.helper import HelperError
    cfg = dataclasses.replace(config.get_config(), use_sudo=True, branch="main")
    monkeypatch.setattr(selfupdate, "get_config", lambda: cfg)
    calls = []

    def fake_helper(*args, **kw):
        calls.append(args)
        if args[0] == "git-fetch":
            raise HelperError("fatal: couldn't find remote ref main")
        if args[0] == "git-branches":
            return "branch=claude/dev\nbranch=stable\ndefault=claude/dev\ncurrent=main\n"
        if args[0] == "set-branch":
            return f"Update-Branch ist jetzt '{args[1]}'."
        return "none"
    monkeypatch.setattr(selfupdate, "run_helper", fake_helper)
    monkeypatch.setattr(config, "load_config", lambda: cfg)
    with pytest.raises(selfupdate.BranchMissing):
        selfupdate.check()
    b = selfupdate.branches()
    assert b["missing"] and b["default"] == "claude/dev" and b["branches"][0] == "claude/dev"
    c = login(app, "i-admin")
    r = c.get("/update")
    assert "existiert im Repository nicht" in r.text and "claude/dev (Standard)" in r.text
    r = c.post("/update/check", data={"csrf_token": c.csrf}, follow_redirects=True)
    assert "Update-Branch" in r.text and "couldn" not in r.text
    r = c.post("/update/branch", data={"branch": "stable", "csrf_token": c.csrf}, follow_redirects=True)
    assert "Update-Branch ist jetzt" in r.text and ("set-branch", "stable") in calls
    r = c.post("/update/branch", data={"branch": "bad;rm", "csrf_token": c.csrf}, follow_redirects=True)
    assert "Ungültiger Branch-Name" in r.text
