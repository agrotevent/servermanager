import re

import pytest

from servermanager import security, settings
from servermanager.models import (LEVEL_OPERATE, LEVEL_VIEW, Job, MaintenanceSchedule, System, SystemAccess, User)


@pytest.fixture(scope="module")
def db(data_dir):
    from servermanager.db import new_session
    s = new_session()
    yield s
    s.close()


@pytest.fixture(autouse=True)
def _fresh(db):
    db.expire_all()
    yield


def csrf_of(client):
    r = client.get("/login")
    m = re.search(r'name="csrf-token" content="([^"]+)"', r.text) or \
        re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    return m.group(1)


def make_user(db, name, role="user", pw="Sehr-Geheim-123"):
    u = db.query(User).filter_by(username=name).first()
    if u is None:
        u = User(username=name, password_hash=security.hash_password(pw), role=role)
        db.add(u)
        db.commit()
    return u


def login(app, name, pw="Sehr-Geheim-123"):
    c = app.test_client()
    tok = csrf_of(c)
    r = c.post("/login", data={"username": name, "password": pw, "csrf_token": tok})
    assert r.status_code == 302, r.text[:500]
    r = c.get("/profile")
    c.csrf = re.search(r'name="csrf-token" content="([^"]+)"', r.text).group(1)
    return c


@pytest.fixture(scope="module")
def setup(app, db):
    make_user(db, "admin1", "admin")
    make_user(db, "viewer1", "user")
    make_user(db, "op1", "user")
    s = System(name="srv1", host="192.0.2.10", types=["debian", "docker"])
    s2 = System(name="srv2", host="192.0.2.11", types=["debian"])
    db.add_all([s, s2])
    db.commit()
    v = db.query(User).filter_by(username="viewer1").one()
    o = db.query(User).filter_by(username="op1").one()
    db.add_all([SystemAccess(user_id=v.id, system_id=s.id, level=LEVEL_VIEW),
                SystemAccess(user_id=o.id, system_id=s.id, level=LEVEL_OPERATE)])
    db.commit()
    return {"s1": s.id, "s2": s2.id}


def test_login_required(app):
    c = app.test_client()
    r = c.get("/systems/")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_wrong_password(app, setup):
    c = app.test_client()
    tok = csrf_of(c)
    r = c.post("/login", data={"username": "admin1", "password": "nope", "csrf_token": tok})
    assert r.status_code == 401


def test_csrf_enforced(app, setup):
    c = login(app, "admin1")
    r = c.post(f"/systems/{setup['s1']}/check", data={})
    assert r.status_code == 400
    r = c.post(f"/systems/{setup['s1']}/check", data={"csrf_token": c.csrf})
    assert r.status_code == 302 and "/jobs/" in r.headers["Location"]


def test_security_headers(app):
    r = app.test_client().get("/login")
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "script-src 'self'" in r.headers["Content-Security-Policy"]


def test_visibility_and_levels(app, setup, db):
    viewer = login(app, "viewer1")
    r = viewer.get("/systems/")
    assert "srv1" in r.text and "srv2" not in r.text
    assert viewer.get(f"/systems/{setup['s2']}").status_code == 403
    assert viewer.get(f"/systems/{setup['s1']}").status_code == 200
    # viewer may not run actions
    r = viewer.post(f"/systems/{setup['s1']}/action", data={"csrf_token": viewer.csrf, "module": "debian",
                                                            "action": "upgrade"})
    assert r.status_code == 403
    # admin pages forbidden
    assert viewer.get("/users/").status_code == 403
    assert viewer.get("/settings").status_code == 403
    assert viewer.get("/enrollment").status_code == 403


def test_operator_actions(app, setup, db):
    op = login(app, "op1")
    before = db.query(Job).count()
    r = op.post(f"/systems/{setup['s1']}/action", data={"csrf_token": op.csrf, "module": "docker",
                                                        "action": "container_restart", "container": "web"})
    assert r.status_code == 302
    assert db.query(Job).count() == before + 1
    # full level action is denied for operators
    r = op.post(f"/systems/{setup['s1']}/action", data={"csrf_token": op.csrf, "module": "debian",
                                                        "action": "release_upgrade", "third_party": "keep"})
    assert r.status_code == 403
    r = op.post(f"/systems/{setup['s1']}/command", data={"csrf_token": op.csrf, "command": "id"})
    assert r.status_code == 403
    # injection in parameters is rejected
    r = op.post(f"/systems/{setup['s1']}/action", data={"csrf_token": op.csrf, "module": "docker",
                                                        "action": "container_restart", "container": "x;id"})
    assert r.status_code == 302 and "/systems/" in r.headers["Location"]
    assert db.query(Job).count() == before + 1


def test_schedule_create_and_permissions(app, setup, db):
    op = login(app, "op1")
    r = op.post("/schedules/new", data={
        "csrf_token": op.csrf, "name": "Nachts", "recurrence": "weekly", "time_of_day": "02:00",
        "weekdays": ["5", "6"], "systems": [str(setup["s1"]), str(setup["s2"])], "steps": ["debian.upgrade"],
        "reboot_policy": "if_required", "only_if_updates": "1", "stop_on_error": "1", "enabled": "1",
        "max_parallel": "2", "window_minutes": "120"})
    assert r.status_code == 302, r.text[:1000]
    s = db.query(MaintenanceSchedule).filter_by(name="Nachts").one()
    assert s.system_ids == [setup["s1"]]  # srv2 is not accessible for op1
    assert s.next_run_at is not None and s.weekdays == [5, 6]
    # commands require full access
    r = op.post("/schedules/new", data={"csrf_token": op.csrf, "name": "Cmd", "recurrence": "daily",
                                        "time_of_day": "01:00", "systems": [str(setup["s1"])],
                                        "command": "reboot", "reboot_policy": "never", "enabled": "1"})
    assert r.status_code == 200 and "Vollzugriff" in r.text
    # run now creates a maintenance job
    r = op.post(f"/schedules/{s.id}/run", data={"csrf_token": op.csrf})
    assert r.status_code == 302
    assert db.query(Job).filter_by(kind="maintenance", system_id=setup["s1"]).count() >= 1


def test_updates_overview(app, setup, db):
    s = db.get(System, setup["s1"])
    s.updates = {"apt": {"count": 3, "security": 1, "packages": [
        {"name": "openssl", "current": "1", "new": "2", "origin": "x-security", "security": True}]},
        "reboot": {"required": True}, "docker": {"updates": [{"container": "web", "image": "nginx"}]}}
    s.facts = {"os_id": "debian", "os_version": "12", "os_name": "Debian 12"}
    db.commit()
    admin = login(app, "admin1")
    r = admin.get("/updates/?filter=security")
    assert r.status_code == 200 and "srv1" in r.text and "openssl" in r.text
    r = admin.get("/updates/?filter=release")
    assert "srv1" in r.text  # debian 12 -> 13 available


def test_enrollment_direct(app, setup, db):
    admin = login(app, "admin1")
    r = admin.post("/enrollment", data={"csrf_token": admin.csrf, "name": "neu1", "connection": "direct",
                                        "ssh_user_mode": "root", "valid_hours": "2", "max_uses": "1"})
    assert r.status_code == 302
    page = admin.get("/enrollment").text
    token = re.search(r"/enroll/([A-Za-z0-9_-]+)\.sh", page).group(1)
    script = app.test_client().get(f"/enroll/{token}.sh").text
    assert script.startswith("#!/bin/bash") and token in script and "SM_MODE='direct'" in script
    hk = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIlfoNZ+m5PzsrZ3cPfG9A3lBv6Zj3y4vMN8b6xq7x1A"
    c = app.test_client()
    r = c.post("/api/enroll", data={"token": token, "hostname": "neu1.example.com", "host_keys": hk,
                                    "address": "198.51.100.7", "ssh_port": "22", "root_login": "prohibit-password"})
    assert r.status_code == 200, r.text
    vals = dict(line.split("=", 1) for line in r.text.strip().splitlines())
    assert vals["SM_STATUS"] == "ok" and vals["SM_SSH_USER"] == "root"
    sid = int(vals["SM_SYSTEM_ID"])
    s = db.get(System, sid)
    db.refresh(s)
    assert s.host == "198.51.100.7" and s.status == "pending" and s.host_keys.startswith("ssh-ed25519")
    # token is single use
    r = c.post("/api/enroll", data={"token": token, "hostname": "x", "host_keys": hk})
    assert r.status_code == 403
    # confirm with wrong secret fails, correct one queues verification
    assert c.post("/api/enroll/confirm", data={"system_id": sid, "secret": "x", "status": "ok"}).status_code == 403
    assert c.post("/api/enroll/confirm", data={"system_id": sid, "secret": vals["SM_CONFIRM_SECRET"],
                                               "status": "ok"}).status_code == 200
    assert db.query(Job).filter_by(kind="enroll_verify", system_id=sid).count() == 1


def test_enrollment_wireguard_with_mikrotik(app, setup, db, monkeypatch):
    from servermanager import enrollment, wireguard
    calls = []

    class FakeMT:
        def wg_peers(self, iface):
            return [{"allowed-address": "10.66.0.10/32"}]

        def add_peer(self, iface, pub, allowed, comment):
            calls.append(("peer", pub, allowed))
            return "*1"

        def add_address_list(self, lst, addr, comment):
            calls.append(("addr", addr))
            return "*2"

        def add_route(self, dst, gw, comment):
            calls.append(("route", dst))
            return "*3"

        def wg_interface(self, name):
            return {"public-key": wireguard.generate_keypair()[1]}

    monkeypatch.setattr(wireguard, "api", lambda db_: FakeMT())
    for k, v in {"wg.enabled": True, "wg.network": "10.66.0.0/24", "wg.router_ip": "10.66.0.1",
                 "wg.sm_ip": "10.66.0.2", "wg.pool_start": 10, "wg.endpoint": "vpn.example.com:13231",
                 "wg.router_public_key": ""}.items():
        settings.set(db, k, v)
    admin = db.query(User).filter_by(username="admin1").one()
    token, _ = enrollment.create_token(db, admin, name="", connection="wireguard", ssh_user_mode="root",
                                       types=["proxmox"], routed="192.168.50.0/24", tags="pve", assign=[],
                                       valid_hours=1, max_uses=1)
    db.commit()
    pub = wireguard.generate_keypair()[1]
    hk = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIlfoNZ+m5PzsrZ3cPfG9A3lBv6Zj3y4vMN8b6xq7x1A"
    r = app.test_client().post("/api/enroll", data={"token": token, "hostname": "pve9.example.com",
                                                    "host_keys": hk, "wg_public_key": pub, "root_login": "no"})
    assert r.status_code == 200, r.text
    vals = dict(line.split("=", 1) for line in r.text.strip().splitlines())
    assert vals["SM_WG_ADDRESS"] == "10.66.0.11/32"  # .10 is used by a manual peer on the router
    assert vals["SM_SSH_USER"] == "smadmin"  # root login disabled -> dedicated user
    assert vals["SM_ROUTED_SUBNETS"] == "192.168.50.0/24"
    assert ("route", "192.168.50.0/24") in calls
    assert ("peer", pub, ["10.66.0.11/32", "192.168.50.0/24"]) in calls
    s = db.get(System, int(vals["SM_SYSTEM_ID"]))
    db.refresh(s)
    assert s.has_type("proxmox") and s.sudo_mode == "nopasswd" and s.host == "10.66.0.11"


def test_admin_pages_render(app, setup):
    admin = login(app, "admin1")
    for url in ["/", "/systems/", f"/systems/{setup['s1']}?tab=updates", f"/systems/{setup['s1']}?tab=docker",
                "/updates/", "/schedules/", "/schedules/new", "/jobs/", "/enrollment", "/users/", "/settings",
                "/backups", "/audit", "/profile"]:
        assert admin.get(url).status_code == 200, url


def test_user_management(app, setup, db):
    admin = login(app, "admin1")
    r = admin.post("/users/new", data={"csrf_token": admin.csrf, "username": "neuer.user", "role": "manager",
                                       "active": "1", "password": "Gutes-Passwort-9", f"sys_{setup['s2']}": "operate"})
    assert r.status_code == 302
    u = db.query(User).filter_by(username="neuer.user").one()
    assert u.role == "manager"
    assert db.query(SystemAccess).filter_by(user_id=u.id, system_id=setup["s2"]).one().level == "operate"
    # last admin protection: admin cannot demote himself
    me = db.query(User).filter_by(username="admin1").one()
    r = admin.post(f"/users/{me.id}", data={"csrf_token": admin.csrf, "role": "user", "active": "1"})
    db.refresh(me)
    assert me.role == "admin"


def test_manager_cannot_use_global_key_for_new_systems(app, setup, db):
    make_user(db, "mgr1", "manager")
    mgr = login(app, "mgr1")
    base = {"csrf_token": mgr.csrf, "name": "fremd", "host": "192.0.2.99", "port": "22", "username": "root",
            "sudo_mode": "none", "connection": "direct", "backup_paths": "/etc"}
    r = mgr.post("/systems/new", data=dict(base, auth_method="key"))
    assert r.status_code == 200 and "Nur Administratoren" in r.text
    assert db.query(System).filter_by(name="fremd").count() == 0
    r = mgr.post("/systems/new", data=dict(base, auth_method="password", password="Ziel-Passwort-1",
                                           deploy_key="1"))
    assert r.status_code == 302
    s = db.query(System).filter_by(name="fremd").one()
    assert s.auth_method == "password"
    # the manager got full access to his own system
    assert db.query(SystemAccess).filter_by(system_id=s.id).one().level == "full"


def test_full_user_cannot_retarget_system(app, setup, db):
    u = make_user(db, "full1", "user")
    db.add(SystemAccess(user_id=u.id, system_id=setup["s2"], level="full"))
    db.commit()
    c = login(app, "full1")
    r = c.post(f"/systems/{setup['s2']}/edit", data={
        "csrf_token": c.csrf, "name": "srv2", "host": "198.51.100.66", "port": "22", "username": "root",
        "auth_method": "key", "sudo_mode": "none", "connection": "direct", "backup_paths": "/etc"})
    assert r.status_code == 200 and "Administratoren" in r.text
    assert db.get(System, setup["s2"]).host == "192.0.2.11"
    assert c.post(f"/systems/{setup['s2']}/hostkey-reset", data={"csrf_token": c.csrf}).status_code == 403
    # unchanged address: other fields may be edited
    r = c.post(f"/systems/{setup['s2']}/edit", data={
        "csrf_token": c.csrf, "name": "srv2", "host": "192.0.2.11", "port": "22", "username": "root",
        "auth_method": "key", "sudo_mode": "none", "connection": "direct", "backup_paths": "/etc /root",
        "description": "neu"})
    assert r.status_code == 302
    db.expire_all()
    assert db.get(System, setup["s2"]).backup_paths == "/etc /root"


def test_routed_subnet_validation(db):
    from servermanager import wireguard
    settings.set(db, "wg.network", "10.66.0.0/24")
    db.add(System(name="router-a", connection="wireguard", wg_ip="10.66.0.50", routed_subnets="172.20.0.0/16"))
    db.flush()
    for bad in ["0.0.0.0/0", "10.66.0.0/25", "172.20.5.0/24"]:
        with pytest.raises(ValueError):
            wireguard.validate_routed(db, wireguard.parse_subnets(bad))
    assert wireguard.validate_routed(db, ["192.168.77.0/24"]) == ["192.168.77.0/24"]
    db.rollback()


def test_direct_enrollment_uses_request_address_for_non_admin_tokens(app, setup, db):
    from servermanager import enrollment
    mgr = make_user(db, "mgr2", "manager")
    token, _ = enrollment.create_token(db, mgr, name="", connection="direct", ssh_user_mode="root", types=[],
                                       routed="", tags="", assign=[], valid_hours=1, max_uses=5)
    db.commit()
    hk = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIlfoNZ+m5PzsrZ3cPfG9A3lBv6Zj3y4vMN8b6xq7x1A"
    c = app.test_client()
    r = c.post("/api/enroll", data={"token": token, "hostname": "evil.example.com", "host_keys": hk,
                                    "address": "192.0.2.10", "ssh_port": "22"},
               environ_base={"REMOTE_ADDR": "203.0.113.5"})
    assert r.status_code == 200, r.text
    sid = int(dict(line.split("=", 1) for line in r.text.strip().splitlines())["SM_SYSTEM_ID"])
    s = db.get(System, sid)
    db.refresh(s)
    assert s.host == "203.0.113.5"  # not the requested 192.0.2.10
    # a second registration for an already managed address is refused
    r = c.post("/api/enroll", data={"token": token, "hostname": "evil2.example.com", "host_keys": hk,
                                    "ssh_port": "22"}, environ_base={"REMOTE_ADDR": "203.0.113.5"})
    assert r.status_code == 409


def test_cancel_queued_job(app, setup, db):
    from servermanager import jobs as jobs_mod
    s = db.get(System, setup["s1"])
    j = jobs_mod.enqueue(db, kind="check", title="x", system=s)
    db.commit()
    jobs_mod.request_cancel(db, j)
    db.commit()
    db.refresh(j)
    assert j.status == "cancelled" and not j.cancel_requested
    j2 = jobs_mod.enqueue(db, kind="check", title="y", system=s)
    j2.status = "running"
    db.commit()
    jobs_mod.request_cancel(db, j2)
    db.commit()
    db.refresh(j2)
    assert j2.status == "running" and j2.cancel_requested
