"""Existing infrastructure: management access, guest import, optimisation proposals, redundant Pangolin paths."""
import pytest

from servermanager import mgmt, optimize, security
from tests import mock_apis as m
from tests.test_integrations import _run


@pytest.fixture(scope="module")
def mocks():
    a, b = m.MockServer().start(), m.MockServer().start()
    b.state.domains = [{"domainId": "dom2", "baseDomain": "backup-example.net", "verified": True}]
    b.state.sites = [{"siteId": 7, "name": "newt-backup", "online": True, "type": "newt"}]
    yield a, b
    a.stop()
    b.stop()


@pytest.fixture()
def infra(db, mocks):
    from servermanager.models import PangolinServer, PveServer, RouterDevice, System
    a, b = mocks
    router = RouterDevice(name="chr-b", api_url=a.url, username=m.ROS_USER, password_enc=security.encrypt(m.ROS_PASS),
                          fingerprint=a.fingerprint)
    prim = PangolinServer(name="pg-prim", api_url=a.url, org_id=m.PG_ORG, api_key_enc=security.encrypt(m.PG_KEY),
                          fingerprint=a.fingerprint, default_site_id=1, default_domain_id="dom1", role="primary")
    back = PangolinServer(name="pg-back", api_url=b.url, org_id=m.PG_ORG, api_key_enc=security.encrypt(m.PG_KEY),
                          fingerprint=b.fingerprint, default_site_id=7, default_domain_id="dom2", role="backup")
    db.add_all([router, prim, back])
    db.flush()
    srv = PveServer(name="pve-b", api_url=a.url, token_id=m.PVE_TOKEN, token_secret_enc=security.encrypt(m.PVE_SECRET),
                    fingerprint=a.fingerprint, router_id=router.id, pangolin_id=prim.id, hosting="hetzner",
                    vswitch_vlan=4000, watch=[])
    db.add(srv)
    db.flush()
    t1 = System(name="newt-prim", host="10.20.0.100", types=["debian", "newt"], pve_server_id=srv.id, pve_vmid=100,
                facts={"newt_version": "1.5.0", "newt_active": "active"})
    t2 = System(name="newt-back", host="10.20.0.101", types=["debian", "newt"], pve_server_id=srv.id, pve_vmid=101,
                facts={"newt_version": "1.5.0", "newt_active": "active"})
    db.add_all([t1, t2])
    db.flush()
    prim.tunnel_system_id, back.tunnel_system_id = t1.id, t2.id
    db.commit()
    from servermanager import integrations
    for o in (srv, router, prim, back):
        integrations.poll(db, o)
    db.commit()
    yield {"srv": srv, "router": router, "prim": prim, "back": back, "t1": t1, "t2": t2}
    for o in (t1, t2, srv, router, prim, back):
        db.delete(o)
    db.commit()


# --------------------------------------------------------------------------
def test_pve_token_via_admin_login(db, mocks):
    from servermanager.models import PveServer
    from servermanager.pveapi import PveClient
    a, _b = mocks
    srv = PveServer(name="login", api_url=a.url, fingerprint=a.fingerprint)
    with pytest.raises(mgmt.MgmtError):
        mgmt.pve_token_via_login(srv, "root@pam", "wrong")
    token_id = mgmt.pve_token_via_login(srv, "root@pam", "rootpw")
    assert token_id.startswith("servermanager@pve!sm")
    assert a.state.acl[-1]["roles"] == "PVEAdmin"
    assert PveClient(a.url, srv.token_id, security.decrypt(srv.token_secret_enc),
                     fingerprint=a.fingerprint).version()
    # without a pinned certificate the password is never sent
    calls = len(a.state.calls)
    with pytest.raises(mgmt.MgmtError):
        mgmt.pve_token_via_login(PveServer(name="x", api_url=a.url), "root@pam", "rootpw")
    assert len(a.state.calls) == calls


def test_router_mgmt_user(db, mocks):
    from servermanager.mikrotik import MikroTik
    from servermanager.models import RouterDevice
    a, _b = mocks
    r = RouterDevice(name="new", api_url=a.url, fingerprint=a.fingerprint)
    assert mgmt.router_mgmt_user(r, "admin", "adminpw", "10.66.0.0/24", with_backup=True) == "servermanager"
    pw = security.decrypt(r.password_enc)
    assert pw and pw not in ("adminpw",)
    user = next(u for u in a.state.ros["user"] if u["name"] == "servermanager")
    assert user["address"] == "10.66.0.0/24" and user["group"] == "servermanager"
    group = next(g for g in a.state.ros["user/group"] if g["name"] == "servermanager")
    assert "sensitive" in group["policy"] and "rest-api" in group["policy"]
    assert MikroTik(a.url, "servermanager", pw, fingerprint=a.fingerprint).identity() == "chr-edge"
    with pytest.raises(mgmt.MgmtError):
        mgmt.router_mgmt_user(r, "admin", "falsch", "")
    with pytest.raises(mgmt.MgmtError):
        mgmt.router_mgmt_user(r, "admin", "adminpw", "10.0.0.0/8; /system reboot")


def test_key_script_output_parsing():
    script = mgmt.key_script(install_ssh=True)
    assert "authorized_keys" in script and "base64 -d" in script and "openssh-server" in script
    out = mgmt.parse_key_output("SM_KEY added\nSM_HOSTKEY ssh-ed25519 AAAAC3Nz\nSM_HOSTKEY evil stuff\n"
                                "SM_ROOTLOGIN no\nSM_IP 10.0.0.5/24\n")
    assert out["added"] and out["host_keys"] == ["ssh-ed25519 AAAAC3Nz"] and out["root_login"] == "no"
    assert out["ips"] == ["10.0.0.5"]


def test_import_vm_via_guest_agent(db, mocks, infra):
    from servermanager.jobs import enqueue, log_path
    from servermanager.models import Job, System
    a, _b = mocks
    g = a.state.guests[200]
    g["status"], g["config"]["agent"] = "running", 1
    job = enqueue(db, kind="pve_import", title="import", pve_id=infra["srv"].id,
                  payload={"items": [{"node": "pve1", "type": "qemu", "vmid": 200, "name": "win",
                                      "ip": "127.0.0.1"}]})
    db.commit()
    _run(job.id)
    db.expire_all()
    job = db.get(Job, job.id)
    # key and host keys are in place, but nothing listens on port 22 here: the system exists, the job
    # fails and can be retried
    assert job.status == "failed" and "SSH-Prüfung fehlgeschlagen" in job.summary, log_path(job.id).read_text()
    assert job.remote["failed_items"][0]["vmid"] == 200
    s = db.query(System).filter_by(pve_server_id=infra["srv"].id, pve_vmid=200).one()
    assert s.host_keys.startswith("ssh-ed25519 ") and s.host == "127.0.0.1"
    assert g["_exec"][:2] == ["/bin/sh", "-c"] and "authorized_keys" in g["_exec"][2]
    g["status"] = "stopped"
    db.delete(s)
    db.commit()


def test_scan_proposals(db, mocks, infra):
    result = optimize.scan(db)
    assert not result["errors"], result["errors"]
    ids = {p["id"]: p for p in result["proposals"]}
    sid, rid = infra["srv"].id, infra["router"].id
    assert ids[f"pve:{sid}:101:onboot"]["action"] == "pve_set"
    assert ids[f"pve:{sid}:101:backup"]["action"] == "pve_backup_job"
    assert ids[f"pve:{sid}:100:disk"]["action"] == "pve_resize"
    assert ids[f"pve:{sid}:101:mtu"]["params"]["config"]["net0"].endswith("mtu=1400")
    assert ids[f"pve:{sid}:pve1:vswitch"]["params"] == {"node": "pve1", "vlan": 4000, "phys": "enp0s31f6",
                                                        "bridge": "vmbr4000"}
    fwd = [p for p in result["proposals"] if p["id"].startswith(f"router:{rid}:fwd:")]
    assert fwd and fwd[0]["action"] == "publish_forward" and fwd[0]["params"]["method"] == "https"
    col = ids[f"tunnel:{infra['back'].id}:colocated"]
    assert col["severity"] == "crit" and col["action"] == "pve_migrate" and col["params"]["target"] == "pve2"
    # firewall changes are never automatic
    assert all(not p["action"] for p in result["proposals"] if p["id"].endswith(":fw.input"))


def test_apply_proposals_and_one_public_ip(db, mocks, infra):
    from servermanager.jobs import enqueue, log_path
    from servermanager.models import Job
    a, b = mocks
    result = optimize.scan(db)
    ids = {p["id"]: p for p in result["proposals"]}
    sid, rid = infra["srv"].id, infra["router"].id
    fwd = next(p for p in result["proposals"] if p["id"].startswith(f"router:{rid}:fwd:"))

    def item(p, **inputs):
        return {"id": p["id"], "title": p["title"], "action": p["action"], "params": p["params"], "obj": p["obj"],
                "inputs": inputs}
    items = [item(ids[f"pve:{sid}:101:onboot"]), item(ids[f"pve:{sid}:101:backup"]),
             item(ids[f"pve:{sid}:101:mtu"]), item(ids[f"pve:{sid}:pve1:vswitch"]), item(fwd, subdomain="shop"),
             item(ids[f"tunnel:{infra['back'].id}:colocated"])]
    job = enqueue(db, kind="optimize", title="opt", payload={"items": items})
    db.commit()
    _run(job.id)
    db.expire_all()
    job = db.get(Job, job.id)
    log = log_path(job.id).read_text()
    assert job.status == "success" and "fehlgeschlagen" not in job.summary, log
    g = a.state.guests[101]
    assert g["config"]["onboot"] in ("1", 1) and "mtu=1400" in g["config"]["net0"] and g["node"] == "pve2"
    assert a.state.backup_jobs[0]["vmid"] == "101" and a.state.backup_jobs[0]["comment"] == "servermanager"
    ifaces = {n["iface"] for n in a.state.networks["pve1"]}
    assert {"enp0s31f6.4000", "vmbr4000"} <= ifaces
    res = next(r for r in a.state.resources.values() if r["fullDomain"] == "shop.example.com")
    tgt = next(t for t in a.state.targets.values() if t["resourceId"] == res["resourceId"])
    assert (tgt["ip"], tgt["port"], tgt["method"]) == ("10.20.0.50", 443, "https")

    # second scan: port forward is now superfluous, backup path missing
    result = optimize.scan(db)
    ids = {p["id"]: p for p in result["proposals"]}
    off = next(p for p in result["proposals"] if p["id"].startswith(f"router:{rid}:fwd-off:"))
    mirror = ids["pangolin:mirror:10.20.0.50:443"]
    assert f"tunnel:{infra['back'].id}:colocated" not in ids
    job = enqueue(db, kind="optimize", title="opt2", payload={"items": [item(off), item(mirror)]})
    db.commit()
    _run(job.id)
    db.expire_all()
    assert db.get(Job, job.id).status == "success", log_path(job.id).read_text()
    nat = next(r for r in a.state.ros["ip/firewall/nat"] if r.get("chain") == "dstnat")
    assert nat["disabled"] == "true"
    bres = next(r for r in b.state.resources.values() if r["fullDomain"] == "shop.backup-example.net")
    assert next(t for t in b.state.targets.values() if t["resourceId"] == bres["resourceId"])["siteId"] == 7


def test_nat_disable_refused_when_not_published(db, mocks, infra):
    from servermanager.jobs import enqueue
    from servermanager.models import Job
    item = {"id": "x", "title": "fwd off", "action": "router_nat_disable", "obj": {"kind": "router",
            "id": infra["router"].id, "name": "r"}, "params": {"nat_id": "*999", "ip": "10.99.99.99", "port": 22},
            "inputs": {}}
    job = enqueue(db, kind="optimize", title="bad", payload={"items": [item]})
    db.commit()
    _run(job.id)
    db.expire_all()
    job = db.get(Job, job.id)
    assert job.status == "failed" and "nicht (mehr) über Pangolin" in job.summary


def test_failover_alert_mentions_backup(db, mocks, infra):
    from servermanager import integrations
    a, _b = mocks
    a.state.sites[0]["online"] = False
    try:
        integrations.poll(db, infra["prim"])
        text = " ".join(x["text"] for x in infra["prim"].alert_list)
        assert "offline" in text and "Backup-Weg über pg-back" in text
    finally:
        a.state.sites[0]["online"] = True


def test_web_pages(app, db, mocks, infra):
    from servermanager.models import Job
    from tests.test_web import login, make_user
    make_user(db, "b-admin", "admin")
    c = login(app, "b-admin")
    r = c.post("/optimierung/scan", data={"csrf_token": c.csrf})
    assert r.status_code == 302
    scan_job = db.query(Job).filter_by(kind="optimize_scan").order_by(Job.id.desc()).first()
    _run(scan_job.id)
    for url in ["/optimierung/", f"/proxmox/{infra['srv'].id}/import", "/pangolin/services",
                f"/pangolin/{infra['prim'].id}/tunnel", f"/routeros/{infra['router'].id}?tab=devices",
                f"/proxmox/{infra['srv'].id}/edit", f"/routeros/{infra['router'].id}/edit",
                f"/pangolin/{infra['back'].id}/edit", f"/proxmox/{infra['srv'].id}/create"]:
        r = c.get(url)
        assert r.status_code == 200, (url, r.text[:500])
    page = c.get("/optimierung/").text
    assert "Auswahl prüfen" in page and "Proxmox" in page
    result = optimize.load(db)
    idx = next(i for i, p in enumerate(result["proposals"]) if p["action"])
    action = result["proposals"][idx]["action"]
    r = c.post("/optimierung/confirm", data={"sel": str(idx), "scan_at": result["at"], "csrf_token": c.csrf})
    assert r.status_code == 200 and "Bitte bestätigen" in r.text
    r = c.post("/optimierung/apply", data={"sel": str(idx), "scan_at": result["at"], "confirmed": "1",
                                           "csrf_token": c.csrf})
    assert r.status_code == 302
    job = db.query(Job).filter_by(kind="optimize").order_by(Job.id.desc()).first()
    assert job.payload["items"][0]["action"] == action
    # stale selection after a new scan is refused
    r = c.post("/optimierung/confirm", data={"sel": str(idx), "scan_at": "old", "csrf_token": c.csrf})
    assert r.status_code == 409
    # non-admins have no access
    make_user(db, "b-user", "user")
    u = login(app, "b-user")
    assert u.get("/optimierung/").status_code == 403


def test_newt_setup_form_validation(app, db, infra):
    from tests.test_web import login, make_user
    make_user(db, "b-admin", "admin")
    c = login(app, "b-admin")
    r = c.post(f"/pangolin/{infra['prim'].id}/tunnel", data={"system_id": str(infra["t1"].id), "newt_id": "abc",
                                                            "newt_secret": "x", "newt_endpoint": "http://x",
                                                            "csrf_token": c.csrf})
    assert "Newt-ID" in r.text
    r = c.post(f"/pangolin/{infra['prim'].id}/tunnel", data={
        "system_id": str(infra["t1"].id), "newt_id": "abcd1234", "newt_secret": "supersecret123",
        "newt_endpoint": "https://pangolin.example.com", "csrf_token": c.csrf})
    assert r.status_code == 302
    from servermanager.models import Job
    job = db.query(Job).filter_by(kind="newt_setup").order_by(Job.id.desc()).first()
    assert "supersecret123" not in str(job.payload) and job.payload["newt"]["secret_enc"]


def test_failed_import_keeps_failed_guests_for_retry(db, mocks, infra):
    from servermanager import jobs as jobq
    from servermanager.jobs import enqueue
    from servermanager.models import Job
    item = {"node": "pve1", "type": "qemu", "vmid": 999, "name": "gone", "ip": ""}
    job = enqueue(db, kind="pve_import", title="import", pve_id=infra["srv"].id, payload={"items": [item]})
    db.commit()
    _run(job.id)
    db.expire_all()
    job = db.get(Job, job.id)
    assert job.status == "failed" and job.remote["failed_items"] == [item]
    assert jobq.retry_plan(job)["payload"]["items"] == [item]
