"""Proxmox / RouterOS / Pangolin integration against the in-process HTTPS mock (tests/mock_apis.py)."""
from pathlib import Path

import pytest

from servermanager import pve, routeros, security
from servermanager.mikrotik import MikroTik, MikroTikError
from servermanager.pangolin import Pangolin, PangolinError
from servermanager.pveapi import PveClient, PveError
from tests import mock_apis as m

EXPORT = (Path(__file__).parent / "data" / "chr_export.rsc").read_text()


@pytest.fixture(scope="module")
def mock():
    srv = m.MockServer().start()
    yield srv
    srv.stop()


@pytest.fixture()
def objects(db, mock):
    from servermanager.models import PangolinServer, PveServer, RouterDevice
    router = RouterDevice(name="chr", api_url=mock.url, username=m.ROS_USER,
                          password_enc=security.encrypt(m.ROS_PASS), fingerprint=mock.fingerprint)
    pg = PangolinServer(name="pg", api_url=mock.url, org_id=m.PG_ORG, api_key_enc=security.encrypt(m.PG_KEY),
                        fingerprint=mock.fingerprint, default_site_id=1, default_domain_id="dom1")
    db.add_all([router, pg])
    db.flush()
    server = PveServer(name="pve", api_url=mock.url, token_id=m.PVE_TOKEN,
                       token_secret_enc=security.encrypt(m.PVE_SECRET), fingerprint=mock.fingerprint,
                       router_id=router.id, pangolin_id=pg.id, watch=[])
    db.add(server)
    db.commit()
    return server, router, pg


# --------------------------------------------------------------------------
# TLS pinning
# --------------------------------------------------------------------------
def test_pinned_certificate_is_required(mock):
    ok = PveClient(mock.url, m.PVE_TOKEN, m.PVE_SECRET, fingerprint=mock.fingerprint)
    assert ok.version()["version"].startswith("9")
    wrong = "AA:" * 31 + "AA"
    with pytest.raises(PveError, match="TLS"):
        PveClient(mock.url, m.PVE_TOKEN, m.PVE_SECRET, fingerprint=wrong).version()
    with pytest.raises(PveError):  # neither pin nor CA check -> refused
        PveClient(mock.url, m.PVE_TOKEN, m.PVE_SECRET)
    with pytest.raises(PveError):  # self-signed certificate is not trusted by the CAs
        PveClient(mock.url, m.PVE_TOKEN, m.PVE_SECRET, verify_ca=True).version()
    with pytest.raises(MikroTikError):
        MikroTik(mock.url, m.ROS_USER, m.ROS_PASS, fingerprint=wrong).identity()
    assert MikroTik(mock.url, m.ROS_USER, m.ROS_PASS, fingerprint=mock.fingerprint).identity() == "chr-edge"


def test_fetch_fingerprint(mock):
    from servermanager import tlspin
    assert tlspin.fetch_fingerprint("127.0.0.1", mock.port) == mock.fingerprint
    assert tlspin.normalize_fingerprint(mock.fingerprint.replace(":", "").lower()) == mock.fingerprint


def test_wrong_token(mock):
    with pytest.raises(PveError, match="Anmeldung"):
        PveClient(mock.url, m.PVE_TOKEN, "wrong", fingerprint=mock.fingerprint).version()


# --------------------------------------------------------------------------
# Proxmox
# --------------------------------------------------------------------------
def test_overview_and_alerts(mock, objects, db):
    from servermanager import integrations
    server, _r, _p = objects
    server.watch = [200]
    integrations.poll(db, server)
    assert server.status == "online"
    assert {g["vmid"] for g in server.data["guests"]} >= {100, 200}
    keys = {a["key"] for a in server.alert_list}
    assert "guest:200:down" in keys          # watched but stopped
    assert "guest:100:disk" in keys          # 95 % full
    server.watch = []
    integrations.poll(db, server)
    assert "guest:200:down" not in {a["key"] for a in server.alert_list}


@pytest.mark.parametrize("field,value,msg", [
    ("hostname", "bad host", "Hostname"),
    ("template", "evil:vztmpl/../../x", "Vorlage"),
    ("ip", "10.20.0.50", "IPv4"),
    ("ssh_keys", "not a key", "SSH"),
    ("vmid", "42", "VMID"),
])
def test_build_create_validation(field, value, msg):
    form = {"node": "pve1", "hostname": "web", "vmid": "150", "template": "local:vztmpl/debian-13.tar.zst",
            "storage": "local-lvm", "bridge": "vmbr1", "ip_mode": "static", "ip": "10.20.0.50/24",
            "gateway": "10.20.0.1", "add_sm_key": "1"}
    form[field] = value
    with pytest.raises(pve.PveParamError, match=msg):
        pve.build_create(form)


def test_create_params():
    p = pve.build_create({"node": "pve1", "hostname": "Web01", "vmid": "150", "template": "download:debian-13-standard_13.1-2_amd64.tar.zst",
                          "template_storage": "local", "storage": "local-lvm", "disk_gb": "10", "bridge": "vmbr1",
                          "vlan": "20", "ip_mode": "dhcp", "password": "geheim123", "unprivileged": "1",
                          "nesting": "1", "tags": "newt, web"})
    assert p["password_enc"] and "geheim123" not in str(p)
    params = pve.create_params(p)
    assert params["hostname"] == "web01"
    assert params["net0"] == "name=eth0,bridge=vmbr1,firewall=1,tag=20,ip=dhcp"
    assert params["rootfs"] == "local-lvm:10" and params["features"] == "nesting=1"
    assert params["password"] == "geheim123" and params["tags"] == "newt;web"
    assert params["ostemplate"] == "local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst"


def _run(job_id):
    from servermanager.worker import Worker
    w = Worker()
    try:
        w._execute(job_id)
    finally:
        w.pool.shutdown(wait=False)
        w.check_pool.shutdown(wait=False)


def test_create_container_full_flow(mock, objects, db, data_dir):
    """download template -> create -> start -> DHCP address -> static lease on RouterOS -> Pangolin."""
    from servermanager.jobs import enqueue, log_path
    from servermanager.models import Job
    server, router, pg = objects
    payload = pve.build_create({
        "node": "pve1", "hostname": "app01", "vmid": "151", "template": "download:debian-13-standard_13.1-2_amd64.tar.zst",
        "template_storage": "local", "storage": "local-lvm", "bridge": "vmbr1", "ip_mode": "dhcp",
        "add_sm_key": "1", "unprivileged": "1", "start": "1", "static_lease": "1", "watch": "1",
        "publish": "1", "pub_subdomain": "app", "pub_domain": "dom1", "pub_site": "1", "pub_port": "8080",
        "pub_method": "http", "password": "secret-pass"})
    job = enqueue(db, kind="pve_create", title="create", payload=payload, pve_id=server.id)
    db.commit()
    _run(job.id)
    db.expire_all()
    job = db.get(Job, job.id)
    log = log_path(job.id).read_text()
    assert job.status == "success", log
    assert "password_enc" not in job.payload
    g = mock.state.guests[151]
    assert g["status"] == "running" and "ssh-" in g["keys"]
    assert "local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst" in mock.state.templates
    lease = next(le for le in mock.state.ros["ip/dhcp-server/lease"] if le["address"] == g["ip"])
    assert lease["dynamic"] == "false" and lease["comment"].startswith("servermanager: app01")
    res = next(r for r in mock.state.resources.values() if r["name"] == "app01")
    assert res["fullDomain"] == "app.example.com" and res["sso"] is False
    target = next(t for t in mock.state.targets.values() if t["resourceId"] == res["resourceId"])
    assert (target["ip"], target["port"]) == (g["ip"], 8080)
    db.refresh(server)
    assert 151 in server.watch_list
    assert "app.example.com" in job.summary


def test_guest_operation_job(mock, objects, db):
    from servermanager.jobs import enqueue
    from servermanager.models import Job
    server, _r, _p = objects
    job = enqueue(db, kind="pve", title="start", pve_id=server.id,
                  payload={"op": "snapshot", "node": "pve1", "type": "lxc", "vmid": 100,
                           "params": {"snapname": "before", "description": "x"}})
    db.commit()
    _run(job.id)
    db.expire_all()
    assert db.get(Job, job.id).status == "success"
    assert [s["name"] for s in mock.state.guests[100]["snapshots"]] == ["before"]


def test_worker_resumes_pve_task(mock, objects, db):
    """A job interrupted while a Proxmox task runs continues to follow that task after a restart."""
    from servermanager.jobs import enqueue
    from servermanager.models import Job
    server, _r, _p = objects
    upid = mock.state.task("pve1", "vzstart", 200, ["starting"], duration=0.5)
    job = enqueue(db, kind="pve", title="start", pve_id=server.id,
                  payload={"op": "start", "node": "pve1", "type": "qemu", "vmid": 200, "params": {}})
    job.status = "running"
    job.remote = {"pve_task": {"node": "pve1", "upid": upid, "n": 0}}
    db.commit()
    from servermanager.worker import Worker, resumable
    assert resumable(job.remote)
    w = Worker()
    w.recover()
    db.expire_all()
    assert db.get(Job, job.id).status == "queued"
    calls_before = len([c for c in mock.state.calls if c[1].endswith("/status/start")])
    w._execute(job.id)
    w.pool.shutdown(wait=False)
    w.check_pool.shutdown(wait=False)
    db.expire_all()
    assert db.get(Job, job.id).status == "success"
    # the operation was not issued a second time
    assert len([c for c in mock.state.calls if c[1].endswith("/status/start")]) == calls_before


# --------------------------------------------------------------------------
# Pangolin
# --------------------------------------------------------------------------
def test_pangolin_publish_and_rollback(mock):
    pg = Pangolin(mock.url, m.PG_KEY, m.PG_ORG, fingerprint=mock.fingerprint)
    res = pg.publish("wiki", "http", 1, "10.20.0.60", 80, "http", "wiki", "dom1", sso=True)
    assert res["fullDomain"] == "wiki.example.com"
    before = set(mock.state.resources)
    with pytest.raises(PangolinError):
        pg.publish("broken", "http", 1, "10.20.0.61", 9, "http", "broken", "dom1")
    assert set(mock.state.resources) == before  # resource removed again after the target failed
    with pytest.raises(PangolinError, match="Subdomain"):
        pg.publish("x", "http", 1, "10.20.0.61", 80, "http", "Bad_Sub!", "dom1")
    with pytest.raises(PangolinError, match="API-Schlüssel"):
        Pangolin(mock.url, "wrong", m.PG_ORG, fingerprint=mock.fingerprint).sites()


def test_pangolin_legacy_routes():
    srv = m.MockServer(legacy_pangolin=True).start()
    try:
        pg = Pangolin(srv.url, m.PG_KEY, m.PG_ORG, fingerprint=srv.fingerprint)
        res = pg.publish("old", "http", 1, "10.20.0.70", 80, "http", "old", "dom1")
        assert res["siteId"] == 1
        assert next(iter(srv.state.targets.values()))["ip"] == "10.20.0.70"
    finally:
        srv.stop()


# --------------------------------------------------------------------------
# RouterOS analysis
# --------------------------------------------------------------------------
def test_export_parser():
    snap = routeros.parse_export(EXPORT)
    menus = snap["menus"]
    assert snap["version"] == "7.16.1"
    assert {i["name"] for i in menus["interface"]} >= {"ether1-wan", "bridge-lan", "wg-mgmt", "ether2"}
    peer = menus["interface/wireguard/peers"][0]
    assert peer["public-key"] == "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ="   # continuation line joined
    services = {s["name"]: s for s in menus["ip/service"]}
    assert services["telnet"]["disabled"] == "yes" and services["www"]["disabled"] == "false"
    assert menus["system/identity"][0]["name"] == "chr-edge"


def test_analysis_findings():
    snap = routeros.parse_export(EXPORT)
    target, errors = routeros.validate_target(routeros.detect_target(snap, "10.66.0.0/24"))
    assert not errors
    assert (target["wan_interface"], target["lan_interface"], target["lan_address"]) == \
        ("ether1-wan", "bridge-lan", "10.20.0.1/24")
    by_id = {f["id"]: f for f in routeros.analyze(snap, target)}
    assert by_id["wan.default"]["status"] == "ok"
    assert by_id["lan.dhcp"]["status"] == "ok"
    assert by_id["lan.network"]["status"] == "change" and by_id["lan.network"]["applicable"]
    assert by_id["nat.masq"]["status"] == "change" and not by_id["nat.masq"]["applicable"]
    assert by_id["pol.fasttrack"]["status"] == "change"
    assert by_id["fw.input"]["severity"] == "crit" and not by_id["fw.input"]["applicable"]
    assert by_id["svc.address"]["status"] == "change" and not by_id["svc.address"]["ops"]
    script = routeros.full_script(list(by_id.values()))
    assert "/routing table add name=sm-inet fib" in script
    assert "new-routing-mark=sm-inet" in script


def test_analysis_apply_via_api(mock):
    mt = MikroTik(mock.url, m.ROS_USER, m.ROS_PASS, fingerprint=mock.fingerprint)
    snap = routeros.snapshot_from_api(mt)
    target, _ = routeros.validate_target(routeros.detect_target(snap, "10.66.0.0/24"))
    findings = routeros.analyze(snap, target)
    todo = [f for f in findings if f["applicable"]]
    assert todo
    routeros.backup_before_change(mt)
    assert mock.state.ros["_backups"]
    routeros.apply_ops(mt, [op for f in todo for op in f["ops"]], lambda _l: None)
    after = {f["id"]: f for f in routeros.analyze(routeros.snapshot_from_api(mt), target)}
    for f in todo:
        assert after[f["id"]]["status"] in ("ok", "check"), (f["id"], after[f["id"]])
    # never touched: firewall filter and services
    assert not any(c[0] in ("PUT", "PATCH", "DELETE") and "firewall/filter" in c[1] for c in mock.state.calls)
    assert not any(c[0] in ("PUT", "PATCH") and "ip/service" in c[1] for c in mock.state.calls)


def test_migration_v1_to_v2(tmp_path):
    from sqlalchemy import create_engine, inspect, text
    from servermanager import migrations
    from servermanager.db import Base
    from sqlalchemy import MetaData, Table
    eng = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    new_tables = {"integration_access", "pve_servers", "router_devices", "pangolin_servers"}
    new_cols = {"pve_server_id", "pve_vmid", "pve_id"}
    old = MetaData()
    for t in Base.metadata.sorted_tables:
        if t.name not in new_tables:
            Table(t.name, old, *[c._copy() for c in t.columns if c.name not in new_cols])
    old.create_all(eng)
    with eng.begin() as conn:
        conn.execute(text("INSERT INTO meta(key, value) VALUES ('schema_version', '1')"))
    assert migrations.migrate(eng) == migrations.SCHEMA_VERSION
    insp = inspect(eng)
    assert {"pve_server_id", "pve_vmid"} <= {c["name"] for c in insp.get_columns("systems")}
    assert "pve_id" in {c["name"] for c in insp.get_columns("jobs")}
    assert "pve_servers" in insp.get_table_names()
    with eng.connect() as conn:
        assert conn.execute(text("SELECT value FROM meta WHERE key='schema_version'")).scalar() == \
            str(migrations.SCHEMA_VERSION)
    assert {"role", "tunnel_system_id"} <= {c["name"] for c in insp.get_columns("pangolin_servers")}
