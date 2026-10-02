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


MULTILAN = (Path(__file__).parent / "data" / "chr_multilan_export.rsc").read_text()
NEW_PROBLEMS = ("fw.dead", "fw.icmp", "fw.log", "sys.orphans", "nat.lanmasq.", "pol.mtu.", "lan.mtu.", "fw.lanout",
                "fw.lanin")


def _multilan(edit=None):
    snap = routeros.parse_export(MULTILAN)
    if edit:
        edit(snap["menus"])
    target, errors = routeros.validate_target(routeros.detect_target(snap))
    assert not errors
    return snap, {f["id"]: f for f in routeros.analyze(snap, target)}


def test_basic_fixture_has_no_multilan_findings():
    snap = routeros.parse_export(EXPORT)
    target, _ = routeros.validate_target(routeros.detect_target(snap, "10.66.0.0/24"))
    bad = [f["id"] for f in routeros.analyze(snap, target)
           if f["id"].startswith(NEW_PROBLEMS) and f["status"] not in ("ok",)]
    assert bad == []


def test_multilan_export_parser_keeps_mtu():
    snap = routeros.parse_export(MULTILAN)
    ifaces = {i["name"]: i for i in snap["menus"]["interface"]}
    assert ifaces["ether4"]["mtu"] == "1400"
    assert snap["menus"]["ip/firewall/raw"][0]["disabled"] == "no"
    # ether2 (no DHCP, not in the list LAN) comes first but is no client network
    assert routeros.detect_target(snap)["lan_interface"] == "ether3"
    nets = routeros.internal_networks(snap, "ether1")
    assert [(n["iface"], str(n["net"]), n["dhcp"]) for n in nets] == \
        [("ether3", "10.20.30.0/24", True), ("ether4", "10.200.30.0/24", True)]


def test_multilan_findings():
    _snap, by_id = _multilan()
    assert by_id["lan.network.ether4"]["status"] == "ok"
    assert by_id["nat.masq.ether4"]["status"] == "ok"
    # DNS to the router: allowed for the LAN, dropped for ether4 by the final drop of the input chain
    assert by_id["fw.lanin"]["status"] == "ok"
    lanin = by_id["fw.lanin.ether4"]
    assert lanin["status"] == "change" and lanin["severity"] == "warn" and not lanin["applicable"]
    assert lanin["current"] == "chain=input action=drop"
    assert "in-interface=ether4 protocol=udp dst-port=53,67" in lanin["script"][0]
    assert "place-before=[:pick [find where chain=input action=drop dynamic=no] 0]" in lanin["script"][0]
    # internet access is not blocked
    assert "fw.lanout" not in by_id and "fw.lanout.ether4" not in by_id
    # rules behind the final drop + user chains without a jump
    dead = by_id["fw.dead"]
    assert dead["status"] == "change"
    assert "dst-port=54321" in dead["current"] and "Kette detect-ddos" in dead["current"]
    assert "Kette icmp" in dead["current"]           # the only jump to it is disabled
    assert '/ip firewall filter remove [ find where comment="Allow WireGuard" ]' in dead["script"]
    assert "/ip firewall filter remove [ find where chain=detect-ddos ]" in dead["script"]
    assert any(s.startswith("# /ip firewall filter: chain=input action=drop") for s in dead["script"])
    # global ICMP rate limit in raw
    icmp = by_id["fw.icmp"]
    assert icmp["script"] == ['/ip firewall raw disable [ find where comment="Block Ping Flood" ]']
    # masquerade of everything into ether4 -> hairpin only
    masq = by_id["nat.lanmasq.ether4"]
    assert masq["status"] == "change" and "10.200.30.1" in masq["detail"]
    assert masq["script"][0].endswith("] src-address=10.200.30.0/24 dst-address=10.200.30.0/24")
    # deleted interfaces
    orphans = by_id["sys.orphans"]
    assert orphans["severity"] == "info"
    for menu in ("/ip address: 1", "/ip dhcp-client: 1", "/ip firewall filter: 1", "/interface wifi cap: 1"):
        assert menu in orphans["current"]
    # MTU 1400: the generic clamp-to-pmtu covers the way out, the way in is missing
    mtu = by_id["pol.mtu.ether4"]
    assert mtu["status"] == "missing" and mtu["applicable"] and "(eingehend)" in mtu["title"]
    assert [op["data"] for op in mtu["ops"]] == [{
        "chain": "forward", "action": "change-mss", "protocol": "tcp", "tcp-flags": "syn", "in-interface": "ether4",
        "tcp-mss": "1361-65535", "new-mss": "1360", "passthrough": "yes", "comment": "servermanager: MSS ether4 (MTU 1400)"}]
    dmtu = by_id["lan.mtu.ether4"]
    assert dmtu["status"] == "missing" and dmtu["applicable"]
    assert dmtu["script"] == ["/ip dhcp-server option add name=sm-mtu-1400 code=26 value=0x0578",
                              "/ip dhcp-server network set [ find address=10.200.30.0/24 ] dhcp-option=sm-mtu-1400"]
    assert "pol.mtu.ether3" not in by_id and "lan.mtu.ether3" not in by_id
    # log=yes on NAT and broad accepts - not on rules that never fire (dead / deleted interface)
    log = by_id["fw.log"]
    assert log["severity"] == "info"
    assert "/ip firewall nat set [ find where log=yes chain=srcnat action=masquerade out-interface=ether4 ] log=no" \
        in log["script"]
    assert any("src-address=192.0.2.142" in s for s in log["script"])
    assert not any("in-interface=ether1" in s or "*1" in s for s in log["script"])
    assert log["title"].startswith("3 ")


def test_multilan_findings_after_fix():
    def fix(m):
        flt = m["ip/firewall/filter"]
        killer = next(i for i, r in enumerate(flt) if r.get("log-prefix") == "DROP_INPUT_")
        flt.insert(killer, {"chain": "input", "action": "accept", "in-interface-list": "LAN", "protocol": "udp",
                            "dst-port": "53,67", "disabled": "no"})
        m["ip/firewall/raw"] = [r for r in m["ip/firewall/raw"] if r.get("comment") != "Block Ping Flood"]
        m["ip/firewall/mangle"].append({"chain": "forward", "action": "change-mss", "protocol": "tcp",
                                        "tcp-flags": "syn", "in-interface": "ether4", "new-mss": "1360",
                                        "disabled": "no"})
        m["ip/dhcp-server/option"] = [{"name": "mtu", "code": "26", "value": "0x0578"}]
        m["ip/dhcp-server/network"][1]["dhcp-option"] = "mtu"
        m["ip/firewall/nat"] = [dict(r, **{"src-address": "10.200.30.0/24", "dst-address": "10.200.30.0/24"})
                                if r.get("out-interface") == "ether4" else r for r in m["ip/firewall/nat"]]
    _snap, by_id = _multilan(fix)
    assert by_id["fw.lanin.ether4"]["status"] == "ok"
    assert by_id["pol.mtu.ether4"]["status"] == "ok"
    assert by_id["lan.mtu.ether4"]["status"] == "ok"
    assert "fw.icmp" not in by_id and "nat.lanmasq.ether4" not in by_id


def test_multilan_missing_nat_and_blocked_forward():
    def edit(m):
        m["ip/firewall/nat"] = [r for r in m["ip/firewall/nat"] if r.get("chain") != "srcnat"
                                or r.get("src-address") == "10.20.30.0/24"]
        m["ip/firewall/filter"].insert(0, {"chain": "forward", "action": "drop", "in-interface": "ether4",
                                           "disabled": "no"})
        m["ip/dhcp-server/network"][1]["dns-server"] = "10.200.30.1"
    _snap, by_id = _multilan(edit)
    nat = by_id["nat.masq.ether4"]
    assert nat["status"] == "missing" and nat["severity"] == "crit" and nat["applicable"]
    assert nat["ops"][0]["data"]["src-address"] == "10.200.30.0/24" and nat["ops"][0]["data"]["out-interface"] == "ether1"
    assert by_id["fw.lanout.ether4"]["current"] == "chain=forward action=drop in-interface=ether4"
    assert "fw.lanout" not in by_id
    # the DHCP network hands out the router as DNS -> a dropped DNS query is critical
    assert by_id["fw.lanin.ether4"]["severity"] == "crit"


def test_multilan_dns_not_offered():
    def edit(m):
        m["ip/dns"][0]["allow-remote-requests"] = "no"
        m["ip/dhcp-server/network"][1]["dns-server"] = "10.200.30.1"
    _snap, by_id = _multilan(edit)
    f = by_id["dns.remote.ether4"]
    assert f["status"] == "change" and f["ops"][0]["data"] == {"allow-remote-requests": "yes"}
    assert not any(k.startswith("fw.lanin") for k in by_id)


def test_probe_evaluator():
    snap = {"menus": {
        "interface/list/member": [{"list": "LAN", "interface": "bridge", "disabled": "no"}],
        "ip/firewall/address-list": [{"list": "admins", "address": "10.0.0.5-10.0.0.9", "disabled": "no"},
                                     {"list": "dyn", "address": "host.example.net", "disabled": "no"}],
        "ip/firewall/filter": [
            {"chain": "input", "action": "jump", "jump-target": "checks", "protocol": "tcp"},
            {"chain": "checks", "action": "return", "src-address-list": "admins"},
            {"chain": "checks", "action": "drop", "tcp-flags": "!syn"},
            {"chain": "checks", "action": "drop", "dst-port": "8000-8999"},
            {"chain": "input", "action": "accept", "in-interface-list": "!LAN", "dst-port": "22", "protocol": "tcp"},
            {"chain": "input", "action": "drop", "protocol": "udp", "limit": "10,20:packet"},
            {"chain": "input", "action": "drop", "src-address-list": "dyn"},
        ]}}
    pkt = {"src": "10.0.0.20", "dst": "10.0.0.1", "proto": "tcp", "sport": 40000, "dport": 22, "in": "ether1",
           "out": None, "state": "new", "nat": (), "dst_type": ("local",), "src_type": ("unicast",), "flags": ("syn",)}
    assert routeros.probe(snap, "input", pkt)[0] == "accept"                      # not in LAN, port 22
    assert routeros.probe(snap, "input", dict(pkt, **{"in": "bridge"}))[0] == "uncertain"   # list with a DNS name
    v, rule, top = routeros.probe(snap, "input", dict(pkt, dport=8080))
    assert (v, rule["dst-port"], top["action"]) == ("drop", "8000-8999", "jump")    # decided inside the jump
    assert routeros.probe(snap, "input", dict(pkt, src="10.0.0.7", dport=8080, **{"in": "x"}))[0] == "uncertain"
    assert routeros.probe(snap, "input", dict(pkt, flags=("ack",)))[1]["tcp-flags"] == "!syn"
    assert routeros.probe(snap, "input", dict(pkt, proto="udp", dport=53))[0] == "uncertain"   # rate limit
    assert routeros.unconditional({"chain": "input", "action": "drop", "log": "yes", "log-prefix": "x",
                                   "comment": "c"})


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


def test_failed_create_is_retried_from_failed_step(mock, objects, db, data_dir, monkeypatch):
    from servermanager import jobs as jobq
    from servermanager.jobs import enqueue, log_path
    from servermanager.models import Job
    from servermanager.worker import JobFailed, Worker
    server, _router, _pg = objects
    payload = pve.build_create({
        "node": "pve1", "hostname": "retry01", "vmid": "152", "template": "download:debian-13-standard_13.1-2_amd64.tar.zst", "template_storage": "local",
        "storage": "local-lvm", "bridge": "vmbr1", "ip_mode": "dhcp", "start": "1", "publish": "1",
        "pub_subdomain": "retry", "pub_domain": "dom1", "pub_site": "1", "pub_port": "80", "pub_method": "http",
        "password": "secret-pass"})
    job = enqueue(db, kind="pve_create", title="create", payload=payload, pve_id=server.id)
    db.commit()
    real_publish = Worker._publish

    def broken(self, ctx, srv, p, ip):
        raise JobFailed("Pangolin nicht erreichbar")
    monkeypatch.setattr(Worker, "_publish", broken)
    _run(job.id)
    db.expire_all()
    job = db.get(Job, job.id)
    assert job.status == "failed" and job.remote["resume_phase"] == "publish", log_path(job.id).read_text()
    assert mock.state.guests[152]["status"] == "running"
    plan = jobq.retry_plan(job)
    assert plan and "veröffentlichen" in plan["label"]

    monkeypatch.setattr(Worker, "_publish", real_publish)
    new = jobq.retry(db, job, None)
    db.commit()
    assert jobq.retry_plan(job) is None  # only once
    _run(new.id)
    db.expire_all()
    new = db.get(Job, new.id)
    log = log_path(new.id).read_text()
    assert new.status == "success", log
    assert f"Wiederholung von Job #{job.id}" in log and "Lege Container" not in log and "Starte Container" not in log
    assert any(r["name"] == "retry01" for r in mock.state.resources.values())
    assert "retry_of" not in (new.remote or {})


def test_retry_create_skips_existing_container(mock, objects, db, data_dir):
    from servermanager import jobs as jobq
    from servermanager.jobs import enqueue, log_path
    from servermanager.models import Job
    server, _router, _pg = objects
    payload = pve.build_create({
        "node": "pve1", "hostname": "retry02", "vmid": "153", "template": "download:debian-13-standard_13.1-2_amd64.tar.zst", "template_storage": "local",
        "storage": "local-lvm", "bridge": "vmbr1", "ip_mode": "static", "ip": "10.20.0.53/24", "gateway": "10.20.0.1", "password": "secret-pass",
        "start": "1"})
    first = enqueue(db, kind="pve_create", title="create", payload=payload, pve_id=server.id)
    db.commit()
    _run(first.id)
    db.expire_all()
    # pretend the first run failed while creating (task state lost)
    first = db.get(Job, first.id)
    first.status, first.remote = "failed", {"resume_phase": "create"}
    db.commit()
    new = jobq.retry(db, first, None)
    db.commit()
    _run(new.id)
    db.expire_all()
    log = log_path(new.id).read_text()
    assert db.get(Job, new.id).status == "success", log
    assert "existiert bereits" in log and "Container läuft bereits" in log


def test_pangolin_connection_hints():
    from servermanager.pangolin import connect_hint
    refused = OSError("Failed to establish a new connection: [Errno 111] Connection refused")
    assert "Traefik" in connect_hint("https://pangolin.example.com:3003/v1", refused)
    assert "lauscht nichts" in connect_hint("https://api.example.com/v1", refused)
    assert "DNS" in connect_hint("https://x.example/v1", OSError("[Errno -2] Name or service not known"))
    with pytest.raises(PangolinError, match="Port 3003"):
        Pangolin("https://127.0.0.1:3003/v1", "key", "org1", timeout=2).sites()


def test_pangolin_wrong_key_message(mock):
    with pytest.raises(PangolinError) as exc:
        Pangolin(mock.url, "nur-das-geheimnis", m.PG_ORG, fingerprint=mock.fingerprint).sites()
    msg = str(exc.value)
    assert exc.value.status == 401 and "<ID>.<Geheimnis>" in msg and m.PG_ORG in msg
    assert "keinen Punkt" in msg
    with pytest.raises(PangolinError) as exc:
        Pangolin(mock.url, "abc.def", m.PG_ORG, fingerprint=mock.fingerprint).sites()
    assert "keinen Punkt" not in str(exc.value)
