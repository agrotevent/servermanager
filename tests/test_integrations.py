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
    assert lanin["current"] == "chain=input action=drop log-prefix=DROP_INPUT_"
    assert "in-interface=ether4 protocol=udp dst-port=53,67" in lanin["script"][0]
    assert "place-before=[ find where chain=input action=drop log-prefix=DROP_INPUT_ ]" in lanin["script"][0]
    # internet access is not blocked
    assert "fw.lanout" not in by_id and "fw.lanout.ether4" not in by_id
    snap = _snap
    pkt = {"src": "10.200.30.2", "dst": "1.1.1.1", "proto": "tcp", "sport": 40000, "dport": 443, "in": "ether4",
           "out": "ether1", "state": "new", "nat": (), "dst_type": ("unicast",), "src_type": ("unicast",),
           "flags": ("syn",)}
    assert routeros.probe(snap, "forward", pkt)[0] == "accept"
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
    assert dmtu["script"] == ['/ip dhcp-server option add name=sm-mtu-1400 code=26 value=0x0578 '
                              'comment="servermanager: MTU 1400"',
                              "/ip dhcp-server network set [ find address=10.200.30.0/24 ] dhcp-option=sm-mtu-1400"]
    assert "pol.mtu.ether3" not in by_id and "lan.mtu.ether3" not in by_id
    # log=yes on NAT and broad accepts - not on rules that never fire (dead / deleted interface)
    log = by_id["fw.log"]
    assert log["severity"] == "info"
    assert "/ip firewall nat set [ find where log=yes chain=srcnat action=masquerade out-interface=ether4 " \
        "log-prefix=nat_ ] log=no" in log["script"]
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
    nat = by_id["nat.masq.ether4"]      # cut off from the internet by the firewall: no NAT needed
    assert nat["status"] == "check" and not nat["applicable"] and "getrennt" in nat["title"]
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


PKT = {"src": "192.168.88.10", "dst": "1.1.1.1", "proto": "tcp", "sport": 40000, "dport": 443, "in": "bridge",
       "out": "ether1", "state": "new", "nat": (), "dst_type": ("unicast",), "src_type": ("unicast",),
       "flags": ("syn",)}


def test_probe_tcp_flags_negate_each_flag():
    snap = {"menus": {}}
    null_scan = {"protocol": "tcp", "tcp-flags": "!fin,!syn,!rst,!ack"}   # MikroTik's bad_tcp rule
    assert routeros.rule_matches(null_scan, PKT, snap) is False
    assert routeros.rule_matches(null_scan, dict(PKT, flags=()), snap) is True
    assert routeros.rule_matches({"protocol": "tcp", "tcp-flags": "syn,!ack"}, PKT, snap) is True
    assert routeros.rule_matches({"protocol": "tcp", "tcp-flags": "syn,!ack"}, dict(PKT, flags=("syn", "ack")),
                                 snap) is False


def test_interface_lists_include_exclude_and_predefined():
    snap = routeros.parse_export("""
/interface list add name=LAN
/interface list add name=VSW
/interface list add name=GUEST
/interface list add exclude=GUEST include=LAN,VSW name=INTERNAL
/interface list add include=LOOP2 name=LOOP1
/interface list add include=LOOP1 name=LOOP2
/interface list member add interface=bridge list=LAN
/interface list member add interface=vlan9 list=LAN
/interface list member add interface=vlan9 list=GUEST
/interface list member add interface=ether4 list=VSW
/ip address add address=10.0.0.1/24 interface=bridge
/ip address add address=10.0.9.1/24 interface=vlan9
/ip address add address=10.0.4.1/24 interface=ether4
""")
    f = routeros.in_iface_list
    assert f(snap, "ether4", "INTERNAL") is True and f(snap, "bridge", "INTERNAL") is True
    assert f(snap, "vlan9", "INTERNAL") is False                   # excluded through GUEST
    assert f(snap, "ether4", "LAN") is False and f(snap, "ether4", "all") is True and f(snap, "ether4", "none") is False
    assert f(snap, "ether4", "static") is True and f(snap, "ether4", "dynamic") is False
    assert f(snap, "unknown", "static") is None
    assert f(snap, "bridge", "LOOP1") is None                      # include cycle
    assert routeros.rule_matches({"in-interface-list": "!INTERNAL"}, dict(PKT, **{"in": "ether4"}), snap) is False


DEFCONF = """
/interface bridge add name=bridge
/interface list add name=WAN
/interface list add name=LAN
/ip pool add name=default-dhcp ranges=192.168.88.10-192.168.88.254
/ip dhcp-server add address-pool=default-dhcp interface=bridge name=defconf
/interface bridge port add bridge=bridge interface=ether2
/interface list member add interface=bridge list=LAN
/interface list member add interface=ether1 list=WAN
/ip address add address=192.168.88.1/24 interface=bridge network=192.168.88.0
/ip dhcp-client add interface=ether1
/ip dhcp-server network add address=192.168.88.0/24 dns-server=192.168.88.1 gateway=192.168.88.1
/ip dns set allow-remote-requests=yes
/ip firewall filter
add action=accept chain=input connection-state=established,related,untracked
add action=drop chain=input connection-state=invalid
add action=accept chain=input protocol=icmp
add action=accept chain=input dst-address=127.0.0.1
add action=drop chain=input in-interface-list=!LAN
add action=accept chain=forward ipsec-policy=in,ipsec
add action=accept chain=forward ipsec-policy=out,ipsec
add action=fasttrack-connection chain=forward connection-state=established,related hw-offload=yes
add action=accept chain=forward connection-state=established,related,untracked
add action=drop chain=forward connection-state=invalid
add action=drop chain=forward connection-nat-state=!dstnat connection-state=new in-interface-list=WAN
/ip firewall nat
add action=masquerade chain=srcnat ipsec-policy=out,none out-interface-list=WAN
"""


def _analyze(text, edit=None):
    snap = routeros.parse_export(text)
    if edit:
        edit(snap["menus"])
    target, errors = routeros.validate_target(routeros.detect_target(snap))
    assert not errors
    findings = routeros.analyze(snap, target)
    assert len({f["id"] for f in findings}) == len(findings)
    return {f["id"]: f for f in findings}


def test_defconf_is_clean_and_a_forward_block_is_found():
    by_id = _analyze(DEFCONF)
    assert by_id["nat.masq"]["status"] == "ok" and by_id["fw.lanin"]["status"] == "ok"
    for fid in ("fw.lanout", "fw.dead", "fw.icmp", "fw.log", "sys.orphans"):
        assert fid not in by_id, fid
    blocked = DEFCONF.replace("add action=fasttrack-connection",
                              "add action=drop chain=forward in-interface=bridge out-interface-list=WAN\n"
                              "add action=fasttrack-connection")
    assert _analyze(blocked)["fw.lanout"]["status"] == "change"       # despite the ipsec-policy rules before
    tunnel = blocked + "/ip ipsec policy add dst-address=0.0.0.0/0 src-address=192.168.88.0/24 tunnel=yes\n"
    assert "fw.lanout" not in _analyze(tunnel)                        # goes into the IPsec tunnel


def test_probe_undecidable_rules():
    snap = {"menus": {"ip/firewall/filter": [
        {"chain": "forward", "action": "accept", "limit": "10,20:packet"},
        {"chain": "forward", "action": "accept", "connection-state": "new"},
        {"chain": "input", "action": "accept", "limit": "10,20:packet"},
        {"chain": "input", "action": "drop"}]}}
    assert routeros.probe(snap, "forward", PKT)[0] == "accept"     # accepted either way
    v, rule, _ = routeros.probe(snap, "input", PKT)
    assert v == "uncertain" and rule["limit"] == "10,20:packet"
    # "return" in a built-in chain ends it with accept - the filter table is still evaluated
    snap = {"menus": {"ip/firewall/raw": [{"chain": "prerouting", "action": "return", "in-interface": "bridge"}],
                      "ip/firewall/filter": [{"chain": "forward", "action": "drop", "in-interface": "bridge"}]}}
    assert routeros.probe(snap, "forward", PKT)[0] == "drop"


def test_multilan_forward_uncertain_is_check():
    def edit(m):
        m["ip/firewall/filter"].insert(0, {"chain": "forward", "action": "drop", "in-interface": "ether4",
                                           "connection-limit": "100,32", "disabled": "no"})
    _snap, by_id = _multilan(edit)
    f = by_id["fw.lanout.ether4"]
    assert f["status"] == "check" and f["current"] == "chain=forward action=drop in-interface=ether4 " \
        "connection-limit=100,32"


def test_multilan_two_subnets_on_one_interface():
    def edit(m):
        m["ip/address"].append({"address": "10.201.0.1/24", "interface": "ether4", "disabled": "no"})
        m["ip/dhcp-server/network"].append({"address": "10.201.0.0/24", "gateway": "10.201.0.1",
                                            "dns-server": "1.1.1.1"})
    snap, by_id = _multilan(edit)
    assert {"lan.mtu.ether4.10.200.30.0", "lan.mtu.ether4.10.201.0.0", "fw.lanin.ether4.10.201.0.0",
            "nat.masq.ether4.10.201.0.0"} <= set(by_id)
    mtu = [f for k, f in by_id.items() if k.startswith("lan.mtu.")]
    ops = routeros.unique_ops(op for f in mtu for op in f["ops"])
    assert [op["path"] for op in ops].count("ip/dhcp-server/option") == 1
    assert routeros.full_script(mtu).count("/ip dhcp-server option add") == 1


def test_detect_target_prefers_client_networks():
    def edit(m):
        m.setdefault("interface/bridge", []).extend([{"name": "containers"}, {"name": "loopback"}])
        m["ip/address"][:0] = [{"address": "172.17.0.1/24", "interface": "containers", "disabled": "no"},
                               {"address": "10.255.255.1/32", "interface": "loopback", "disabled": "no"}]
    snap = routeros.parse_export(MULTILAN)
    edit(snap["menus"])
    assert routeros.detect_target(snap)["lan_interface"] == "ether3"


@pytest.mark.parametrize("nat, status", [
    ({"action": "masquerade", "src-address-list": "local", "out-interface-list": "WAN"}, "ok"),
    ({"action": "masquerade", "out-interface-list": "!LAN"}, "ok"),
    ({"action": "masquerade", "src-address-list": "dns", "out-interface": "ether1"}, "check"),
    ({"action": "masquerade", "src-address-list": "local", "out-interface": "ether3"}, "missing"),
])
def test_multilan_nat_coverage(nat, status):
    def edit(m):
        m["ip/firewall/nat"] = [dict(nat, chain="srcnat", disabled="no")]
        m["ip/firewall/address-list"] += [{"list": "local", "address": "10.0.0.0/8"},
                                          {"list": "dns", "address": "nets.example.net"}]
    _snap, by_id = _multilan(edit)
    assert by_id["nat.masq"]["status"] == status
    assert by_id["nat.masq.ether4"]["status"] == status
    assert by_id["nat.masq.ether4"]["applicable"] == (status == "missing")


def test_multilan_router_not_gateway():
    def edit(m):
        m["ip/dhcp-server/network"][1]["gateway"] = "10.200.30.254"
        m["ip/firewall/nat"] = [r for r in m["ip/firewall/nat"] if r.get("out-interface") != "ether1"]
    _snap, by_id = _multilan(edit)
    nat = by_id["nat.masq.ether4"]
    assert nat["status"] == "check" and not nat["applicable"] and "masquerade" in nat["script"][0]
    masq = by_id["nat.lanmasq.ether4"]
    assert masq["status"] == "check" and masq["severity"] == "info" and not masq["script"]


def test_multilan_dhcp_option_set_on_server():
    def edit(m):
        next(x for x in m["ip/dhcp-server"] if x["interface"] == "ether4")["dhcp-option-set"] = "vsw"
    _snap, by_id = _multilan(edit)
    f = by_id["lan.mtu.ether4"]
    assert f["status"] == "check" and not f["ops"] and "dhcp-option-set=vsw" in f["current"]


def _icmp_rule(**kw):
    return dict({"chain": "input", "action": "drop", "protocol": "icmp", "disabled": "no"}, **kw)


@pytest.mark.parametrize("rule, pos, flagged", [
    (_icmp_rule(), 0, True),
    (_icmp_rule(**{"icmp-options": "3:4"}), 0, True),
    (_icmp_rule(**{"in-interface-list": "WAN"}), 0, True),
    (_icmp_rule(**{"connection-state": "!established"}), 0, True),
    (_icmp_rule(**{"src-address": "203.0.113.0/24"}), 0, False),
    (_icmp_rule(**{"icmp-options": "8:0"}), 0, False),
    (_icmp_rule(**{"dst-limit": "10,20,src-address/1m"}), 0, False),
    (_icmp_rule(**{"in-interface": "ether3"}), 0, False),
    (_icmp_rule(**{"in-interface-list": "LAN"}), 0, False),
    (_icmp_rule(**{"connection-state": "new"}), 0, False),
    (_icmp_rule(), 7, False),                                    # behind "accept established,related"
    (_icmp_rule(chain="forward", **{"out-interface-list": "WAN"}), 0, False),
])
def test_multilan_icmp_variants(rule, pos, flagged):
    def edit(m):
        m["ip/firewall/raw"] = [r for r in m["ip/firewall/raw"] if r.get("comment") != "Block Ping Flood"]
        m["ip/firewall/filter"].insert(pos, rule)
    _snap, by_id = _multilan(edit)
    assert ("fw.icmp" in by_id) == flagged


@pytest.mark.parametrize("accepts, flagged", [
    (("3", "11:0"), False),
    (("3:0-255", "11"), False),
    (("3:0-4", "11:0"), False),
    (("3:4", "11"), True),          # other unreachable codes (3:0, 3:1, 3:3) are still dropped
    (("3",), True),
])
def test_multilan_icmp_errors_accepted_before_raw_drop(accepts, flagged):
    def edit(m):
        m["ip/firewall/raw"][:0] = [{"chain": "prerouting", "action": "accept", "protocol": "icmp", "icmp-options": o,
                                     "disabled": "no"} for o in accepts]
    assert ("fw.icmp" in _multilan(edit)[1]) == flagged


def test_multilan_icmp_rule_text_duplicates():

    def twice(m):
        m["ip/firewall/raw"] = [r for r in m["ip/firewall/raw"] if r.get("comment") != "Block Ping Flood"]
        m["ip/firewall/filter"][:0] = [_icmp_rule(), _icmp_rule()]
    script = _multilan(twice)[1]["fw.icmp"]["script"]
    assert script == ["# /ip firewall filter: chain=input action=drop protocol=icmp – von Hand deaktivieren"] * 2


def test_multilan_dead_wireguard_rule_is_moved():
    def edit(m):
        m["interface/wireguard"].append({"name": "wg-partner", "listen-port": "54321"})
    f = _multilan(edit)[1]["fw.dead"]
    assert "darunter WireGuard wg-partner" in f["title"]
    assert '/ip firewall filter move [ find where comment="Allow WireGuard" ] ' \
           'destination=[ find where chain=input action=drop log-prefix=DROP_INPUT_ ]' in f["script"]


def test_multilan_log_script_spares_unflagged_rules():
    def edit(m):
        m["ip/firewall/filter"].insert(0, {"chain": "input", "action": "accept", "src-address": "192.0.2.142",
                                           "protocol": "tcp", "dst-port": "25", "log": "yes",
                                           "log-prefix": "Lager_", "disabled": "no"})
    script = _multilan(edit)[1]["fw.log"]["script"]
    assert not any("src-address=192.0.2.142" in s and s.startswith("/") for s in script)
    assert any(s.startswith("# /ip firewall filter: chain=input action=accept src-address=192.0.2.142")
               for s in script)


def test_multiline_comment_stays_on_one_script_line():
    def edit(m):
        m["ip/firewall/raw"][0]["comment"] = "Block\nPing Flood"
    _snap, by_id = _multilan(edit)
    assert by_id["fw.icmp"]["script"] == ['/ip firewall raw disable [ find where comment="Block\\nPing Flood" ]']
    for line in routeros.full_script(list(by_id.values())).splitlines():
        assert line == "" or line.startswith(("#", "/", "add ")), line


def test_bridge_mtu_from_its_ports_in_an_export():
    snap = routeros.parse_export("""
/interface bridge add name=bridge-vsw
/interface ethernet set [ find default-name=ether3 ] mtu=1400
/interface bridge port add bridge=bridge-vsw interface=ether3
/ip address add address=10.30.0.1/24 interface=bridge-vsw
""")
    br = next(i for i in snap["menus"]["interface"] if i["name"] == "bridge-vsw")
    assert routeros.iface_mtu(br) == 1400


def test_stale_api_snapshot_is_reported():
    snap = routeros.parse_export(MULTILAN)
    snap["source"] = "api"
    snap["menus"].pop("ip/firewall/raw")
    target, _ = routeros.validate_target(routeros.detect_target(snap))
    by_id = {f["id"]: f for f in routeros.analyze(snap, target)}
    assert by_id["sys.snapshot"]["status"] == "check" and "ip/firewall/raw" in by_id["sys.snapshot"]["current"]
    assert "lan.mtu.ether4" not in by_id       # DHCP options were not read


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


# --------------------------------------------------------------------------
# second review round
# --------------------------------------------------------------------------
def test_interface_list_static_member_beats_exclude_and_names_with_spaces():
    snap = routeros.parse_export("""
/interface list add name=WAN
/interface list add name=VLANS
/interface list add exclude=WAN,VLANS include=all name=LAN
/interface list add name="Home LAN"
/interface list add include="Home LAN" name=INTERNAL
/interface list member add interface=ether1 list=WAN
/interface list member add interface=vlan10 list=VLANS
/interface list member add interface=vlan10 list=LAN
/interface list member add interface=vlan20 list=VLANS
/interface list member add interface=bridge list="Home LAN"
/ip address add address=10.0.0.1/24 interface=bridge
""")
    f = routeros.in_iface_list
    assert f(snap, "vlan10", "LAN") is True       # static members are added after include/exclude
    assert f(snap, "vlan20", "LAN") is False and f(snap, "ether2", "LAN") is True
    assert f(snap, "bridge", "INTERNAL") is True and f(snap, "bridge", "LAN") is True


def test_ipsec_default_template_from_export_is_no_policy():
    blocked = DEFCONF.replace("add action=fasttrack-connection",
                              "add action=drop chain=forward in-interface=bridge out-interface-list=WAN\n"
                              "add action=fasttrack-connection")
    for extra in ("/ip ipsec policy\nset 0 dst-address=0.0.0.0/0 src-address=0.0.0.0/0\n",
                  "/ip ipsec policy\nset [ find default=yes ] dst-address=0.0.0.0/0 src-address=0.0.0.0/0\n",
                  "/ip ipsec policy\nadd action=none dst-address=0.0.0.0/0 src-address=192.168.88.0/24\n"):
        assert _analyze(blocked + extra)["fw.lanout"]["status"] == "change", extra


def _defconf_forward(*rules):
    return DEFCONF.replace("add action=accept chain=forward ipsec-policy=in,ipsec", "\n".join(rules)
                           + "\nadd action=accept chain=forward ipsec-policy=in,ipsec")


def test_undecidable_rule_in_user_chain_uses_the_callers_continuation():
    same_accept = _defconf_forward("add action=jump chain=forward in-interface=bridge jump-target=lan",
                                   "add action=accept chain=lan time=8h-17h,mon,tue,wed,thu,fri",
                                   "add action=return chain=lan",
                                   "add action=accept chain=forward in-interface=bridge")
    assert "fw.lanout" not in _analyze(same_accept)
    same_drop = _defconf_forward("add action=jump chain=forward in-interface=bridge jump-target=lan",
                                 "add action=drop chain=lan time=0s-6h,sun",
                                 "add action=return chain=lan",
                                 "add action=drop chain=forward comment=block in-interface=bridge")
    f = _analyze(same_drop)["fw.lanout"]
    assert f["status"] == "change" and "comment=block" in f["current"]


def test_probe_jump_loops_terminate():
    rules = [{"chain": "forward", "action": "jump", "jump-target": "a"}]
    for c, nxt in (("a", "b"), ("b", "a")):
        rules += [{"chain": c, "action": "jump", "jump-target": nxt, "limit": "1,1:packet"} for _ in range(6)]
    assert routeros.probe({"menus": {"ip/firewall/filter": rules}}, "forward", PKT)[0] in ("accept", "uncertain")


def test_keys_for_subnets_with_the_same_base_address():
    nets = routeros.keyed([{"iface": "e", "net": routeros.net_of(n)} for n in ("10.1.0.0/24", "10.1.0.0/16",
                                                                              "10.2.0.0/24")])
    assert [n["key"] for n in nets] == ["e.10.1.0.0-24", "e.10.1.0.0-16", "e.10.2.0.0"]


def test_detect_target_skips_tunnels_and_ranks_dhcp_first():
    def edit(m):
        m["interface"] += [{"name": "gre-hq", "type": "gre"}, {"name": "containers", "type": "bridge"}]
        m.setdefault("interface/bridge", []).append({"name": "containers"})
        m["interface/list/member"] += [{"interface": "gre-hq", "list": "LAN"}, {"interface": "containers", "list": "LAN"}]
        m["ip/address"][:0] = [{"address": "10.255.255.1/30", "interface": "gre-hq"},
                               {"address": "172.17.0.1/24", "interface": "containers"}]
    snap = routeros.parse_export(MULTILAN)
    edit(snap["menus"])
    assert routeros.detect_target(snap)["lan_interface"] == "ether3"
    assert "gre-hq" not in {n["iface"] for n in routeros.internal_networks(snap, "ether1")}


def test_multilan_nat_list_filled_by_dhcp_is_unsure():
    def edit(m):
        next(x for x in m["ip/dhcp-server"] if x["interface"] == "ether4")["address-lists"] = "vsw-clients"
        m["ip/firewall/nat"] = [r for r in m["ip/firewall/nat"] if r.get("src-address") != "10.200.30.0/24"]
        m["ip/firewall/nat"].append({"chain": "srcnat", "action": "masquerade", "src-address-list": "vsw-clients",
                                     "out-interface": "ether1", "disabled": "no"})
    f = _multilan(edit)[1]["nat.masq.ether4"]
    assert f["status"] == "check" and not f["ops"] and "src-address-list=vsw-clients" in f["current"]


def test_multilan_missing_nat_op():
    def edit(m):
        m["ip/firewall/nat"] = [r for r in m["ip/firewall/nat"] if r.get("chain") != "srcnat"
                                or r.get("src-address") == "10.20.30.0/24"]
    nat = _multilan(edit)[1]["nat.masq.ether4"]
    assert nat["status"] == "missing" and nat["severity"] == "crit" and nat["applicable"]
    assert nat["ops"][0]["data"]["src-address"] == "10.200.30.0/24" and nat["ops"][0]["data"]["out-interface"] == "ether1"


def test_multilan_missing_nat_with_masquerade_into_the_net():
    def edit(m):
        m["ip/firewall/nat"] = [r for r in m["ip/firewall/nat"] if r.get("src-address") != "10.200.30.0/24"]
    _snap, by_id = _multilan(edit)
    assert by_id["nat.masq.ether4"]["status"] == "missing" and by_id["nat.masq.ether4"]["severity"] == "crit"
    assert by_id["nat.lanmasq.ether4"]["status"] == "change"


@pytest.mark.parametrize("nat", [
    {"action": "masquerade", "src-address": "10.200.30.0/24", "dst-address": "10.200.30.0/24"},   # hairpin only
    {"action": "src-nat", "protocol": "tcp", "dst-port": "25", "out-interface": "ether1", "to-addresses": "198.51.100.239"},
    {"action": "masquerade", "out-interface": "ether4", "in-interface": "wg1"},
])
def test_multilan_nat_rules_that_are_no_internet_nat(nat):
    def edit(m):
        m["ip/firewall/nat"] = [r for r in m["ip/firewall/nat"] if r.get("chain") != "srcnat"
                                or r.get("src-address") == "10.20.30.0/24"] + [dict(nat, chain="srcnat", disabled="no")]
    _snap, by_id = _multilan(edit)
    assert by_id["nat.masq.ether4"]["status"] == "missing"
    assert "nat.lanmasq.ether4" not in by_id        # narrowed to VPN traffic / no masquerade into the net


def test_multilan_extra_network_with_foreign_gateway_is_a_hint():
    def edit(m):
        m["ip/dhcp-server/network"][1]["gateway"] = "10.200.30.254"
    f = _multilan(edit)[1]["lan.network.ether4"]
    assert f["status"] == "check" and not f["applicable"] and "10.200.30.254" in f["title"]


def test_multilan_container_veth_makes_the_router_gateway():
    def edit(m):
        m.setdefault("interface/bridge", []).append({"name": "containers"})
        m["interface"].append({"name": "containers", "type": "bridge"})
        m["ip/address"].append({"address": "172.17.0.1/24", "interface": "containers"})
        m["interface/veth"] = [{"name": "veth1", "address": "172.17.0.2/24", "gateway": "172.17.0.1"}]
    f = _multilan(edit)[1]["nat.masq.containers"]
    assert f["status"] == "missing" and f["applicable"]


def test_multilan_icmp_drop_towards_a_dmz_is_found():
    def edit(m):
        m["ip/firewall/raw"] = [r for r in m["ip/firewall/raw"] if r.get("comment") != "Block Ping Flood"]
        m["ip/address"].append({"address": "10.99.0.1/24", "interface": "ether5"})
        m["ip/firewall/filter"].insert(0, _icmp_rule(chain="forward", **{"out-interface": "ether5"}))
    assert "fw.icmp" in _multilan(edit)[1]


def test_dhcp_option_comment_needs_routeros_7_16():
    snap = routeros.parse_export(MULTILAN.replace("RouterOS 7.24.4", "RouterOS 7.15.3"))
    target, _ = routeros.validate_target(routeros.detect_target(snap))
    f = next(f for f in routeros.analyze(snap, target) if f["id"] == "lan.mtu.ether4")
    assert f["script"][0] == "/ip dhcp-server option add name=sm-mtu-1400 code=26 value=0x0578"


def test_export_escapes_round_trip():
    snap = routeros.parse_export('/ip firewall filter add action=drop chain=input comment="Gr\\C3\\BC\\C3\\9Fe\\_x"')
    rules = snap["menus"]["ip/firewall/filter"]
    assert rules[0]["comment"] == "Grüße x"
    assert routeros.find_expr(rules[0], rules) == 'comment="Gr\\C3\\BC\\C3\\9Fe x"'


def test_multilan_dead_rules_and_wireguard():
    def edit(m):
        flt = m["ip/firewall/filter"]
        killer = next(i for i, r in enumerate(flt) if r.get("log-prefix") == "DROP_INPUT_")
        flt.insert(killer, {"chain": "input", "action": "drop", "in-interface-list": "WAN", "disabled": "no"})
        m["interface/wireguard"].append({"name": "wg-partner", "listen-port": "54321"})
        flt += [{"chain": "input", "action": "accept", "protocol": "udp", "dst-port": "13231", "disabled": "no"},
                {"chain": "input", "action": "accept", "src-address": "172.16.50.0/24", "comment": "wg50 traffic",
                 "disabled": "no"},
                {"chain": "forward", "action": "drop", "disabled": "no"},
                {"chain": "forward", "action": "accept", "protocol": "udp", "dst-port": "51820", "disabled": "no"}]
    f = _multilan(edit)[1]["fw.dead"]
    assert f["title"].endswith("darunter WireGuard wg-partner, wg50")      # not wg1 for "accept in-interface=ether1"
    dest = "destination=[ find where chain=input action=drop in-interface-list=WAN ]"
    assert f'/ip firewall filter move [ find where comment="Allow WireGuard" ] {dest}' in f["script"]
    assert '/ip firewall filter move [ find where comment="wg50 traffic" ] destination=[ find where ' \
           'chain=input action=drop log-prefix=DROP_INPUT_ ]' in f["script"]
    # 13231 is accepted at the top already, the forward rule has nothing to do with the router's WireGuard
    assert "# /ip firewall filter: chain=input action=accept protocol=udp dst-port=13231 – nicht eindeutig " \
        "auswählbar, von Hand löschen" in f["script"]
    assert "/ip firewall filter remove [ find where chain=forward action=accept protocol=udp dst-port=51820 ]" \
        in f["script"]


def test_multilan_unconditional_accept_is_the_problem():
    def edit(m):
        m["ip/firewall/filter"].insert(0, {"chain": "input", "action": "accept", "disabled": "no"})
    _snap, by_id = _multilan(edit)
    assert by_id["fw.open.input"]["severity"] == "crit"
    assert by_id["fw.input"]["status"] != "ok" and by_id["fw.dns"]["severity"] == "crit"
    assert not any("DROP_INPUT_" in s and s.startswith("/") for s in by_id.get("fw.dead", {}).get("script", []))


@pytest.mark.parametrize("rule, fid, status", [
    ({"chain": "forward", "action": "drop", "src-address": "10.200.30.5", "out-interface": "ether1"},
     "fw.lanout.ether4", "check"),                                              # one device, not the network
    ({"chain": "forward", "action": "drop", "dst-address-list": "doh", "protocol": "tcp", "dst-port": "443"},
     "fw.lanout.ether4", None),                                                 # DoH block, not the internet
    ({"chain": "forward", "action": "reject", "tls-host": "*.tiktok.com"}, "fw.lanout.ether4", None),
    ({"chain": "forward", "action": "drop", "dst-address-list": "!allowed", "in-interface": "ether4"},
     "fw.lanout.ether4", "change"),                                             # allow list: blocks the rest
    ({"chain": "input", "action": "drop", "protocol": "udp", "limit": "10,20:packet"}, "fw.lanin", "check"),
])
def test_multilan_probe_variants(rule, fid, status):
    def edit(m):
        m["ip/firewall/filter"].insert(0, dict(rule, disabled="no"))
        m["ip/firewall/address-list"] += [{"list": "doh", "address": "1.1.1.1"}, {"list": "doh", "address": "8.8.8.8"},
                                          {"list": "allowed", "address": "192.0.2.10"}]
    by_id = _multilan(edit)[1]
    assert (by_id[fid]["status"] if fid in by_id else None) == status


def test_multilan_alias_address_is_no_dhcp_network():
    def edit(m):
        m["ip/address"].append({"address": "192.168.0.2/24", "interface": "ether3"})
    by_id = _multilan(edit)[1]
    assert not any(k.startswith("lan.network.ether3") for k in by_id)
    assert by_id["fw.lanin"]["status"] == "ok"


def test_multilan_more_branches():
    def broad(m):
        m["ip/firewall/nat"] = [r for r in m["ip/firewall/nat"] if r.get("src-address") != "10.200.30.0/24"]
        m["ip/firewall/nat"].append({"chain": "srcnat", "action": "masquerade", "disabled": "no"})
    f = _multilan(broad)[1]["nat.masq.ether4"]
    assert f["status"] == "check" and "ohne Ausgangs-Interface" in f["title"]

    def no_network(m):
        m["ip/dhcp-server/network"] = m["ip/dhcp-server/network"][:1]
    f = _multilan(no_network)[1]["lan.network.ether4"]   # extra network: a hint with a script, no API op
    assert f["status"] == "check" and not f["ops"] and f["script"][0].startswith("/ip dhcp-server network add")

    snap = {"menus": {}}
    assert routeros.rule_matches({"dst-address-type": "local"}, dict(PKT, dst_type=("local",)), snap) is True
    assert routeros.rule_matches({"dst-address-type": "!local"}, PKT, snap) is True


def test_defconf_upstream_dns_from_the_provider():
    f = _analyze(DEFCONF)["dns.servers"]
    assert f["status"] == "ok" and f["current"] == "DHCP-Client ether1"


# --------------------------------------------------------------------------
# third review round
# --------------------------------------------------------------------------
def test_interface_list_include_with_spaces_is_split_on_commas_only():
    snap = routeros.parse_export("""
/interface list add name=LAN
/interface list add name=WAN
/interface list add name="Home LAN"
/interface list add include="Home LAN" name=INTERNAL
/interface list add include="Home LAN",WAN name=MULTI
/interface list add exclude="Home LAN" include=all name=X
/interface list member add interface=bridge list="Home LAN"
/interface list member add interface=vlan9 list=LAN
/interface list member add interface=ether1 list=WAN
""")
    f = routeros.in_iface_list
    assert f(snap, "bridge", "INTERNAL") is True and f(snap, "vlan9", "INTERNAL") is False
    assert f(snap, "bridge", "MULTI") is True and f(snap, "ether1", "MULTI") is True
    assert f(snap, "vlan9", "MULTI") is False and f(snap, "bridge", "X") is False


def test_probe_is_iterative_and_fast():
    import time
    rules = [{"chain": "forward", "action": "drop", "limit": "1,1:packet"} for _ in range(800)]
    rules += [{"chain": "forward", "action": "jump", "jump-target": "dev", "src-address": f"192.168.88.{i}"}
              for i in range(2, 250)]
    rules += [{"chain": "dev", "action": "drop", "protocol": "tcp", "dst-port": str(p), "limit": "1,1:packet"}
              for p in range(400, 700)]
    pkt = dict(PKT, src_net=routeros.net_of("192.168.88.0/24"), any_dst=True)
    t0 = time.time()
    assert routeros.probe({"menus": {"ip/firewall/filter": rules}}, "forward", pkt)[0] == "uncertain"
    assert time.time() - t0 < 2


def test_ipsec_full_tunnel_needs_no_nat():
    tunnel = DEFCONF + "/ip ipsec policy add dst-address=0.0.0.0/0 src-address=192.168.88.0/24 tunnel=yes\n"
    assert _analyze(tunnel)["nat.masq"]["status"] == "ok"


@pytest.mark.parametrize("extra, status", [
    ("randomise-ports=yes", "ok"),            # a NAT parameter, no matcher
    ("protocol=udp", "check"),                # only part of the traffic
])
def test_defconf_masquerade_variants(extra, status):
    text = DEFCONF.replace("add action=masquerade chain=srcnat ipsec-policy=out,none out-interface-list=WAN",
                           f"add action=masquerade chain=srcnat {extra} out-interface-list=WAN")
    assert _analyze(text)["nat.masq"]["status"] == status


def test_defconf_protection_is_judged_by_probes():
    by_id = _analyze(DEFCONF)
    assert by_id["fw.input"]["status"] == "ok" and by_id["fw.forward"]["status"] == "ok"
    # "drop all not coming from LAN" in forward, and a default-deny forward chain, protect as well
    for rule in ("add action=drop chain=forward in-interface-list=!LAN",
                 "add action=accept chain=forward in-interface-list=LAN\nadd action=drop chain=forward"):
        text = DEFCONF.replace("add action=drop chain=forward connection-nat-state=!dstnat connection-state=new "
                               "in-interface-list=WAN", rule)
        assert _analyze(text)["fw.forward"]["status"] == "ok", rule
    # one matcher is enough to open everything from WAN
    opened = DEFCONF.replace("add action=accept chain=input protocol=icmp",
                             "add action=accept chain=input protocol=icmp\nadd action=accept chain=input in-interface=ether1")
    by_id = _analyze(opened)
    assert by_id["fw.input"]["severity"] == "crit" and "tcp/8291" in by_id["fw.input"]["current"]
    assert by_id["fw.dns"]["severity"] == "crit"


def test_unconditional_accept_behind_the_wan_drop_and_user_chain_return():
    text = DEFCONF.replace("add action=drop chain=input in-interface-list=!LAN",
                           "add action=drop chain=input in-interface-list=!LAN\nadd action=accept chain=input\n"
                           "add action=drop chain=input protocol=tcp dst-port=23")
    f = _analyze(text)["fw.open.input"]
    assert f["severity"] == "warn"                                    # the internet never gets there
    text = _defconf_forward("add action=jump chain=forward jump-target=chk in-interface=bridge",
                            "add action=return chain=chk", "add action=drop chain=chk protocol=tcp dst-port=25")
    by_id = _analyze(text)
    assert not any(k.startswith("fw.open") for k in by_id)
    assert "/ip firewall filter remove [ find where chain=chk action=drop protocol=tcp dst-port=25 ]" \
        in by_id["fw.dead"]["script"]


def test_multilan_wireguard_port_blocked_and_rule_in_a_user_chain():
    def edit(m):
        m["interface/wireguard"].append({"name": "wg-rw", "listen-port": "51999"})
        m["interface/wireguard/peers"] = [{"interface": "wg-rw", "public-key": "x"},
                                          {"interface": "wg1", "public-key": "y", "endpoint-address": "192.0.2.9"}]
    by_id = _multilan(edit)[1]
    f = by_id["tun.wgport.wg-rw"]
    assert f["status"] == "change" and "place-before=[ find where chain=input action=drop log-prefix=DROP_INPUT_ ]" \
        in f["script"][0]
    assert by_id["tun.wgport.wg1"]["status"] == "check"              # the router dials its peer itself

    def chain(m):
        flt = m["ip/firewall/filter"]
        killer = next(i for i, r in enumerate(flt) if r.get("log-prefix") == "DROP_INPUT_")
        flt.insert(killer, {"chain": "input", "action": "jump", "jump-target": "vpn", "disabled": "no"})
        flt += [{"chain": "vpn", "action": "return", "disabled": "no"},
                {"chain": "vpn", "action": "accept", "protocol": "udp", "dst-port": "51820", "comment": "wg1 port",
                 "disabled": "no"}]
    f = _multilan(chain)[1]["fw.dead"]
    assert '/ip firewall filter move [ find where comment="wg1 port" ] ' \
           'destination=[ find where chain=vpn action=return ]' in f["script"]


def test_multilan_dns_accept_goes_before_the_deciding_rule():
    def edit(m):
        m["ip/firewall/filter"].insert(6, {"chain": "input", "action": "drop", "src-address": "10.200.30.50",
                                           "protocol": "udp", "dst-port": "53", "comment": "camera dns",
                                           "disabled": "no"})
    f = _multilan(edit)[1]["fw.lanin.ether4"]
    assert "place-before=[ find where chain=input action=drop log-prefix=DROP_INPUT_ ]" in f["script"][0]


def test_multilan_private_destinations_are_no_internet():
    def edit(m):
        m["ip/firewall/filter"][:0] = [
            {"chain": "forward", "action": "accept", "dst-address": "192.168.0.0/16", "disabled": "no"},
            {"chain": "forward", "action": "drop", "in-interface": "ether4", "out-interface": "ether1",
             "disabled": "no"}]
    f = _multilan(edit)[1]["fw.lanout.ether4"]
    assert f["status"] == "change"


def test_defconf_default_route_without_dst_address():
    text = DEFCONF.replace("/ip dhcp-client add interface=ether1",
                           "/ip dhcp-client add add-default-route=no interface=ether1\n/ip route add gateway=203.0.113.1")
    assert _analyze(text)["wan.default"]["status"] == "ok"


def test_provider_dns_only_from_active_clients():
    assert _analyze(DEFCONF.replace("/ip dhcp-client add interface=ether1",
                                    "/ip dhcp-client add interface=ether1 use-peer-dns=no"))["dns.servers"]["status"] \
        == "missing"
    snap = routeros.parse_export(DEFCONF)
    snap["source"] = "api"
    target, _ = routeros.validate_target(routeros.detect_target(snap))
    assert {f["id"]: f for f in routeros.analyze(snap, target)}["dns.servers"]["status"] == "missing"


def test_undecodable_comment_is_not_used_in_find():
    snap = routeros.parse_export('/ip firewall filter add action=drop chain=input comment="Gr\\FC\\DFe" protocol=icmp')
    rules = snap["menus"]["ip/firewall/filter"]
    assert routeros.find_expr(rules[0], rules) == "chain=input action=drop protocol=icmp"


def test_policy_marks_spare_the_routers_own_addresses():
    snap = routeros.parse_export(EXPORT)
    target, _ = routeros.validate_target(routeros.detect_target(snap, "10.66.0.0/24"))
    by_id = {f["id"]: f for f in routeros.analyze(snap, target)}
    assert by_id["pol.m1"]["ops"][0]["data"]["dst-address-type"] == "!local"
    assert by_id["pol.m3"]["ops"][0]["data"]["dst-address-type"] == "!local"
