"""Telephony (Asterisk/FreePBX): parsing, status script, web pages, router proposals."""
import os
import subprocess
from pathlib import Path

import pytest

from servermanager import pbx, routeros, security
from tests import mock_apis as m
from tests.test_web import login, make_user

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "servermanager" / "modules" / "scripts"

REGS = """
 <Registration/ServerURI..............................>  <Auth....................>  <Status.......>
==========================================================================================

 sipgate/sip:sipgate.de                                  sipgate                     Registered        (exp. 562s)
 easybell/sip:voip.easybell.de                           easybell                    Rejected

Objects found: 2
"""
CONTACTS = """
  Contact:  <Aor/ContactUri..........................> <Hash....> <Status> <RTT(ms)..>
==========================================================================================

  Contact:  201/sip:201@10.20.0.51:5060;ob             3b1f5c7a2d Avail        14.212
  Contact:  202/sip:202@10.20.0.52:5062                1a2b3c4d5e Unavail         nan
  Contact:  sipgate/sip:sipgate.de                     9f8e7d6c5b Avail        21.004

Objects found: 3
"""
ENDPOINTS = """
Endpoint:  <Endpoint/CID.....................................>  <State.....>  <Channels.>
==========================================================================================

Endpoint:  201/201                                              Not in use    0 of inf
Endpoint:  202/202                                              Unavailable   0 of inf
Endpoint:  easybell                                             Unavailable   0 of inf
Endpoint:  sipgate                                              In use        1 of inf

Objects found: 4
"""
TRANSPORTS = """
Transport:  <TransportId........>  <Type>  <cos>  <tos>  <BindAddress....................>
==========================================================================================

Transport:  0.0.0.0-udp               udp      0      0  0.0.0.0:5060
Transport:  0.0.0.0-tcp               tcp      0      0  0.0.0.0:5060

Objects found: 2
"""
UPGRADES = """__UPGRADES__
Module Upgrades Available
+-----------+---------------+----------------+
| Module    | Local Version | Online Version |
+-----------+---------------+----------------+
| core      | 17.0.12       | 17.0.14        |
| framework | 17.0.19       | 17.0.20        |
+-----------+---------------+----------------+
__END__
"""


def _fake_bin(tmp_path: Path) -> dict:
    b = tmp_path / "bin"
    b.mkdir()
    cmds = {"pjsip show registrations": REGS, "pjsip show contacts": CONTACTS, "pjsip list endpoints": ENDPOINTS,
            "pjsip show transports": TRANSPORTS, "core show version": "Asterisk 20.9.3 built by root @ pbx on x86_64",
            "core show uptime seconds": "System uptime: 93784\nLast reload: 400",
            "core show channels count": "1 active channel\n1 active call\n57 calls processed",
            "sip show registry": "No such command 'sip show registry'"}
    lines = ["#!/bin/bash", 'case "$2" in']
    for k, v in cmds.items():
        (tmp_path / (k.replace(" ", "_") + ".txt")).write_text(v)
        lines.append(f'  "{k}") cat "{tmp_path}/{k.replace(" ", "_")}.txt" ;;')
    lines += ["esac"]
    (b / "asterisk").write_text("\n".join(lines) + "\n")
    (b / "pgrep").write_text("#!/bin/bash\nexit 0\n")
    (b / "fwconsole").write_text("#!/bin/bash\necho fwconsole \"$@\" >> " + str(tmp_path / "fw.log") + "\n")
    (b / "mysql").write_text("#!/bin/bash\n"
                             "q=\"$(cat)\"\n"
                             "case \"$q\" in\n"
                             "  *framework*) echo 17.0.19 ;;\n"
                             "  *'FROM users u'*) printf '201\\tMax Muster\\tpjsip\\tdefault\\n202\\tEva\\tpjsip\\tnovm\\n' ;;\n"
                             "esac\n")
    for f in b.iterdir():
        f.chmod(0o755)
    return {**os.environ, "PATH": f"{b}:{os.environ['PATH']}", "SM_TASK": "status"}


def test_status_script_and_parser(tmp_path):
    env = _fake_bin(tmp_path)
    body = (SCRIPTS / "lib.sh").read_text() + "\n" + (SCRIPTS / "asterisk.sh").read_text()
    res = subprocess.run(["bash", "-c", body], capture_output=True, text=True, env=env)
    assert res.returncode == 0, res.stdout + res.stderr
    d = pbx.parse_status(res.stdout)
    assert d["version"] == "20.9.3" and d["freepbx"] == "17.0.19" and d["is_freepbx"] and d["active"]
    assert (d["uptime"], d["calls"], d["processed"]) == (93784, 1, 57)
    regs = {r["name"]: r for r in d["registrations"]}
    assert regs["sipgate"]["ok"] and regs["sipgate"]["status"] == "Registered"
    assert not regs["easybell"]["ok"] and regs["easybell"]["status"] == "Rejected"
    exts = {e["ext"]: e for e in d["extensions"]}
    assert exts["201"]["online"] and exts["201"]["name"] == "Max Muster" and exts["201"]["voicemail"]
    assert exts["201"]["contact"]["ip"] == "10.20.0.51"
    assert not exts["202"]["online"] and not exts["202"]["voicemail"] and exts["202"]["contact"]["rtt"] == ""
    assert d["extensions_online"] == 1
    assert {t["name"] for t in d["trunks"]} == {"easybell", "sipgate"}
    assert [t["port"] for t in d["transports"]] == [5060, 5060]
    alerts = {a["key"]: a for a in pbx.alerts(d)}
    assert alerts["reg:easybell"]["severity"] == "crit" and "reg:sipgate" not in alerts
    assert "trunk:easybell" not in alerts  # already reported through its registration


def test_upgrades_and_down_alert():
    assert pbx.parse_upgrades(UPGRADES) == [{"module": "core", "local": "17.0.12", "online": "17.0.14"},
                                            {"module": "framework", "local": "17.0.19", "online": "17.0.20"}]
    assert pbx.alerts({"active": False}) == [{"key": "down", "severity": "crit", "text": "Asterisk läuft nicht"}]


def test_sip_registry_legacy():
    lines = ["Host                                    dnsmgr Username       Refresh State                Reg.Time",
             "sip.provider.de:5060                    N      4930123        105 Registered           Mon, 01 Jan",
             "1 SIP registrations."]
    regs = pbx.parse_sip_registry(lines)
    assert regs == [{"name": "sip.provider.de:5060", "uri": "sip.provider.de:5060", "auth": "4930123",
                     "status": "Registered", "ok": True, "tech": "sip"}]


def test_validate_extension():
    env = pbx.validate_extension("201", "Max Muster", "abcdefgh12", "max@example.com", "1234")
    assert env["SM_EXT"] == "201" and env["SM_VM_PIN"] == "1234"
    for bad in (("2",), ("201", 'x"y'), ("201", "ok", "kurz"), ("201", "ok", "", "keine-mail"),
                ("201", "ok", "", "", "12")):
        with pytest.raises(pbx.PbxError):
            pbx.validate_extension(*bad)
    assert len(pbx.sip_secret()) == 24 and pbx.SECRET_RE.match(pbx.sip_secret())


def test_extension_add_script(tmp_path):
    env = _fake_bin(tmp_path)
    # bulk handler present; after the import the extension exists
    (tmp_path / "bin" / "fwconsole").write_text(
        "#!/bin/bash\necho \"$@\" >> " + str(tmp_path / "fw.log") + "\n"
        "if [ \"$1 $2\" = 'ma list' ]; then echo '| bulkhandler | 17.0.1 | Enabled |'; fi\n"
        "if [ \"$1\" = bulkimport ]; then cp \"${@: -1}\" " + str(tmp_path / "import.csv") + "; touch "
        + str(tmp_path / "created") + "; fi\n")
    (tmp_path / "bin" / "mysql").write_text(
        "#!/bin/bash\nq=\"$(cat)\"\n"
        "case \"$q\" in *\"WHERE extension='203'\"*) [ -f " + str(tmp_path / "created") + " ] && echo 203 ;; esac\n")
    env.update({"SM_TASK": "ext_add", "SM_EXT": "203", "SM_NAME": 'Anna "Chefin", Vertrieb',
                "SM_SECRET": "Geheim123456", "SM_VM_EMAIL": "anna@example.com", "SM_VM_PIN": "4711"})
    body = (SCRIPTS / "lib.sh").read_text() + "\n" + (SCRIPTS / "asterisk.sh").read_text()
    res = subprocess.run(["bash", "-c", body], capture_output=True, text=True, env=env)
    assert res.returncode == 0 and "SM_OK" in res.stdout, res.stdout + res.stderr
    csv_text = (tmp_path / "import.csv").read_text()
    import csv
    rows = list(csv.DictReader(csv_text.splitlines()))
    assert rows[0]["extension"] == "203" and rows[0]["name"] == 'Anna "Chefin", Vertrieb'
    assert rows[0]["voicemail_enable"] == "yes" and rows[0]["voicemail_email"] == "anna@example.com"
    assert "reload" in (tmp_path / "fw.log").read_text()


# --------------------------------------------------------------------------
# web + router
# --------------------------------------------------------------------------
@pytest.fixture(scope="module")
def mock():
    srv = m.MockServer().start()
    yield srv
    srv.stop()


SAMPLE = None


@pytest.fixture()
def pbx_obj(db, mock, monkeypatch, tmp_path):
    from servermanager.models import PbxServer, RouterDevice, System
    global SAMPLE
    if SAMPLE is None:
        env = _fake_bin(tmp_path)
        body = (SCRIPTS / "lib.sh").read_text() + "\n" + (SCRIPTS / "asterisk.sh").read_text()
        SAMPLE = pbx.parse_status(subprocess.run(["bash", "-c", body], capture_output=True, text=True,
                                                 env=env).stdout)
    monkeypatch.setattr(pbx, "status", lambda system: SAMPLE)
    calls = []
    monkeypatch.setattr(pbx, "extension_task", lambda system, task, env: calls.append((task, env)) or "SM_OK")
    router = RouterDevice(name="chr-pbx", api_url=mock.url, username=m.ROS_USER,
                          password_enc=security.encrypt(m.ROS_PASS), fingerprint=mock.fingerprint)
    system = System(name="pbx01", host="10.20.0.40", types=["debian", "asterisk"])
    db.add_all([router, system])
    db.flush()
    p = PbxServer(name="Telefonanlage", system_id=system.id, sip_internal_ip="10.20.0.40", router_id=router.id,
                  public_url="https://pbx.example.com", web_url="https://10.20.0.40", sip_port=5060,
                  rtp_start=10000, rtp_end=20000)
    db.add(p)
    db.commit()
    yield {"pbx": p, "router": router, "system": system, "calls": calls}
    for o in (p, system, router):
        db.delete(o)
    db.commit()


def test_poll_sets_alerts(db, pbx_obj):
    from servermanager import integrations
    p = pbx_obj["pbx"]
    integrations.poll(db, p)
    assert p.status == "online" and p.data["version"] == "20.9.3"
    assert any("easybell" in a["text"] for a in p.alert_list)


def test_web_pages_and_actions(app, db, pbx_obj):
    from servermanager.models import IntegrationAccess
    make_user(db, "pbx-admin", "admin")
    c = login(app, "pbx-admin")
    pid = pbx_obj["pbx"].id
    assert "Telefonie" in c.get("/").text
    assert "Telefonanlage" in c.get("/telefonie/").text
    for tab in ("overview", "extensions", "trunks", "network"):
        r = c.get(f"/telefonie/{pid}?tab={tab}")
        assert r.status_code == 200, (tab, r.text[:300])
    ext = c.get(f"/telefonie/{pid}?tab=extensions").text
    assert "Max Muster" in ext and "Nebenstelle anlegen" in ext
    net = c.get(f"/telefonie/{pid}?tab=network").text
    assert "Externe Adresse nicht gesetzt" in net and "für alle Absender" in net
    r = c.post(f"/telefonie/{pid}/do", data={"action": "ext_add", "ext": "203", "name": "Anna",
                                               "csrf_token": c.csrf}, follow_redirects=True)
    assert "Nebenstelle 203 angelegt" in r.text and "SIP-Passwort (wird nur jetzt angezeigt)" in r.text
    task, env = pbx_obj["calls"][-1]
    assert task == "ext_add" and env["SM_EXT"] == "203" and pbx.SECRET_RE.match(env["SM_SECRET"])
    r = c.post(f"/telefonie/{pid}/do", data={"action": "ext_add", "ext": "2", "csrf_token": c.csrf},
               follow_redirects=True)
    assert "Nebenstelle: 2–8 Ziffern" in r.text
    # viewer: sees the extensions, may not change them
    viewer = make_user(db, "pbx-viewer")
    db.add(IntegrationAccess(user_id=viewer.id, kind="pbx", obj_id=pid, level="view"))
    db.commit()
    v = login(app, "pbx-viewer")
    page = v.get(f"/telefonie/{pid}?tab=extensions").text
    assert "Max Muster" in page and "Nebenstelle anlegen" not in page and "Neues SIP-Passwort" not in page
    assert v.post(f"/telefonie/{pid}/do", data={"action": "ext_delete", "ext": "201",
                                                 "csrf_token": v.csrf}).status_code == 403


def test_form_create(app, db, pbx_obj):
    from servermanager.models import PbxServer
    make_user(db, "pbx-admin", "admin")
    c = login(app, "pbx-admin")
    sid = pbx_obj["system"].id
    assert "Asterisk erkannt" in c.get(f"/telefonie/new?system={sid}").text
    r = c.post("/telefonie/new", data={"name": "pbx2", "system_id": str(sid), "sip_port": "5060",
                                       "rtp_start": "20000", "rtp_end": "10000", "sip_sources": "1.2.3.4, nix",
                                       "csrf_token": c.csrf})
    assert "Start muss kleiner" in r.text and "nix ist keine IP" in r.text
    r = c.post("/telefonie/new", data={"name": "pbx2", "system_id": str(sid), "sip_port": "5160",
                                       "rtp_start": "10000", "rtp_end": "20000", "sip_sources": "217.10.79.0/24",
                                       "monitor": "1", "csrf_token": c.csrf})
    assert r.status_code == 302
    p = db.query(PbxServer).filter_by(name="pbx2").one()
    assert p.sip_internal_ip == "10.20.0.40" and p.web_url == "http://10.20.0.40" and p.sip_port == 5160
    db.delete(p)
    db.commit()


def test_router_proposals(db, mock, pbx_obj):
    from servermanager import optimize
    ros = mock.state.ros
    ros["ip/firewall/service-port"] = [{".id": "*S1", "name": "sip", "disabled": "false", "ports": "5060,5061"}]
    p = pbx_obj["pbx"]
    p.sip_sources = "217.10.79.0/24"
    db.commit()
    props = {x["id"]: x for x in optimize.scan_pbx(db, p)}
    alg = props[f"pbx:{p.id}:alg"]
    assert alg["action"] == "router_direct_ops"
    assert all(routeros.direct_op_allowed(op) for op in alg["params"]["ops"])
    fwd = props[f"pbx:{p.id}:router"]["params"]["ops"]
    nat = [op["data"] for op in fwd if op["path"] == "ip/firewall/nat"]
    assert {(n["protocol"], n["dst-port"]) for n in nat} == {("udp", "5060"), ("tcp", "5060"), ("udp", "10000-20000")}
    assert all(n.get("src-address-list") == f"sm-sip-{p.id}" for n in nat if n["dst-port"] == "5060")
    assert "src-address-list" not in next(n for n in nat if n["dst-port"] == "10000-20000")
    assert any(op["path"] == "ip/firewall/address-list" and op["data"]["address"] == "217.10.79.0/24" for op in fwd)
    assert all(routeros.direct_op_allowed(op) for op in fwd)
    assert f"pbx:{p.id}:open" not in props
    # applied rules count as covered; SIP forwards are no candidates for Pangolin
    from servermanager.mikrotik import MikroTik
    mt = MikroTik(mock.url, m.ROS_USER, m.ROS_PASS, fingerprint=mock.fingerprint)
    routeros.apply_ops(mt, fwd + alg["params"]["ops"], lambda _l: None)
    props = {x["id"]: x for x in optimize.scan_pbx(db, p)}
    assert f"pbx:{p.id}:router" not in props and f"pbx:{p.id}:alg" not in props
    assert optimize._is_pbx_forward(db, {"to-addresses": "10.20.0.40", "protocol": "udp"})
    ros.pop("ip/firewall/service-port", None)
    ros["ip/firewall/nat"] = [r for r in ros.get("ip/firewall/nat", []) if "SIP" not in str(r.get("comment"))]
    ros["ip/firewall/address-list"] = [r for r in ros.get("ip/firewall/address-list", [])
                                       if "SIP" not in str(r.get("comment"))]


def test_direct_op_allowlist():
    assert not routeros.direct_op_allowed(routeros.op_set("ip/firewall/service-port", {"disabled": "no"}, "*1"))
    assert not routeros.direct_op_allowed(routeros.op_add("user", {"name": "x"}))
    assert not routeros.direct_op_allowed(routeros.op_set("ip/firewall/nat", {"disabled": "yes"}, "*1"))
