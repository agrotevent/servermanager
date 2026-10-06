"""Hetzner Robot: client, synchronisation, rights (Auswerten / Neustarten / Ändern) per account and server."""
from datetime import date

import pytest

from servermanager import hetzner, security
from servermanager.hetzner import Robot, RobotError
from tests import mock_apis as m
from tests.test_web import login, make_user


@pytest.fixture(scope="module")
def mock():
    srv = m.MockServer().start()
    yield srv
    srv.stop()


def robot(mock, pw=m.HZ_PASS):
    return Robot(m.HZ_USER, pw, base=f"{mock.url}/robot", fingerprint=mock.fingerprint)


@pytest.fixture()
def account(db, mock):
    from servermanager.models import HetznerAccount, HetznerServer
    a = HetznerAccount(name="hz", username=m.HZ_USER, password_enc=security.encrypt(m.HZ_PASS),
                       api_url=f"{mock.url}/robot", fingerprint=mock.fingerprint, traffic_alert_pct=0)
    db.add(a)
    db.commit()
    yield a
    db.query(HetznerServer).filter_by(account_id=a.id).delete()
    db.delete(a)
    db.commit()


# --------------------------------------------------------------------------
def test_helpers():
    assert hetzner.parse_limit_gb("20 TB") == 20480 and hetzner.parse_limit_gb("unlimited") is None
    assert hetzner.parse_limit_gb("500 GB") == 500
    assert hetzner.validate_ptr("Mail.Example.com.") == "mail.example.com"
    for bad in ("", "a b.de", "x" * 300 + ".de", "-bad.example.com", "localhost"):
        with pytest.raises(RobotError):
            hetzner.validate_ptr(bad)
    s = {"server_ip": "1.2.3.4", "ip": ["1.2.3.4"], "subnet": [{"ip": "2a01:4f8::", "mask": "64"}]}
    assert hetzner.belongs_to("2a01:4f8::abcd", s) and hetzner.belongs_to("1.2.3.4", s)
    assert not hetzner.belongs_to("1.2.3.5", s) and not hetzner.belongs_to("2a01:4f9::1", s)
    assert hetzner.month_range(2026, 2, date(2026, 10, 3)) == ("2026-02-01", "2026-02-28")
    assert hetzner.month_range(2026, 10, date(2026, 10, 3)) == ("2026-10-01", "2026-10-03")
    days, total = hetzner.sum_series({"1.2.3.4": {"01": {"in": 1, "out": 2, "sum": 3}},
                                      "2a01::": {"01": {"in": 1, "out": 1, "sum": 2}}}, ["1.2.3.4", "2a01::/64"])
    assert days == {"01": {"in": 2.0, "out": 3.0, "sum": 5.0}} and total["sum"] == 5.0
    with pytest.raises(RobotError, match="https"):
        Robot("u", "p", base="http://robot.example.com")


def test_client(mock):
    r = robot(mock)
    assert [s["server_number"] for s in r.servers()] == [321, 654]
    assert r.reset_options()[321] == ["sw", "hw", "man"]
    r.set_rdns("88.99.10.7", "web.example.com")
    assert mock.state.hz_rdns["88.99.10.7"] == "web.example.com"
    r.delete_rdns("88.99.10.7")
    r.delete_rdns("88.99.10.7")  # already gone: no error
    data = r.traffic("month", "2026-10-01", "2026-10-03", ["88.99.10.1"], ["2a01:4f8:10:1::/64"])
    q = mock.state.hz_traffic_queries[-1]
    assert q == {"type": "month", "from": "2026-10-01", "to": "2026-10-03", "ip": ["88.99.10.1"],
                 "subnet": ["2a01:4f8:10:1::"], "single_values": "true"}  # network address without prefix
    assert data["88.99.10.1"]["01"]["sum"] == 11.5 and data["2a01:4f8:10:1::"]["01"]["sum"] == 1.5
    # a subnet Hetzner refuses: the IPs and the other subnets are still evaluated
    mock.state.hz_reject_subnets = {"2a01:4f8:10:1::"}
    try:
        data = r.traffic("month", "2026-10-01", "2026-10-03", ["88.99.10.1"],
                         ["2a01:4f8:10:1::/64", "2a01:4f8:fff0:53::/64"])
        assert set(data) == {"88.99.10.1", "2a01:4f8:fff0:53::"} and r.skipped_subnets == ["2a01:4f8:10:1::"]
    finally:
        mock.state.hz_reject_subnets = set()
    with pytest.raises(RobotError, match="Webservice-Benutzer"):
        robot(mock, "falsch").servers()
    with pytest.raises(RobotError, match="Ungültige Eingabe \\(ptr\\)"):
        r.request("POST", "rdns/88.99.10.7", {"ptr": ""})
    saved = list(mock.state.hz_resets)
    mock.state.hz_resets[:] = [(0, "x")] * 50
    try:
        with pytest.raises(RobotError, match="begrenzt"):
            r.reset(321, "sw")
    finally:
        mock.state.hz_resets[:] = saved


def test_sync(db, mock, account):
    from servermanager import integrations
    from servermanager.models import HetznerServer, System
    sys_ = System(name="pve-fsn-sys", host="88.99.10.1")
    db.add(sys_)
    db.commit()
    try:
        account.traffic_alert_pct = 90
        integrations.poll(db, account)
        db.commit()
        assert account.status == "online", account.status_message
        rows = {r.number: r for r in db.query(HetznerServer).filter_by(account_id=account.id)}
        a, b = rows[321], rows[654]
        assert a.name == "pve-fsn" and b.name == "#654" and a.system_id == sys_.id and b.cancelled
        ips = {r["ip"]: r for r in a.info["ips"]}
        assert ips["88.99.10.1"]["ptr"] == "pve-fsn.example.com" and ips["88.99.10.1"]["main"]
        assert ips["2a01:4f8:10:1::2"]["ptr"] == "mail.example.com"  # IPv6 PTR from the server's /64
        assert a.info["reset"] == ["sw", "hw", "man"]
        # 2 IPs à 11.5 GB + the /64 à 1.5 GB per day, 3 days
        assert a.info["traffic"]["total"]["sum"] == pytest.approx(3 * (2 * 11.5 + 1.5))
        keys = {x["key"] for x in account.alerts}
        assert "cancelled:654" in keys and "traffic:654" in keys and "traffic:321" not in keys  # unlimited
        over = next(x for x in account.alerts if x["key"] == "traffic:654")
        assert over["severity"] == "crit" and "115 %" in over["text"]  # 34.5 of 30 GB
        # a server that disappears from the account is removed
        gone = mock.state.hz_servers.pop()
        try:
            integrations.poll(db, account)
            db.commit()
            assert {r.number for r in db.query(HetznerServer).filter_by(account_id=account.id)} == {321}
        finally:
            mock.state.hz_servers.append(gone)
    finally:
        db.delete(sys_)
        db.commit()


def test_rights_per_account_and_server(app, db, mock, account):
    from servermanager import integrations
    from servermanager.models import HetznerServer, IntegrationAccess
    integrations.poll(db, account)
    db.commit()
    rows = {r.number: r for r in db.query(HetznerServer).filter_by(account_id=account.id)}
    a, b = rows[321], rows[654]
    viewer, rebooter, changer = make_user(db, "hz-view"), make_user(db, "hz-reboot"), make_user(db, "hz-change")
    db.add_all([IntegrationAccess(user_id=viewer.id, kind="hetzner_srv", obj_id=a.id, level="view"),
                IntegrationAccess(user_id=rebooter.id, kind="hetzner_srv", obj_id=a.id, level="operate"),
                IntegrationAccess(user_id=changer.id, kind="hetzner", obj_id=account.id, level="full")])
    db.commit()
    st = mock.state
    try:
        c = login(app, "hz-view")
        page = c.get("/hetzner/").text
        assert "pve-fsn" in page and "#654" not in page  # only the granted server
        assert c.get(f"/hetzner/server/{b.id}").status_code == 403
        page = c.get(f"/hetzner/server/{a.id}").text
        assert "pve-fsn.example.com" in page and "Für Neustarts fehlt" in page
        assert c.post(f"/hetzner/server/{a.id}/reset", data={"type": "sw", "csrf_token": c.csrf}).status_code == 403
        assert c.post(f"/hetzner/server/{a.id}/rdns", data={"ip": "88.99.10.7", "ptr": "x.example.com",
                                                            "csrf_token": c.csrf}).status_code == 403
        # Neustarten: software/hardware reset and WOL, but no changes and no technician
        c = login(app, "hz-reboot")
        n = len(st.hz_resets)
        assert c.post(f"/hetzner/server/{a.id}/reset", data={"type": "sw", "csrf_token": c.csrf}).status_code == 302
        assert c.post(f"/hetzner/server/{a.id}/wol", data={"csrf_token": c.csrf}).status_code == 302
        assert st.hz_resets[n:] == [(321, "sw"), (321, "wol")]
        assert c.post(f"/hetzner/server/{a.id}/reset", data={"type": "man", "csrf_token": c.csrf}).status_code == 403
        assert c.post(f"/hetzner/server/{a.id}/rename", data={"name": "x", "csrf_token": c.csrf}).status_code == 403
        assert c.post(f"/hetzner/server/{b.id}/reset", data={"type": "hw", "csrf_token": c.csrf}).status_code == 403
        # a reset type Hetzner does not offer for the server is refused without calling the API
        c.post(f"/hetzner/server/{a.id}/reset", data={"type": "power", "csrf_token": c.csrf})
        assert st.hz_resets[-1] == (321, "wol")
        # Ändern on the whole account: PTR, IPv6 PTR in the server's net, name, traffic warnings
        c = login(app, "hz-change")
        assert "#654" in c.get("/hetzner/").text
        r = c.post(f"/hetzner/server/{a.id}/rdns", data={"ip": "88.99.10.7", "ptr": "Web.Example.com",
                                                         "csrf_token": c.csrf})
        assert r.status_code == 302 and st.hz_rdns["88.99.10.7"] == "web.example.com"
        c.post(f"/hetzner/server/{a.id}/rdns", data={"ip": "2a01:4f8:10:1::25", "ptr": "v6.example.com",
                                                     "csrf_token": c.csrf})
        assert st.hz_rdns["2a01:4f8:10:1::25"] == "v6.example.com"
        r = c.post(f"/hetzner/server/{a.id}/rdns", data={"ip": "5.9.20.2", "ptr": "steal.example.com",
                                                         "csrf_token": c.csrf})
        assert r.status_code == 400 and "5.9.20.2" not in st.hz_rdns  # address of another server
        c.post(f"/hetzner/server/{a.id}/rdns", data={"ip": "88.99.10.7", "ptr": "", "csrf_token": c.csrf})
        assert "88.99.10.7" not in st.hz_rdns
        c.post(f"/hetzner/server/{a.id}/traffic-warnings", data={"ip": "88.99.10.1", "enabled": "1", "hourly": "100",
                                                                 "daily": "1000", "monthly": "50",
                                                                 "csrf_token": c.csrf})
        assert st.hz_ips["88.99.10.1"]["traffic_warnings"] is True and st.hz_ips["88.99.10.1"]["traffic_monthly"] == 50
        c.post(f"/hetzner/server/{a.id}/rename", data={"name": "pve-falkenstein", "csrf_token": c.csrf})
        assert st.hz_servers[0]["server_name"] == "pve-falkenstein"
        db.expire_all()
        assert db.get(HetznerServer, a.id).name == "pve-falkenstein"
        assert c.post(f"/hetzner/server/{a.id}/reset", data={"type": "man", "csrf_token": c.csrf}).status_code == 302
        assert st.hz_resets[-1] == (321, "man")
        # traffic of another month / the year (fetched live)
        page = c.get(f"/hetzner/server/{a.id}?period=year&m=2026-01").text
        assert st.hz_traffic_queries[-1]["type"] == "year" and "Eingehend" in page
        page = c.get(f"/hetzner/server/{a.id}?m=2026-02").text
        assert st.hz_traffic_queries[-1]["from"] == "2026-02-01" and "<svg" in page
        # account settings stay with administrators
        assert c.get(f"/hetzner/account/{account.id}/edit").status_code == 403
        st.hz_servers[0]["server_name"] = "pve-fsn"
    finally:
        for u in (viewer, rebooter, changer):
            db.query(IntegrationAccess).filter_by(user_id=u.id).delete()
            db.delete(u)
        db.commit()


def test_admin_pages(app, db, mock, monkeypatch):
    from servermanager.models import HetznerAccount, HetznerServer

    def offline(self, *a, **k):
        raise RobotError("Hetzner Robot nicht erreichbar: Testumgebung")
    monkeypatch.setattr(Robot, "request", offline)  # never call the real Robot from tests
    make_user(db, "hz-admin", "admin")
    c = login(app, "hz-admin")
    assert "Webservice-Benutzer" in c.get("/hetzner/new").text
    r = c.post("/hetzner/new", data={"name": "hz-neu", "username": m.HZ_USER, "password": "falsch",
                                     "traffic_alert_pct": "90", "monitor": "1", "csrf_token": c.csrf})
    assert r.status_code == 302
    a = db.query(HetznerAccount).filter_by(name="hz-neu").one()
    assert a.status == "error" and "Testumgebung" in a.status_message
    assert security.decrypt(a.password_enc) == "falsch" and "falsch" not in a.password_enc
    users = c.get("/users/new").text
    assert ">Neustarten</option>" in users and "Ändern = Neustarten + PTR" in users
    db.query(HetznerServer).filter_by(account_id=a.id).delete()
    db.commit()
    c.post(f"/hetzner/account/{a.id}/delete", data={"csrf_token": c.csrf})
    assert not db.query(HetznerAccount).filter_by(name="hz-neu").first()


def test_vswitch(app, db, mock, account):
    from servermanager import integrations
    from servermanager.models import HetznerServer, IntegrationAccess, PveServer
    st = mock.state
    st.hz_rdns["88.99.200.3"] = "gw.example.com"
    pve = PveServer(name="pve-hz", api_url="https://10.0.0.9:8006", token_id="a@pve!b",
                    token_secret_enc=security.encrypt("x"), hosting="hetzner", vswitch_vlan=4001)
    db.add(pve)
    db.commit()
    try:
        integrations.poll(db, account)
        db.commit()
        assert account.status == "online", account.status_message
        v = account.data["vswitches"][0]
        assert v["vlan"] == 4001 and [x["name"] for x in v["servers"]] == ["pve-fsn", "#654"]
        assert v["rdns"] == [{"ip": "88.99.200.3", "ptr": "gw.example.com"}]
        # vSwitch nets are part of the traffic query – as bare network addresses
        q = st.hz_traffic_queries[-1]
        assert "88.99.200.0" in q["subnet"] and "2a01:4f8:fff0:53::" in q["subnet"]
        assert v["traffic"]["total"]["sum"] == pytest.approx(2 * 3 * 1.5)
        assert any(a["key"] == "vswitch:50301:654" for a in account.alerts)  # failed connection
        srv = db.query(HetznerServer).filter_by(account_id=account.id, number=321).one()
        assert srv.info["vswitches"][0]["status"] == "ready"
        # the 88.99.200.x PTR belongs to the vSwitch, not to the server
        assert "88.99.200.3" not in {r["ip"] for r in srv.info["ips"]}

        viewer, admin_like = make_user(db, "hz-vs-view"), make_user(db, "hz-vs-full")
        db.add_all([IntegrationAccess(user_id=viewer.id, kind="hetzner_srv", obj_id=srv.id, level="full"),
                    IntegrationAccess(user_id=admin_like.id, kind="hetzner", obj_id=account.id, level="full")])
        db.commit()
        c = login(app, "hz-vs-view")
        page = c.get(f"/hetzner/server/{srv.id}").text
        assert "pve-lan" in page and "88.99.200.0/29" in page  # summary on the server page
        assert c.get(f"/hetzner/account/{account.id}/vswitch/50301").status_code == 403  # needs account rights
        assert c.post(f"/hetzner/account/{account.id}/vswitch/50301/rdns",
                      data={"ip": "88.99.200.4", "ptr": "x.example.com", "csrf_token": c.csrf}).status_code == 403
        c = login(app, "hz-vs-full")
        page = c.get(f"/hetzner/account/{account.id}/vswitch/50301").text
        assert "gw.example.com" in page and "fehlgeschlagen" in page
        assert "pve-hz" not in page  # no rights on the Proxmox server: no link
        db.add(IntegrationAccess(user_id=admin_like.id, kind="pve", obj_id=pve.id, level="view"))
        db.commit()
        assert "pve-hz" in c.get(f"/hetzner/account/{account.id}/vswitch/50301").text
        assert "pve-lan" in c.get("/hetzner/").text
        c.post(f"/hetzner/account/{account.id}/vswitch/50301/rdns",
               data={"ip": "2a01:4f8:fff0:53::10", "ptr": "v6.example.com", "csrf_token": c.csrf})
        assert st.hz_rdns["2a01:4f8:fff0:53::10"] == "v6.example.com"
        r = c.post(f"/hetzner/account/{account.id}/vswitch/50301/rdns",
                   data={"ip": "88.99.10.1", "ptr": "x.example.com", "csrf_token": c.csrf})
        assert r.status_code == 400  # a server address is not a vSwitch address
        page = c.get(f"/hetzner/account/{account.id}/vswitch/50301?m=2026-02").text
        assert st.hz_traffic_queries[-1]["ip"] == [] and "<svg" in page
        for u in (viewer, admin_like):
            db.query(IntegrationAccess).filter_by(user_id=u.id).delete()
            db.delete(u)
        db.commit()
    finally:
        st.hz_rdns.pop("88.99.200.3", None)
        st.hz_rdns.pop("2a01:4f8:fff0:53::10", None)
        db.delete(pve)
        db.commit()


def test_vswitch_without_traffic_data(app, db, mock, account):
    """Robot answers 'Not Found' for vSwitch nets: the servers keep their traffic, the vSwitch says why."""
    from servermanager import integrations
    from servermanager.models import HetznerServer
    st = mock.state
    st.hz_notfound_subnets = {"88.99.200.0", "2a01:4f8:fff0:53::"}
    try:
        integrations.poll(db, account)
        db.commit()
        assert account.status == "online", account.status_message
        assert not account.data["traffic_error"]
        srv = db.query(HetznerServer).filter_by(account_id=account.id, number=321).one()
        assert srv.info["traffic"]["total"]["sum"] == pytest.approx(3 * (2 * 11.5 + 1.5))
        v = account.data["vswitches"][0]
        assert "keine Traffic-Werte" in v["traffic"]["error"] and v["traffic"]["total"]["sum"] == 0
        make_user(db, "hz-vs-nf", "admin")
        c = login(app, "hz-vs-nf")
        page = c.get(f"/hetzner/account/{account.id}/vswitch/50301").text
        assert "keine Traffic-Werte" in page and "Not Found" not in page
        page = c.get(f"/hetzner/account/{account.id}/vswitch/50301?m=2026-02").text  # live query, other month
        assert "keine Traffic-Werte" in page and "Not Found" not in page
    finally:
        st.hz_notfound_subnets = set()
