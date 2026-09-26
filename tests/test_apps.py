"""Nextcloud users (occ), Mailcow (mailboxes, mail IP), authentik (users, one-click SSO)."""
import pytest

from servermanager import security
from servermanager.authentik import Authentik, AuthentikError
from servermanager.mailcow import Mailcow, MailcowError
from servermanager.modules.nextcloud import parse_users, validate_user
from tests import mock_apis as m
from tests.test_integrations import _run


@pytest.fixture(scope="module")
def mock():
    srv = m.MockServer().start()
    yield srv
    srv.stop()


@pytest.fixture()
def apps(db, mock):
    from servermanager.models import MailcowServer, PangolinServer, RouterDevice, SsoServer, System
    router = RouterDevice(name="chr-apps", api_url=mock.url, username=m.ROS_USER,
                          password_enc=security.encrypt(m.ROS_PASS), fingerprint=mock.fingerprint)
    db.add(router)
    db.flush()
    mc = MailcowServer(name="mc", api_url=f"https://127.0.0.1:{mock.port}", api_key_enc=security.encrypt(m.MC_KEY),
                       fingerprint=mock.fingerprint, public_url="https://webmail.example.com",
                       mail_hostname="mail.example.com", mail_public_ip="5.9.10.11", mail_internal_ip="10.20.0.30",
                       mail_ports="25,465,587,993,80", router_id=router.id)
    ak = SsoServer(name="auth", api_url=mock.url, public_url="https://auth.example.com",
                   token_enc=security.encrypt(m.AK_TOKEN), fingerprint=mock.fingerprint)
    nc = System(name="cloud-apps", host="10.20.0.40", types=["debian", "nextcloud"])
    pg = PangolinServer(name="pg-apps", api_url=mock.url, org_id=m.PG_ORG, api_key_enc=security.encrypt(m.PG_KEY),
                        fingerprint=mock.fingerprint, default_site_id=1, default_domain_id="dom1", role="primary")
    db.add_all([mc, ak, nc, pg])
    db.commit()
    others = db.query(PangolinServer).filter(PangolinServer.id != pg.id).all()
    saved = [(o, o.role) for o in others]
    for o in others:
        o.role = "inactive"
    db.commit()
    yield {"mc": mc, "ak": ak, "nc": nc, "router": router, "pg": pg}
    for o, role in saved:
        o.role = role
    from servermanager.models import SsoClient
    for c in db.query(SsoClient).all():
        db.delete(c)
    for o in (mc, ak, nc, router, pg):
        db.delete(o)
    db.commit()


# --------------------------------------------------------------------------
def test_parse_nextcloud_users():
    text = ('noise\n__USERS__\n{"anna": {"user_id": "anna", "display_name": "Anna", "email": "a@x.de", '
            '"enabled": false, "groups": ["admin"], "quota": "10 GB", "last_seen": "2026-09-01"}, '
            '"bob": "Bob"}\n__GROUPS__\n{"admin": ["anna"], "team": []}\n')
    users, groups = parse_users(text)
    assert [u["uid"] for u in users] == ["anna", "bob"]
    assert users[0]["enabled"] is False and users[0]["groups"] == ["admin"] and users[1]["display"] == "Bob"
    assert groups == ["admin", "team"]
    env = validate_user("max.muster", "max@x.de", "Team A, Buchhaltung", "10 GB")
    assert env["SM_GROUPS"] == "Team A,Buchhaltung"
    for bad in [("max muster",), ("x", "keine-mail"), ("x", "", "a;b"), ("x", "", "", "zehn")]:
        with pytest.raises(ValueError):
            validate_user(*bad)


def test_mailcow_client(mock):
    mc = Mailcow(f"https://127.0.0.1:{mock.port}", m.MC_KEY, fingerprint=mock.fingerprint)
    assert mc.version() == "2025-03" and mc.domains()[0]["domain_name"] == "example.com"
    assert mc.add_mailbox("Max.Muster", "example.com", "Max", "Geheim-12345", 2048) == "max.muster@example.com"
    with pytest.raises(MailcowError, match="object_exists"):
        mc.add_mailbox("max.muster", "example.com", "Max", "Geheim-12345")
    with pytest.raises(MailcowError):
        mc.add_mailbox("x", "unknown.org", "X", "Geheim-12345")
    mc.set_mailbox("max.muster@example.com", active="0")
    assert next(b for b in mock.state.mc_mailboxes if b["username"] == "max.muster@example.com")["active"] == 0
    mc.delete_mailbox("max.muster@example.com")
    assert all(b["username"] != "max.muster@example.com" for b in mock.state.mc_mailboxes)
    with pytest.raises(MailcowError, match="verweigert"):
        Mailcow(f"https://127.0.0.1:{mock.port}", "wrong", fingerprint=mock.fingerprint).domains()


def test_authentik_oidc_app_both_api_versions(mock):
    au = Authentik(mock.url, m.AK_TOKEN, public_url="https://auth.example.com", fingerprint=mock.fingerprint)
    app = au.create_oidc_app("Test", "sm-test-1", ["https://x.example.com/cb"], "https://x.example.com")
    prov = mock.state.ak_providers[app["provider_pk"]]
    assert prov["redirect_uris"] == [{"matching_mode": "strict", "url": "https://x.example.com/cb"}]
    assert prov["invalidation_flow"] == "flow-inv" and len(prov["property_mappings"]) == 3
    assert app["discovery"] == "https://auth.example.com/application/o/sm-test-1/.well-known/openid-configuration"
    with pytest.raises(AuthentikError, match="bereits"):
        au.create_oidc_app("Test", "sm-test-1", ["https://x.example.com/cb"], "https://x.example.com")
    au.delete_oidc_app("sm-test-1", app["provider_pk"])
    assert "sm-test-1" not in mock.state.ak_apps and app["provider_pk"] not in mock.state.ak_providers
    mock.state.ak_legacy = True
    try:
        app = au.create_oidc_app("Old", "sm-old-1", ["https://a/cb", "https://b/cb"], "https://a")
        prov = mock.state.ak_providers[app["provider_pk"]]
        assert prov["redirect_uris"] == "https://a/cb\nhttps://b/cb" and "invalidation_flow" not in prov
        au.delete_oidc_app("sm-old-1", app["provider_pk"])
    finally:
        mock.state.ak_legacy = False


def test_sso_connect_mailcow(db, mock, apps):
    from servermanager.jobs import enqueue, log_path
    from servermanager.models import Job, SsoClient
    job = enqueue(db, kind="sso_connect", title="sso", payload={"sso_id": apps["ak"].id, "kind": "mailcow",
                                                                "target_id": apps["mc"].id,
                                                                "app_url": "https://webmail.example.com"})
    db.commit()
    _run(job.id)
    db.expire_all()
    assert db.get(Job, job.id).status == "success", log_path(job.id).read_text()
    idp = mock.state.mc_idp
    assert idp["authsource"] == "generic-oidc" and idp["authorize_url"] == "https://auth.example.com/application/o/authorize/"
    assert idp["redirect_url"] == "https://webmail.example.com/" and idp["client_secret"].startswith("csec")
    client = db.query(SsoClient).filter_by(target_kind="mailcow", target_id=apps["mc"].id).one()
    assert client.slug in mock.state.ak_apps and client.status == "active"
    slug, cid = client.slug, client.id
    job = enqueue(db, kind="sso_disconnect", title="off", payload={"client_id": cid})
    db.commit()
    _run(job.id)
    db.expire_all()
    assert db.get(Job, job.id).status == "success"
    assert slug not in mock.state.ak_apps and not db.query(SsoClient).filter_by(id=cid).first()


def test_sso_connect_nextcloud_and_rollback(db, mock, apps, monkeypatch):
    from servermanager.jobs import enqueue, log_path
    from servermanager.models import Job, SsoClient
    from servermanager.modules import nextcloud as ncmod
    from servermanager.worker import Worker
    calls = []

    class DummyConn:
        def close(self):
            pass
    monkeypatch.setattr(Worker, "_connect", lambda self, ctx, system: DummyConn())
    fail = {"on": False}

    def fake_occ(conn, system, task, env=None, timeout=180):
        calls.append((task, dict(env or {})))
        if fail["on"]:
            return "[FEHLER] App-Store nicht erreichbar"
        return "SM_OK"
    monkeypatch.setattr(ncmod, "occ_task", fake_occ)
    job = enqueue(db, kind="sso_connect", title="sso", payload={"sso_id": apps["ak"].id, "kind": "nextcloud",
                                                                "target_id": apps["nc"].id,
                                                                "app_url": "https://cloud.example.com"})
    db.commit()
    _run(job.id)
    db.expire_all()
    assert db.get(Job, job.id).status == "success", log_path(job.id).read_text()
    task, env = calls[-1]
    assert task == "oidc_setup" and env["SM_OIDC_ID"] == "auth"
    assert env["SM_OIDC_DISCOVERY"].startswith("https://auth.example.com/application/o/sm-nextcloud-")
    client = db.query(SsoClient).filter_by(target_kind="nextcloud", target_id=apps["nc"].id).one()
    prov = mock.state.ak_providers[client.provider_pk]
    assert {"matching_mode": "strict", "url": "https://cloud.example.com/apps/user_oidc/code"} in prov["redirect_uris"]
    db.delete(client)
    mock.state.ak_apps.pop(client.slug, None)
    db.commit()
    # failure on the Nextcloud side removes the authentik application again
    fail["on"] = True
    apps_before = set(mock.state.ak_apps)
    job = enqueue(db, kind="sso_connect", title="sso", payload={"sso_id": apps["ak"].id, "kind": "nextcloud",
                                                                "target_id": apps["nc"].id,
                                                                "app_url": "https://cloud.example.com"})
    db.commit()
    _run(job.id)
    db.expire_all()
    job = db.get(Job, job.id)
    assert job.status == "failed" and set(mock.state.ak_apps) == apps_before
    assert not db.query(SsoClient).filter_by(target_kind="nextcloud", target_id=apps["nc"].id).first()


def test_mail_ip_and_web_publication_proposals(db, mock, apps):
    from servermanager import optimize
    from servermanager.jobs import enqueue, log_path
    from servermanager.models import Job
    mock.state.domains = [{"domainId": "dom1", "baseDomain": "example.com"}]
    result = optimize.scan(db)
    ids = {p["id"]: p for p in result["proposals"]}
    mail = ids[f"mail:{apps['mc'].id}:router"]
    ops = mail["params"]["ops"]
    assert ops[0]["data"] == {"address": "5.9.10.11/32", "interface": "ether1-wan",
                              "comment": "servermanager: Mail-IP mc"}
    assert ops[1]["data"]["dst-port"] == "25,465,587,993,80" and ops[1]["data"]["to-addresses"] == "10.20.0.30"
    assert ops[2]["data"]["action"] == "src-nat" and ops[2]["data"]["to-addresses"] == "5.9.10.11"
    assert ops[2]["data"]["place-before"]  # before the general masquerade
    pub = ids[f"app:sso:{apps['ak'].id}:publish"]
    assert pub["action"] == "publish_forward" and pub["params"]["subdomain"] == "auth"
    assert pub["params"]["sso"] is False and pub["params"]["ip"] == "127.0.0.1"
    assert ids[f"app:mailcow:{apps['mc'].id}:publish"]["params"]["subdomain"] == "webmail"

    def item(p):
        return {"id": p["id"], "title": p["title"], "action": p["action"], "params": p["params"], "obj": p["obj"],
                "inputs": {}}
    job = enqueue(db, kind="optimize", title="mail", payload={"items": [item(mail), item(pub)]})
    db.commit()
    _run(job.id)
    db.expire_all()
    assert db.get(Job, job.id).status == "success", log_path(job.id).read_text()
    assert any(a.get("address") == "5.9.10.11/32" for a in mock.state.ros["ip/address"])
    res = next(r for r in mock.state.resources.values() if r["fullDomain"] == "auth.example.com")
    assert res["sso"] is False
    # the mail forwards are an allowed exception: no "replace by Pangolin" proposal for them
    result = optimize.scan(db)
    mailfwd = [p for p in result["proposals"] if p["id"].startswith(f"router:{apps['router'].id}:fwd")
               and "5.9.10.11" in p["title"]]
    assert not mailfwd
    assert f"mail:{apps['mc'].id}:router" not in {p["id"] for p in result["proposals"]}
    # never touch the router with other operations than the whitelisted ones
    bad = dict(item(mail), params={"router_id": apps["router"].id,
                                   "ops": [{"m": "add", "path": "ip/firewall/filter", "data": {}}]})
    job = enqueue(db, kind="optimize", title="bad", payload={"items": [bad]})
    db.commit()
    _run(job.id)
    db.expire_all()
    assert "Unzulässige" in db.get(Job, job.id).summary


def test_web_pages_and_user_management(app, db, mock, apps, monkeypatch):
    from servermanager import inventory
    from servermanager.modules import nextcloud as ncmod
    from servermanager.web.views import nextcloud_users
    from tests.test_web import login, make_user
    make_user(db, "apps-admin", "admin")
    c = login(app, "apps-admin")
    mc, ak, nc = apps["mc"], apps["ak"], apps["nc"]
    for url in ["/mailcow/", "/mailcow/new", f"/mailcow/{mc.id}", f"/mailcow/{mc.id}?tab=aliases",
                f"/mailcow/{mc.id}?tab=domains", f"/mailcow/{mc.id}?tab=mail", f"/mailcow/{mc.id}/edit", "/sso/",
                "/sso/new", f"/sso/{ak.id}", f"/sso/{ak.id}?tab=users", f"/sso/{ak.id}/edit"]:
        r = c.get(url)
        assert r.status_code == 200, (url, r.text[:400])
    # mailbox with generated password, shown once
    r = c.post(f"/mailcow/{mc.id}/do", data={"action": "mb_add", "local": "eva", "domain": "example.com",
                                             "name": "Eva", "quota": "1024", "csrf_token": c.csrf},
               follow_redirects=True)
    assert "Postfach eva@example.com angelegt" in r.text and "wird nur jetzt angezeigt" in r.text
    box = next(b for b in mock.state.mc_mailboxes if b["username"] == "eva@example.com")
    assert len(box["_password"]) == 16
    # SSO user + mailbox in one step
    r = c.post(f"/sso/{ak.id}/users", data={"action": "add", "username": "tom", "name": "Tom T",
               "email": "tom@example.com", "groups": "11111111-aaaa-bbbb-cccc-000000000001",
               "mailbox_mailcow": str(mc.id), "quota": "2048", "csrf_token": c.csrf}, follow_redirects=True)
    assert "Benutzer tom angelegt" in r.text and "Postfach tom@example.com" in r.text
    tom = next(u for u in mock.state.ak_users if u["username"] == "tom")
    assert tom["pk"] in mock.state.ak_passwords and tom["pk"] in mock.state.ak_groups[0]["users"]
    # Nextcloud users via occ (SSH faked)

    class DummyConn:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    monkeypatch.setattr(inventory, "connect", lambda system, timeout=None: DummyConn())
    seen = []

    def fake_occ(conn, system, task, env=None, timeout=180):
        seen.append((task, env))
        if task == "user_list":
            return '__USERS__\n{"anna": {"display_name": "Anna", "enabled": true, "groups": []}}\n__GROUPS__\n{"admin": []}'
        return "SM_OK"
    monkeypatch.setattr(nextcloud_users, "occ_task", fake_occ)
    r = c.get(f"/systems/{nc.id}/nextcloud/users")
    assert r.status_code == 200 and "anna" in r.text
    r = c.post(f"/systems/{nc.id}/nextcloud/users", data={"op": "add", "uid": "max", "display": "Max",
               "groups": "team", "quota": "5 GB", "csrf_token": c.csrf}, follow_redirects=True)
    assert "max: angelegt" in r.text and "wird nur jetzt angezeigt" in r.text
    task, env = next(x for x in reversed(seen) if x[0] == "user_add")
    assert env["SM_GROUPS"] == "team" and len(env["SM_NC_PASSWORD"]) == 16
    r = c.post(f"/systems/{nc.id}/nextcloud/users", data={"op": "add", "uid": "bad user", "csrf_token": c.csrf},
               follow_redirects=True)
    assert "Ungültige Benutzer-ID" in r.text
    # permissions: a viewer of the system cannot create users
    from servermanager.models import SystemAccess
    v = make_user(db, "apps-viewer", "user")
    db.add(SystemAccess(user_id=v.id, system_id=nc.id, level="view"))
    db.commit()
    vc = login(app, "apps-viewer")
    assert vc.get(f"/systems/{nc.id}/nextcloud/users").status_code == 200
    assert vc.post(f"/systems/{nc.id}/nextcloud/users", data={"op": "add", "uid": "x", "csrf_token": vc.csrf}
                   ).status_code == 403
    assert vc.get(f"/mailcow/{mc.id}").status_code == 403
    assert ncmod.QUOTA_RE.match("10 GB")


def test_mailcow_form_validation(app, db, apps):
    from tests.test_web import login, make_user
    make_user(db, "apps-admin", "admin")
    c = login(app, "apps-admin")
    mc = apps["mc"]
    r = c.post(f"/mailcow/{mc.id}/edit", data={"name": "mc", "api_url": mc.api_url, "fingerprint": mc.fingerprint,
               "public_url": "https://mail.example.com", "mail_hostname": "mail.example.com",
               "mail_public_ip": "5.9.10.11", "mail_ports": "25,993", "csrf_token": c.csrf}, follow_redirects=True)
    assert "brauchen verschiedene Namen" in r.text
    r = c.post(f"/mailcow/{mc.id}/edit", data={"name": "mc", "api_url": mc.api_url, "fingerprint": mc.fingerprint,
               "public_url": "https://webmail.example.com", "mail_hostname": "mail.example.com",
               "mail_public_ip": "999.1.1.1", "mail_ports": "25;993", "csrf_token": c.csrf}, follow_redirects=True)
    assert "Mail-IP: ungültige IP-Adresse" in r.text and "Ports als Liste" in r.text
