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


def test_sso_connect_pangolin_and_rollback(db, mock, apps):
    from servermanager.jobs import enqueue, log_path
    from servermanager.models import Job, SsoClient
    from servermanager.pangolin import dashboard_guess
    assert dashboard_guess("https://api.pangolin.example.com/v1") == "https://pangolin.example.com"
    assert dashboard_guess("https://pangolin.example.com:3003/v1") == "https://pangolin.example.com"
    assert dashboard_guess("https://10.0.0.5:3003/v1") == ""
    pg, st = apps["pg"], mock.state

    def run():
        job = enqueue(db, kind="sso_connect", title="sso", payload={"sso_id": apps["ak"].id, "kind": "pangolin",
                                                                    "target_id": pg.id,
                                                                    "app_url": "https://pangolin.example.com"})
        db.commit()
        _run(job.id)
        db.expire_all()
        return db.get(Job, job.id), log_path(job.id).read_text()
    job, log = run()
    assert job.status == "success", log
    client = db.query(SsoClient).filter_by(target_kind="pangolin", target_id=pg.id).one()
    idp = st.pg_idps[int(client.target_ref)]
    prov = st.ak_providers[client.provider_pk]
    callback = f"https://pangolin.example.com/auth/idp/{client.target_ref}/oidc/callback"
    assert prov["redirect_uris"] == [{"matching_mode": "strict", "url": callback}]
    assert idp["clientId"] == prov["client_id"] and idp["clientSecret"] == prov["client_secret"]
    assert idp["authUrl"] == "https://auth.example.com/application/o/authorize/" and idp["autoProvision"] is True
    assert st.pg_idp_policies[(int(client.target_ref), m.PG_ORG)]["roleMapping"] == "'Member'"
    # disconnect removes both sides
    slug, cid, iid = client.slug, client.id, int(client.target_ref)
    job = enqueue(db, kind="sso_disconnect", title="off", payload={"client_id": cid})
    db.commit()
    _run(job.id)
    db.expire_all()
    assert db.get(Job, job.id).status == "success"
    assert iid not in st.pg_idps and slug not in st.ak_apps and not db.query(SsoClient).filter_by(id=cid).first()
    # an organization key cannot manage identity providers: clear message, nothing left behind
    st.pg_idp_forbidden = True
    apps_before = set(st.ak_apps)
    try:
        job, log = run()
    finally:
        st.pg_idp_forbidden = False
    assert job.status == "failed" and "Server-Admin" in log and set(st.ak_apps) == apps_before
    # failure in authentik removes the Pangolin IdP again
    st.ak_apps[f"sm-pangolin-{pg.id}"] = {"slug": f"sm-pangolin-{pg.id}", "name": "x"}
    idps_before = set(st.pg_idps)
    try:
        job, log = run()
    finally:
        st.ak_apps.pop(f"sm-pangolin-{pg.id}", None)
    assert job.status == "failed" and set(st.pg_idps) == idps_before
    assert not db.query(SsoClient).filter_by(target_kind="pangolin").first()


def test_sso_connect_pangolin_needs_full_access(app, db, apps):
    from servermanager.models import LEVEL_FULL, LEVEL_VIEW, IntegrationAccess
    from tests.test_web import login, make_user
    u = make_user(db, "pg-sso-user")
    db.add(IntegrationAccess(user_id=u.id, kind="sso", obj_id=apps["ak"].id, level=LEVEL_FULL))
    db.add(IntegrationAccess(user_id=u.id, kind="pangolin", obj_id=apps["pg"].id, level=LEVEL_VIEW))
    db.commit()
    c = login(app, "pg-sso-user")
    r = c.post(f"/sso/{apps['ak'].id}/connect", data={"kind": "pangolin", "target_id": apps["pg"].id,
                                                       "app_url": "https://pangolin.example.com", "csrf_token": c.csrf})
    assert r.status_code == 403
    page = c.get(f"/sso/{apps['ak'].id}").text
    assert "Keine (weitere) Pangolin-Verbindung" in page


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
    mc, pg = apps["mc"], apps["pg"]
    same = {"name": "mc", "api_url": mc.api_url, "fingerprint": mc.fingerprint,
            "public_url": "https://mail.example.com", "mail_hostname": "mail.example.com",
            "mail_public_ip": "5.9.10.11", "mail_ports": "25,993"}
    # web interface and mail server under one name on the own IP (not via Pangolin): allowed
    r = c.post(f"/mailcow/{mc.id}/edit", data={**same, "csrf_token": c.csrf}, follow_redirects=True)
    assert "eigenen Namen" not in r.text and "Gespeichert" in r.text
    db.expire_all()
    assert db.get(type(mc), mc.id).public_url == "https://mail.example.com"
    # the same name published via Pangolin points to Pangolin: refused
    pg.cache = {**(pg.cache or {}), "published": ["mail.example.com"]}
    db.commit()
    r = c.post(f"/mailcow/{mc.id}/edit", data={**same, "csrf_token": c.csrf}, follow_redirects=True)
    assert "über Pangolin (pg-apps) veröffentlicht" in r.text
    pg.cache = {**pg.cache, "published": []}
    db.commit()
    # the optimizer never proposes to publish it under the mail name (that would cut off SMTP/IMAP)
    from servermanager import optimize
    ids = {p["id"]: p for p in optimize.scan(db)["proposals"]}
    prop = ids[f"app:mailcow:{mc.id}:publish"]
    assert prop["action"] is None and prop["severity"] == "info" and "eigenen Namen" in prop["detail"]
    mc = db.get(type(mc), mc.id)
    mc.public_url = "https://webmail.example.com"
    db.commit()
    r = c.post(f"/mailcow/{mc.id}/edit", data={"name": "mc", "api_url": mc.api_url, "fingerprint": mc.fingerprint,
               "public_url": "https://webmail.example.com", "mail_hostname": "mail.example.com",
               "mail_public_ip": "999.1.1.1", "mail_ports": "25;993", "csrf_token": c.csrf}, follow_redirects=True)
    assert "Mail-IP: ungültige IP-Adresse" in r.text and "Ports als Liste" in r.text


# -------------------------------------------------------------------- login to the servermanager via SSO
def _sso_round(c, st, user, nonce=None, aud=None):
    from urllib.parse import parse_qs, urlsplit
    r = c.get("/login/sso?next=/systems")
    assert r.status_code == 302, r.text[:300]
    loc = urlsplit(r.headers["Location"])
    q = {k: v[0] for k, v in parse_qs(loc.query).items()}
    assert f"{loc.scheme}://{loc.netloc}{loc.path}" == "https://auth.example.com/application/o/authorize/"
    assert q["code_challenge_method"] == "S256" and q["scope"] == "openid profile email"
    code = f"code-{len(st.ak_codes)}-{q['state'][:6]}"
    st.ak_codes[code] = {"user": user, "challenge": q["code_challenge"], "nonce": nonce or q["nonce"],
                         "client_id": q["client_id"], "redirect": q["redirect_uri"],
                         **({"aud": aud} if aud else {})}
    return c.get(f"/login/sso/callback?code={code}&state={q['state']}"), q


def test_servermanager_login_via_sso(app, db, mock, apps):
    from servermanager import security, settings
    from servermanager.models import Job, SsoClient, User
    from tests.test_integrations import _run as run_job
    from tests.test_web import login, make_user
    st = mock.state
    make_user(db, "sso-admin", "admin")
    admin = login(app, "sso-admin")
    # only administrators set it up
    make_user(db, "sso-plain")
    plain = login(app, "sso-plain")
    assert plain.post(f"/sso/{apps['ak'].id}/connect", data={"kind": "servermanager", "target_id": 0,
                                                              "csrf_token": plain.csrf}).status_code == 403
    r = admin.post(f"/sso/{apps['ak'].id}/connect", data={
        "kind": "servermanager", "target_id": 0, "app_url": "https://sm.example.com", "sso_auto_create": "1",
        "sso_group": "", "csrf_token": admin.csrf})
    assert r.status_code == 302
    job_id = int(r.headers["Location"].rstrip("/").split("/")[-1])
    run_job(job_id)
    db.expire_all()
    assert db.get(Job, job_id).status == "success"
    client = db.query(SsoClient).filter_by(target_kind="servermanager").one()
    prov = st.ak_providers[client.provider_pk]
    assert prov["redirect_uris"] == [{"matching_mode": "strict", "url": "https://sm.example.com/login/sso/callback"}]
    assert security.decrypt(client.secret_enc) == prov["client_secret"] and prov["client_secret"] not in client.secret_enc
    try:
        c = app.test_client()
        assert "Mit auth anmelden" in c.get("/login").text
        # new user is created (no rights) and logged in
        r, q = _sso_round(c, st, {"sub": "h-anna", "username": "sso-anna", "name": "Anna", "email": "a@x.de"})
        assert r.status_code == 302 and r.headers["Location"].endswith("/systems"), r.headers.get("Location")
        anna = db.query(User).filter_by(username="sso-anna").one()
        assert anna.role == "user" and anna.display_name == "Anna" and not anna.access
        assert c.get("/").status_code == 200
        # the same state cannot be used twice
        c2 = app.test_client()
        r = c2.get(f"/login/sso/callback?code=x&state={q['state']}")
        assert r.status_code == 302 and c2.get("/").status_code == 302
        # wrong nonce / audience are rejected
        for kw in ({"nonce": "other"}, {"aud": "someone-else"}):
            c3 = app.test_client()
            r, _ = _sso_round(c3, st, {"sub": "h-anna", "username": "sso-anna"}, **kw)
            assert c3.get("/").status_code == 302
        # unknown users without automatic creation
        settings.set(db, "login.sso_auto_create", False)
        db.commit()
        c4 = app.test_client()
        r, _ = _sso_round(c4, st, {"sub": "h-ben", "username": "sso-ben"})
        assert "kein Konto" in c4.get("/login").text and not db.query(User).filter_by(username="sso-ben").first()
        # group restriction
        settings.set(db, "login.sso_group", "servermanager")
        db.commit()
        c5 = app.test_client()
        _sso_round(c5, st, {"sub": "h-anna", "username": "sso-anna", "groups": ["other"]})
        assert "Gruppe" in c5.get("/login").text
        c5 = app.test_client()
        _sso_round(c5, st, {"sub": "h-anna", "username": "sso-anna", "groups": ["servermanager"]})
        assert c5.get("/").status_code == 200
        # administrators only when allowed
        c6 = app.test_client()
        _sso_round(c6, st, {"sub": "h-adm", "username": "sso-admin", "groups": ["servermanager"]})
        assert "Administratoren" in c6.get("/login").text
        settings.set(db, "login.sso_admins", True)
        db.commit()
        c6 = app.test_client()
        _sso_round(c6, st, {"sub": "h-adm", "username": "sso-admin", "groups": ["servermanager"]})
        assert c6.get("/").status_code == 200
        # a local second factor is still asked for
        import pyotp
        anna.totp_secret_enc, anna.totp_enabled = security.encrypt(pyotp.random_base32()), True
        db.commit()
        c7 = app.test_client()
        r, _ = _sso_round(c7, st, {"sub": "h-anna", "username": "sso-anna", "groups": ["servermanager"]})
        assert r.headers["Location"].endswith("/login/2fa") and c7.get("/").status_code == 302
        # options are saved by administrators
        r = admin.post(f"/sso/{apps['ak'].id}/login-options", data={"sso_group": "", "csrf_token": admin.csrf})
        assert r.status_code == 302 and settings.get(db, "login.sso_admins") is False
        # disconnect: only administrators, then the button is gone
        assert plain.post(f"/sso/{apps['ak'].id}/disconnect/{client.id}",
                          data={"csrf_token": plain.csrf}).status_code == 403
        r = admin.post(f"/sso/{apps['ak'].id}/disconnect/{client.id}", data={"csrf_token": admin.csrf})
        run_job(int(r.headers["Location"].rstrip("/").split("/")[-1]))
        db.expire_all()
        assert not db.query(SsoClient).filter_by(target_kind="servermanager").first()
        assert "Mit auth anmelden" not in app.test_client().get("/login").text
    finally:
        from servermanager.web import auth as web_auth
        web_auth._failures.clear()  # the rejected attempts above count towards the IP throttle
        for k in ("login.sso_auto_create", "login.sso_group", "login.sso_admins"):
            settings.set(db, k, settings.DEFAULTS[k])
        for name in ("sso-anna", "sso-admin", "sso-plain"):
            u = db.query(User).filter_by(username=name).first()
            if u:
                db.delete(u)
        db.commit()


@pytest.fixture()
def pve_srv(db, mock):
    from servermanager.models import PveServer
    srv = PveServer(name="pve-sso", api_url=mock.url, token_id=m.PVE_TOKEN, token_secret_enc=security.encrypt(m.PVE_SECRET),
                    fingerprint=mock.fingerprint)
    db.add(srv)
    db.commit()
    yield srv
    db.delete(srv)
    db.commit()


def test_sso_connect_proxmox(db, mock, apps, pve_srv):
    from servermanager import sso
    from servermanager.jobs import enqueue, log_path
    from servermanager.models import Job, SsoClient
    st = mock.state

    def run(options=None):
        job = enqueue(db, kind="sso_connect", title="sso", payload={
            "sso_id": apps["ak"].id, "kind": "pve", "target_id": pve_srv.id, "app_url": "https://pve.example.com:8006",
            "options": options or {}})
        db.commit()
        _run(job.id)
        db.expire_all()
        return db.get(Job, job.id), log_path(job.id).read_text()
    job, log = run({"groups": True, "default": True})
    assert job.status == "success", log
    realm = sso.pve_realm(apps["ak"])
    assert realm == "auth"
    d = st.pve_domains[realm]
    client = db.query(SsoClient).filter_by(target_kind="pve", target_id=pve_srv.id).one()
    prov = st.ak_providers[client.provider_pk]
    assert d["type"] == "openid" and d["client-id"] == prov["client_id"] and d["client-key"] == prov["client_secret"]
    # exactly authentik's issuer incl. trailing slash (Proxmox compares it with the discovery document)
    assert d["issuer-url"] == f"https://auth.example.com/application/o/{client.slug}/"
    assert d["username-claim"] == "username" and d["autocreate"] == "1" and d["groups-claim"] == "groups"
    assert d["default"] == "1" and client.target_ref == realm
    assert {"matching_mode": "strict", "url": "https://pve.example.com:8006"} in prov["redirect_uris"]
    # disconnect removes realm and application
    slug, cid = client.slug, client.id
    job = enqueue(db, kind="sso_disconnect", title="off", payload={"client_id": cid})
    db.commit()
    _run(job.id)
    db.expire_all()
    assert db.get(Job, job.id).status == "success"
    assert realm not in st.pve_domains and slug not in st.ak_apps
    # Proxmox before 8.1: realm without groups claim
    st.pve_old = True
    try:
        job, log = run({"groups": True})
        assert job.status == "success" and "groups-claim" not in st.pve_domains[realm], log
        assert "ab PVE 8.1" in log
    finally:
        st.pve_old = False
    c2 = db.query(SsoClient).filter_by(target_kind="pve").one()
    db.delete(c2)
    st.ak_apps.pop(c2.slug, None)
    st.pve_domains.pop(realm, None)
    db.commit()
    # token without Realm.Allocate: clear message, authentik app removed again
    st.pve_no_realm_perm = True
    apps_before = set(st.ak_apps)
    try:
        job, log = run()
    finally:
        st.pve_no_realm_perm = False
    assert job.status == "failed" and "Realm.Allocate" in log and set(st.ak_apps) == apps_before
    # a realm of another type with the same name is never touched
    st.pve_domains[realm] = {"realm": realm, "type": "ldap"}
    try:
        job, log = run()
        assert job.status == "failed" and "anderen Typs" in log and st.pve_domains[realm]["type"] == "ldap"
    finally:
        st.pve_domains.pop(realm, None)
    assert not db.query(SsoClient).filter_by(target_kind="pve").first()


def test_sso_proxmox_needs_full_access(app, db, apps, pve_srv):
    from servermanager.models import LEVEL_FULL, LEVEL_OPERATE, IntegrationAccess
    from tests.test_web import login, make_user
    u = make_user(db, "pve-sso-user")
    db.add(IntegrationAccess(user_id=u.id, kind="sso", obj_id=apps["ak"].id, level=LEVEL_FULL))
    db.add(IntegrationAccess(user_id=u.id, kind="pve", obj_id=pve_srv.id, level=LEVEL_OPERATE))
    db.commit()
    c = login(app, "pve-sso-user")
    r = c.post(f"/sso/{apps['ak'].id}/connect", data={"kind": "pve", "target_id": pve_srv.id,
                                                       "app_url": "https://pve.example.com:8006", "csrf_token": c.csrf})
    assert r.status_code == 403
    assert "Keine (weitere) Proxmox-Verbindung" in c.get(f"/sso/{apps['ak'].id}").text
    make_user(db, "pve-sso-admin", "admin")
    page = login(app, "pve-sso-admin").get(f"/sso/{apps['ak'].id}").text
    assert "Proxmox VE verbinden" in page and "Realm.Allocate" in page and "pve-sso" in page


def test_pangolin_poll_remembers_published_domains(db, mock, apps):
    from servermanager import integrations
    pg = apps["pg"]
    client = integrations.pangolin_client(pg)
    client.publish("Webmail", "http", 1, "10.20.0.30", 443, "https", "webmail", "dom1")
    integrations.poll(db, pg)
    db.commit()
    assert "webmail.example.com" in pg.cache["published"]
    assert integrations.published_via_pangolin(db, "WEBMAIL.example.com") == "pg-apps"  # DNS ignores case
    assert integrations.published_via_pangolin(db, "webmail.example.com") == "pg-apps"
    assert integrations.published_via_pangolin(db, "mail.example.com") is None
