"""Link existing accounts: authentik <-> Nextcloud <-> Mailcow."""
import re

import pytest

from servermanager import account_link as al
from servermanager import security
from tests import mock_apis as m
from tests.test_web import login, make_user


def test_plan_matching_and_rights():
    ak_users = [{"pk": 1, "username": "akadmin", "email": "", "is_superuser": True},
                {"pk": 2, "username": "Anna", "name": "Anna", "email": "anna@example.com"},
                {"pk": 3, "username": "bm", "name": "Bernd", "email": "bernd@example.com"}]
    ak_groups = [{"pk": "g1", "name": "mitarbeiter", "users": [2]}, {"pk": "g2", "name": "Buchhaltung", "users": []},
                 {"pk": "gs", "name": "admins", "is_superuser": True, "users": [1]}]
    nc = [{"uid": "anna", "display": "Anna", "email": "anna@example.com", "enabled": True,
           "groups": ["Mitarbeiter", "Buchhaltung"]},
          {"uid": "bernd", "display": "Bernd", "email": "bernd@example.com", "enabled": True, "groups": ["Mitarbeiter"]},
          {"uid": "carl", "display": "Carl", "email": "carl@example.com", "enabled": True, "groups": []},
          {"uid": "ncadmin", "display": "Admin", "email": "admin@example.com", "enabled": True, "groups": ["admin"]}]
    mbs = [{"username": "anna@example.com", "authsource": "mailcow"},
           {"username": "carl@example.com", "authsource": "generic-oidc"},
           {"username": "info@example.com", "active": 1}]
    p = al.plan(ak_users, ak_groups, nc, mbs, "generic-oidc", is_admin=False)
    rows = {r["key"]: r for r in p["rows"]}
    anna = rows["ak:2"]
    assert anna["nc"]["uid"] == "anna" and anna["mb_how"] == "ak_email"   # user name matched without case
    assert anna["fixes"] == ["groups", "authsource"] and anna["groups_missing"] == ["Buchhaltung"]
    bernd = rows["ak:3"]   # only the e-mail matches: renaming is for administrators
    assert bernd["nc_how"] == "email" and "rename" not in bernd["fixes"] and "Administratoren" in bernd["notes"][0]
    carl = rows["nc:carl"]   # mailbox found through the Nextcloud address, already on authentik
    assert carl["fixes"] == ["create"] and carl["mb"]["username"] == "carl@example.com"
    assert rows["nc:ncadmin"]["fixes"] == [] and rows["nc:ncadmin"]["protected"]
    assert rows["ak:1"]["fixes"] == []
    assert rows["mb:info@example.com"]["fixes"] == ["create", "authsource"]
    # without an identity provider in the Mailcow nothing is switched
    assert al.plan(ak_users, ak_groups, nc, mbs, "")["counts"]["authsource"] == 0
    p = al.plan(ak_users, ak_groups, nc, mbs, "generic-oidc", is_admin=True)
    rows = {r["key"]: r for r in p["rows"]}
    assert "rename" in rows["ak:3"]["fixes"] and rows["nc:ncadmin"]["fixes"] == ["create", "groups"]


def test_group_whitelist():
    rx = al.group_whitelist_regex(["Vertrieb Nord", "a/b", "Buchhaltung"])
    assert rx.startswith("/^(") and rx.endswith(")$/") and "\\/" in rx
    py = re.compile(rx[1:-1].replace("\\/", "/"))
    assert py.match("Vertrieb Nord") and py.match("a/b") and not py.match("Vertrieb Nord2") and not py.match("x")
    assert al.group_whitelist_regex([]) == ""
    ak = [{"name": "mitarbeiter"}, {"name": "Buchhaltung"}, {"name": "admin"}, {"name": "Root", "is_superuser": True}]
    assert al.syncable_groups(["Mitarbeiter", "Buchhaltung", "admin", "Root"], ak) == ["Buchhaltung"]
    assert al.syncable_groups(["Mitarbeiter", "Buchhaltung", "admin"], ak, include_admin=True) == ["admin", "Buchhaltung"]


@pytest.fixture(scope="module")
def mock():
    srv = m.MockServer().start()
    yield srv
    srv.stop()


@pytest.fixture()
def env(db, mock):
    from servermanager.models import MailcowServer, NextcloudServer, SsoServer, System
    st = mock.state
    sysrow = System(name="cloud-link", host="10.20.0.41", types=["debian", "nextcloud"])
    db.add(sysrow)
    db.flush()
    n = NextcloudServer(name="cloud-link", api_url=mock.url, username=m.NC_USER,
                        password_enc=security.encrypt(m.NC_PASS), fingerprint=mock.fingerprint, system_id=sysrow.id)
    mc = MailcowServer(name="mc-link", api_url=f"https://127.0.0.1:{mock.port}", api_key_enc=security.encrypt(m.MC_KEY),
                       fingerprint=mock.fingerprint)
    ak = SsoServer(name="auth", api_url=mock.url, public_url="https://auth.example.com",
                   token_enc=security.encrypt(m.AK_TOKEN), fingerprint=mock.fingerprint)
    db.add_all([n, mc, ak])
    db.commit()
    saved = (list(st.ak_users), [dict(x, users=list(x["users"])) for x in st.ak_groups],
             [dict(x) for x in st.mc_mailboxes], dict(st.mc_idp))
    st.mc_idp = {"authsource": "generic-oidc"}
    st.mc_mailboxes.append({"username": "anna@example.com", "name": "Anna", "domain": "example.com",
                            "local_part": "anna", "active": 1, "quota": 0, "quota_used": 0, "authsource": "mailcow"})
    yield {"nc": n, "mc": mc, "ak": ak, "system": sysrow}
    st.ak_users[:], st.ak_groups[:], st.mc_mailboxes[:] = saved[0], saved[1], saved[2]
    st.mc_idp = saved[3]
    from servermanager.models import SsoClient
    db.query(SsoClient).filter_by(sso_id=ak.id).delete()
    for x in (n, mc, ak, sysrow):
        db.delete(x)
    db.commit()


def test_link_page_and_apply(app, db, mock, env, monkeypatch):
    st = mock.state
    ak, n, mc = env["ak"], env["nc"], env["mc"]
    make_user(db, "link-admin", "admin")
    c = login(app, "link-admin")
    assert f"/sso/{ak.id}/link" in c.get(f"/sso/{ak.id}?tab=users").text
    assert c.get(f"/sso/{ak.id}/link").status_code == 200
    url = f"/sso/{ak.id}/link?nc=api:{n.id}&mc={mc.id}"
    page = c.get(url).text
    assert 'name="rows" value="nc:anna" checked' in page and 'name="rows" value="mb:info@example.com" checked' in page
    assert "App-Passwort" in page and "Postfach auf authentik umstellen (2)" in page
    r = c.post(f"/sso/{ak.id}/link", data={"nc": f"api:{n.id}", "mc": str(mc.id), "rows": ["nc:anna", "mb:info@example.com"],
                                           "fixes": ["create", "groups", "authsource"], "csrf_token": c.csrf})
    assert "authentik-Benutzer anlegen: 2" in r.text and "Postfach auf authentik umstellen: 2" in r.text, r.text[-3000:]
    assert "Startpasswörter" in r.text and "neue Gruppen: Buchhaltung" in r.text
    users = {u["username"]: u for u in st.ak_users}
    assert users["anna"]["email"] == "anna@example.com" and users["info@example.com"]["email"] == "info@example.com"
    grp = {x["name"]: set(x["users"]) for x in st.ak_groups}
    assert grp["mitarbeiter"] == {users["anna"]["pk"]} and grp["Buchhaltung"] == {users["anna"]["pk"]}
    assert {x["username"]: x["authsource"] for x in st.mc_mailboxes} == {"info@example.com": "generic-oidc",
                                                                          "anna@example.com": "generic-oidc"}
    assert 'name="rows" value="ak:%d"' % users["anna"]["pk"] in r.text and "verknüpft" in r.text
    # only the e-mail matches: an administrator aligns the user name with the Nextcloud ID
    st.ak_seq += 1
    st.ak_users.append({"pk": st.ak_seq, "username": "carl", "name": "Carl", "email": "carl@example.com",
                        "is_active": True, "is_superuser": False, "type": "internal", "groups_obj": []})
    r = c.post(f"/sso/{ak.id}/link", data={"nc": f"api:{n.id}", "rows": [f"ak:{st.ak_seq}"], "fixes": ["rename"],
                                           "csrf_token": c.csrf})
    assert "authentik-Benutzername = Nextcloud-ID: 1" in r.text and st.ak_users[-1]["username"] == "carl.old"

    # group sync at login: needs the Nextcloud connected through this SSO and occ over SSH
    from servermanager import inventory
    from servermanager.models import SsoClient
    from servermanager.modules import nextcloud as ncmod
    db.add(SsoClient(sso_id=ak.id, target_kind="nextcloud", target_id=env["system"].id, slug="sm-nc-link",
                     status="active"))
    db.commit()
    calls = []

    class DummyConn:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    monkeypatch.setattr(inventory, "connect", lambda system, timeout=None: DummyConn())
    monkeypatch.setattr(ncmod, "occ_task", lambda conn, system, task, env=None, timeout=180:
                        calls.append((task, dict(env or {}))) or "SM_OK")
    page = c.get(f"/sso/{ak.id}/link?nc=api:{n.id}").text
    assert "Nextcloud-Gruppen bei der Anmeldung abgleichen" in page and 'name="groups" value="Buchhaltung"' in page
    assert "abweichend, daher nicht wählbar: Mitarbeiter" in page
    r = c.post(f"/sso/{ak.id}/link/nc-groups", data={"nc": f"api:{n.id}", "action": "on",
                                                     "groups": ["Buchhaltung", "Mitarbeiter", "x"],
                                                     "csrf_token": c.csrf}, follow_redirects=True)
    assert "Gruppen-Abgleich eingeschaltet (1 Gruppe(n))" in r.text
    task, e = calls[-1]
    assert task == "oidc_groups" and e["SM_GROUP_PROVISIONING"] == "1" and e["SM_GROUP_REGEX"] == "/^(Buchhaltung)$/"
    assert e["SM_OIDC_ID"] == "auth"
    r = c.post(f"/sso/{ak.id}/link/nc-groups", data={"nc": f"api:{n.id}", "action": "off", "csrf_token": c.csrf},
               follow_redirects=True)
    assert "ausgeschaltet" in r.text and calls[-1][1]["SM_GROUP_PROVISIONING"] == "0"


def test_link_rights(app, db, mock, env):
    from servermanager.models import KIND_MAILCOW, KIND_NEXTCLOUD, KIND_SSO, LEVEL_FULL, LEVEL_VIEW, IntegrationAccess
    ak, n, mc = env["ak"], env["nc"], env["mc"]
    u = make_user(db, "link-op")
    db.add_all([IntegrationAccess(user_id=u.id, kind=KIND_SSO, obj_id=ak.id, level=LEVEL_FULL),
                IntegrationAccess(user_id=u.id, kind=KIND_NEXTCLOUD, obj_id=n.id, level=LEVEL_VIEW),
                IntegrationAccess(user_id=u.id, kind=KIND_MAILCOW, obj_id=mc.id, level=LEVEL_VIEW)])
    db.commit()
    try:
        c = login(app, "link-op")
        page = c.get(f"/sso/{ak.id}/link?nc=api:{n.id}&mc={mc.id}").text
        assert "verknüpfen nur Administratoren" in page and 'name="rows" value="nc:ncadmin" checked' not in page
        assert 'value="rename"' not in page and "braucht Vollzugriff auf die Mailcow" in page
        r = c.post(f"/sso/{ak.id}/link", data={"nc": f"api:{n.id}", "mc": str(mc.id), "rows": ["nc:anna"],
                                               "fixes": ["authsource"], "csrf_token": c.csrf})
        assert "Vollzugriff auf die Mailcow" in r.text
        assert mock.state.mc_mailboxes[-1]["authsource"] == "mailcow"
        # a protected row stays untouched even if posted
        r = c.post(f"/sso/{ak.id}/link", data={"nc": f"api:{n.id}", "rows": ["nc:ncadmin"], "fixes": ["create"],
                                               "csrf_token": c.csrf})
        assert "Nichts geändert" in r.text and "ncadmin" not in {x["username"] for x in mock.state.ak_users}
        assert c.get(f"/sso/{ak.id}/link?mc=999999").status_code == 404
    finally:
        db.query(IntegrationAccess).filter_by(user_id=u.id).delete()
        db.commit()
