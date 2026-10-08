"""Nextcloud via the OCS API: client, polling, users and groups, rights."""
import pytest

from servermanager import integrations, security
from servermanager.nextcloud_api import Nextcloud, NextcloudError, normalize_url, quota_info, quota_text, summary
from tests import mock_apis as m
from tests.test_web import login, make_user


@pytest.fixture(scope="module")
def mock():
    srv = m.MockServer().start()
    yield srv
    srv.stop()


def client(mock, pw=m.NC_PASS):
    return Nextcloud(mock.url, m.NC_USER, pw, fingerprint=mock.fingerprint)


@pytest.fixture()
def ncs(db, mock):
    from servermanager.models import NextcloudServer
    n = NextcloudServer(name="cloud", api_url=mock.url, username=m.NC_USER, password_enc=security.encrypt(m.NC_PASS),
                        fingerprint=mock.fingerprint, monitor=True)
    db.add(n)
    db.commit()
    yield n
    db.delete(n)
    db.commit()


def test_url_and_helpers():
    assert normalize_url("cloud.example.com/") == "https://cloud.example.com"
    assert normalize_url("https://example.com/nextcloud/index.php/apps/files") == "https://example.com/nextcloud"
    with pytest.raises(NextcloudError):
        normalize_url("https://user:pw@cloud.example.com")
    assert quota_text({"quota": {"quota": 10 * 1024 ** 3}}) == "10 GB"
    assert quota_text({"quota": {"quota": -3}}) == "none" and quota_text({"quota": {"quota": "default"}}) == "default"
    assert quota_info({"quota": {"used": 5, "quota": 10}})["pct"] == 50


def test_client(mock):
    nc = client(mock)
    assert [u["id"] for u in nc.users()] == ["anna", "bernd", "carl.old", "ncadmin"]
    assert {g["id"]: g["usercount"] for g in nc.groups()}["Mitarbeiter"] == 3
    info = summary(nc.serverinfo())
    assert info["version"] == "31.0.9.1" and info["core_update"] == "32.0.0" and info["app_updates"] == ["calendar"]
    with pytest.raises(NextcloudError, match="App-Passwort"):
        client(mock, "wrong").users()
    with pytest.raises(NextcloudError, match="Benutzer-ID"):
        nc.delete_user("../etc")
    with pytest.raises(NextcloudError, match="Quota"):
        nc.edit_user("anna", "quota", "viel")


def test_poll_alerts(app, db, ncs):
    integrations.poll(db, ncs)
    db.commit()
    assert ncs.status == "online", ncs.status_message
    assert ncs.data["version"] == "31.0.9.1" and ncs.data["users"] == 4 and ncs.data["disabled"] == 1
    assert [a["key"] for a in ncs.alerts] == ["quota:anna"]  # 9 of 10 GB
    make_user(db, "nc-admin", "admin")
    page = login(app, "nc-admin").get("/").text  # the dashboard links the warning to the connection
    assert "Speicher von anna zu 90 % belegt" in page and f"/nextcloud/{ncs.id}" in page


def test_pages_and_user_actions(app, db, mock, ncs):
    make_user(db, "nc-admin", "admin")
    c = login(app, "nc-admin")
    assert "Nextcloud" in c.get("/nextcloud/").text
    page = c.get(f"/nextcloud/{ncs.id}?tab=users").text
    assert "anna@example.com" in page and 'data-dialog-open="#ncu-edit"' in page and '"quota": "10 GB"' in page
    integrations.poll(db, ncs)
    db.commit()
    assert "Update verfügbar: 32.0.0" in c.get(f"/nextcloud/{ncs.id}").text
    assert "Vertrieb Nord" in c.get(f"/nextcloud/{ncs.id}?tab=groups").text
    r = c.post(f"/nextcloud/{ncs.id}/users", data={"action": "add", "uid": "dora", "display": "Dora",
                                                    "email": "dora@example.com", "groups": ["Vertrieb Nord"],
                                                    "quota": "5 GB", "csrf_token": c.csrf}, follow_redirects=True)
    assert "dora angelegt" in r.text and "wird nur jetzt angezeigt" in r.text
    assert mock.state.nc_users["dora"]["groups"] == ["Vertrieb Nord"]
    r = c.post(f"/nextcloud/{ncs.id}/users", data={"action": "edit", "uid": "dora", "display": "Dora B.",
                                                    "email": "dora@example.com", "quota": "5 GB",
                                                    "groups": ["Mitarbeiter"], "csrf_token": c.csrf},
               follow_redirects=True)
    assert "Anzeigename, Gruppen geändert" in r.text
    assert mock.state.nc_users["dora"]["groups"] == ["Mitarbeiter"]
    r = c.post(f"/nextcloud/{ncs.id}/users", data={"action": "disable", "uid": m.NC_USER, "csrf_token": c.csrf},
               follow_redirects=True)
    assert "Konto der Schnittstelle" in r.text and mock.state.nc_users[m.NC_USER]["enabled"]
    c.post(f"/nextcloud/{ncs.id}/users", data={"action": "delete", "uid": "dora", "csrf_token": c.csrf})
    assert "dora" not in mock.state.nc_users
    r = c.post(f"/nextcloud/{ncs.id}/groups", data={"gid": "Projekt X", "csrf_token": c.csrf}, follow_redirects=True)
    assert "Gruppe Projekt X angelegt" in r.text
    mock.state.nc_groups.remove("Projekt X")


def test_rights(app, db, mock, ncs):
    from servermanager.models import KIND_NEXTCLOUD, LEVEL_FULL, LEVEL_OPERATE, IntegrationAccess
    u = make_user(db, "nc-op")
    db.add(IntegrationAccess(user_id=u.id, kind=KIND_NEXTCLOUD, obj_id=ncs.id, level=LEVEL_OPERATE))
    db.commit()
    c = login(app, "nc-op")
    page = c.get(f"/nextcloud/{ncs.id}?tab=users").text
    assert "Sperren" in page and 'data-dialog-open="#ncu-edit"' not in page and "Neues Passwort" not in page
    assert c.post(f"/nextcloud/{ncs.id}/users", data={"action": "password", "uid": "anna",
                                                       "csrf_token": c.csrf}).status_code == 403
    c.post(f"/nextcloud/{ncs.id}/users", data={"action": "disable", "uid": "bernd", "csrf_token": c.csrf})
    assert mock.state.nc_users["bernd"]["enabled"] is False
    mock.state.nc_users["bernd"]["enabled"] = True
    # full access, but not admin of the servermanager: Nextcloud administrators and the admin group are off limits
    db.query(IntegrationAccess).filter_by(user_id=u.id).update({"level": LEVEL_FULL})
    db.commit()
    r = c.post(f"/nextcloud/{ncs.id}/users", data={"action": "password", "uid": "ncadmin", "csrf_token": c.csrf},
               follow_redirects=True)
    assert "Nextcloud-Administratoren" in r.text and "ncadmin" not in mock.state.nc_passwords
    r = c.post(f"/nextcloud/{ncs.id}/users", data={"action": "edit", "uid": "bernd", "display": "Bernd",
                                                    "groups": ["admin", "Mitarbeiter"], "csrf_token": c.csrf},
               follow_redirects=True)
    assert "Gruppe „admin“" in r.text and "admin" not in mock.state.nc_users["bernd"]["groups"]
    db.query(IntegrationAccess).filter_by(user_id=u.id).delete()
    db.commit()


def test_import_to_authentik(app, db, mock, ncs):
    from servermanager import nc_import
    from servermanager.models import KIND_NEXTCLOUD, KIND_SSO, LEVEL_FULL, LEVEL_VIEW, IntegrationAccess, SsoServer
    st = mock.state
    ak = SsoServer(name="auth", api_url=mock.url, public_url="https://auth.example.com",
                   token_enc=security.encrypt(m.AK_TOKEN), fingerprint=mock.fingerprint)
    db.add(ak)
    db.commit()
    users_before, groups_before = list(st.ak_users), list(st.ak_groups)
    try:
        assert nc_import.normalize_users([{"uid": "x", "display": "X", "groups": ["a"]}])[0]["display"] == "X"
        make_user(db, "nc-admin", "admin")
        c = login(app, "nc-admin")
        assert f"/sso/{ak.id}/import?source=api:{ncs.id}" in c.get(f"/nextcloud/{ncs.id}").text.replace("&amp;", "&")
        page = c.get(f"/sso/{ak.id}/import?source=api:{ncs.id}").text
        assert "Buchhaltung" in page and "Vertrieb Nord" in page and "wird angelegt" in page
        assert 'name="users" value="anna" checked' in page          # new and active
        assert 'name="users" value="carl.old" checked' not in page   # disabled in Nextcloud
        assert 'name="groups" value="admin" checked' not in page     # Nextcloud administrators: opt-in
        r = c.post(f"/sso/{ak.id}/import", data={
            "source": f"api:{ncs.id}", "groups": ["Buchhaltung", "Mitarbeiter", "Vertrieb Nord"],
            "users": ["anna", "bernd"], "passwords": "random", "existing_members": "1", "csrf_token": c.csrf})
        assert "2 Gruppe(n) und 2 Benutzer angelegt, 4 Mitgliedschaft(en)" in r.text, r.text[-3000:]
        assert "Startpasswörter" in r.text
        pk = {u["username"]: u["pk"] for u in st.ak_users}
        grp = {x["name"]: set(x["users"]) for x in st.ak_groups}
        assert grp["mitarbeiter"] == {pk["anna"], pk["bernd"]}   # existing group, matched without case
        assert grp["Buchhaltung"] == {pk["anna"]} and grp["Vertrieb Nord"] == {pk["bernd"]}
        assert pk["anna"] in st.ak_passwords and next(u for u in st.ak_users if u["username"] == "anna")["is_active"]
        # second run: nothing new
        r = c.post(f"/sso/{ak.id}/import", data={"source": f"api:{ncs.id}", "groups": ["Buchhaltung"],
                                                  "users": ["anna"], "passwords": "none", "existing_members": "1",
                                                  "csrf_token": c.csrf})
        assert "0 Gruppe(n) und 0 Benutzer angelegt, 0 Mitgliedschaft(en)" in r.text
        # not an administrator of the servermanager: Nextcloud admins are off limits
        u = make_user(db, "nc-importer")
        db.add_all([IntegrationAccess(user_id=u.id, kind=KIND_SSO, obj_id=ak.id, level=LEVEL_FULL),
                    IntegrationAccess(user_id=u.id, kind=KIND_NEXTCLOUD, obj_id=ncs.id, level=LEVEL_VIEW)])
        db.commit()
        c2 = login(app, "nc-importer")
        r = c2.post(f"/sso/{ak.id}/import", data={"source": f"api:{ncs.id}", "users": ["ncadmin"],
                                                   "passwords": "random", "csrf_token": c2.csrf})
        assert "Nextcloud-Administratoren" in r.text and "ncadmin" not in {x["username"] for x in st.ak_users}
        assert c2.get(f"/sso/{ak.id}/import?source=ssh:999999").status_code == 404
        db.query(IntegrationAccess).filter_by(user_id=u.id).delete()
        db.commit()
    finally:
        st.ak_users[:] = users_before
        for x in groups_before:
            x["users"] = []
        st.ak_groups[:] = groups_before
        db.delete(ak)
        db.commit()
