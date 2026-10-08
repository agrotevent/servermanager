"""CloudPanel: clpctl over SSH, lists from CloudPanel's database, rights, authentik users."""
import json
import os
import sqlite3
import subprocess
from pathlib import Path

import pytest

from servermanager import security
from servermanager.modules.cloudpanel import parse_status, site_env, user_env
from tests import mock_apis as m
from tests.test_web import login, make_user

ROOT = Path(__file__).resolve().parent.parent
DUMP = {"site": [{"id": 1, "domain_name": "shop.example.com", "type": "php", "user": "shop", "root_directory":
                  "/home/shop/htdocs/shop.example.com", "php_settings_id": 4},
                 {"id": 2, "domain_name": "app.example.com", "type": "reverse-proxy", "user": "app"}],
        "php_settings": [{"id": 4, "php_version": "8.3"}],
        "database": [{"id": 9, "site_id": 1, "name": "shopdb"}],
        "database_user": [{"database_id": 9, "user_name": "shopuser"}],
        "user": [{"id": 1, "user_name": "admin", "email": "admin@example.com", "role": "admin", "status": 1},
                 {"id": 2, "user_name": "anna", "email": "anna@example.com", "first_name": "Anna", "role": "user",
                  "status": 1}]}
STATUS = ("version=2.5.1\n__CLP__" + json.dumps(DUMP) + "\n"
          "cert=shop.example.com|Dec 31 23:59:59 2030 GMT|Let's Encrypt\n")


def test_parse_and_validate():
    d = parse_status(STATUS)
    assert d["version"] == "2.5.1" and d["full"]
    shop = d["sites"][1]
    assert shop["domain"] == "shop.example.com" and shop["php"] == "8.3" and shop["cert"]["until"].year == 2030
    assert d["databases"] == [{"name": "shopdb", "site": "shop.example.com", "users": ["shopuser"]}]
    assert [u["name"] for u in d["users"]] == ["admin", "anna"]
    assert parse_status("version=2\nsite=a.example.com\n")["sites"][0]["domain"] == "a.example.com"
    env = site_env({"type": "php", "domain": "WWW.Example.com", "site_user": "example", "php": "8.3"})
    assert env == {"SM_TYPE": "php", "SM_DOMAIN": "www.example.com", "SM_SITE_USER": "example", "SM_PHP": "8.3",
                   "SM_VHOST": "Generic"}
    for bad in ({"type": "php", "domain": "x", "site_user": "example", "php": "8.3"},
                {"type": "php", "domain": "a.example.com", "site_user": "Bad User", "php": "8.3"},
                {"type": "php", "domain": "a.example.com", "site_user": "abc", "php": "5.6"},
                {"type": "reverse-proxy", "domain": "a.example.com", "site_user": "abc", "proxy_url": "file:///x"},
                {"type": "nodejs", "domain": "a.example.com", "site_user": "abc", "runtime": "20", "app_port": "80"},
                {"type": "exe", "domain": "a.example.com", "site_user": "abc"}):
        with pytest.raises(ValueError):
            site_env(bad)
    assert site_env({"type": "reverse-proxy", "domain": "a.example.com", "site_user": "abc",
                     "proxy_url": "http://127.0.0.1:8000"})["SM_PROXY_URL"] == "http://127.0.0.1:8000"
    with pytest.raises(ValueError, match="Administratoren"):
        user_env({"user": "max", "email": "max@example.com", "role": "admin"}, [], allow_admin=False)
    with pytest.raises(ValueError, match="Site"):
        user_env({"user": "max", "email": "max@example.com", "role": "user", "sites": ["evil.example.com"]},
                 ["shop.example.com"], allow_admin=False)
    assert user_env({"user": "max", "email": "max@example.com", "role": "user", "sites": ["shop.example.com"]},
                    ["shop.example.com"], allow_admin=False)["SM_SITES"] == "shop.example.com"


def test_script_reads_database_without_secrets(tmp_path):
    db = tmp_path / "db.sq3"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE site (id INTEGER, domain_name TEXT, type TEXT, user TEXT, user_password TEXT)")
    con.execute("INSERT INTO site VALUES (1, 'shop.example.com', 'php', 'shop', 'geheim1')")
    con.execute("CREATE TABLE user (id INTEGER, user_name TEXT, email TEXT, password TEXT, mfa_secret TEXT, role TEXT)")
    con.execute("INSERT INTO user VALUES (1, 'admin', 'a@example.com', '$2y$hash', 'TOTPSECRET', 'admin')")
    con.commit()
    con.close()
    b = tmp_path / "bin"
    b.mkdir()
    calls = tmp_path / "calls"
    (b / "clpctl").write_text(f"#!/bin/bash\nprintf '%s\\n' \"$*\" >> {calls}\necho 'Site has been created.'\n")
    (b / "clpctl").chmod(0o755)
    lib = ROOT / "servermanager" / "modules" / "scripts" / "lib.sh"
    script = ROOT / "servermanager" / "modules" / "scripts" / "cloudpanel.sh"
    env = {**os.environ, "PATH": f"{b}:{os.environ['PATH']}", "SM_CLP_DB": str(db), "SM_CLP_CERTS": str(tmp_path)}
    res = subprocess.run(["bash", "-c", f"source {lib}; source {script}"], capture_output=True, text=True,
                         env={**env, "SM_TASK": "status"})
    assert res.returncode == 0, res.stdout + res.stderr
    d = parse_status(res.stdout)
    assert d["sites"][0]["domain"] == "shop.example.com" and d["users"][0]["name"] == "admin"
    assert "geheim1" not in res.stdout and "TOTPSECRET" not in res.stdout and "$2y$hash" not in res.stdout
    res = subprocess.run(["bash", "-c", f"source {lib}; source {script}"], capture_output=True, text=True,
                         env={**env, "SM_TASK": "site_add", "SM_TYPE": "php", "SM_DOMAIN": "a.example.com",
                              "SM_SITE_USER": "abc", "SM_SITE_PASSWORD": "Pw-123", "SM_PHP": "8.3"})
    assert "SM_OK" in res.stdout and "Pw-123" not in res.stdout
    assert calls.read_text().strip().splitlines()[-1] == ("site:add:php --domainName=a.example.com --phpVersion=8.3 "
                                         "--vhostTemplate=Generic --siteUser=abc --siteUserPassword=Pw-123")


@pytest.fixture()
def cp(db, monkeypatch):
    from servermanager import inventory
    from servermanager.models import System
    from servermanager.web.views import cloudpanel as view
    system = System(name="cp01", host="10.20.0.70", types=["debian", "cloudpanel"])
    db.add(system)
    db.commit()
    calls = []

    class DummyConn:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    monkeypatch.setattr(inventory, "connect", lambda s, timeout=None: DummyConn())

    def fake(conn, s, task, env=None, timeout=180):
        calls.append((task, dict(env or {})))
        return STATUS if task == "status" else "Done.\nSM_OK\n"
    monkeypatch.setattr(view, "cp_task", fake)
    yield system, calls
    db.delete(system)
    db.commit()


def test_pages_actions_and_rights(app, db, cp):
    from servermanager.models import SystemAccess
    system, calls = cp

    def last():
        return next(x for x in reversed(calls) if x[0] != "status")
    make_user(db, "cp-admin", "admin")
    c = login(app, "cp-admin")
    assert 'href="/cloudpanel/"' in c.get("/").text
    assert "cp01" in c.get("/cloudpanel/").text
    page = c.get(f"/cloudpanel/{system.id}").text
    assert "shop.example.com" in page and "bis 31.12.2030" in page and "PHP 8.3" in page
    assert "shopdb" in c.get(f"/cloudpanel/{system.id}?tab=databases").text
    page = c.get(f"/cloudpanel/{system.id}?tab=access").text
    assert "Pangolin" in page and "8443" in page
    r = c.post(f"/cloudpanel/{system.id}/do", data={"op": "site_add", "type": "php", "domain": "neu.example.com",
                                                    "site_user": "neu", "php": "8.3", "csrf_token": c.csrf},
               follow_redirects=True)
    task, env = last()
    assert task == "site_add" and env["SM_DOMAIN"] == "neu.example.com" and len(env["SM_SITE_PASSWORD"]) == 16
    assert "Site angelegt" in r.text and env["SM_SITE_PASSWORD"] in r.text   # shown once
    r = c.post(f"/cloudpanel/{system.id}/do", data={"op": "db_add", "domain": "shop.example.com", "db": "neu_db",
                                                    "db_user": "neu_user", "csrf_token": c.csrf}, follow_redirects=True)
    assert last()[0] == "db_add" and "Datenbank angelegt" in r.text
    c.post(f"/cloudpanel/{system.id}/do", data={"op": "cert", "domain": "shop.example.com",
                                                "san": "example.com, www.example.com", "csrf_token": c.csrf})
    assert last()[1]["SM_SAN"] == "example.com,www.example.com"
    r = c.post(f"/cloudpanel/{system.id}/do", data={"op": "cert", "domain": "shop.example.com; rm -rf /",
                                                    "csrf_token": c.csrf}, follow_redirects=True)
    assert "Ungültige Domain" in r.text
    # operator: certificates yes, sites no
    op = make_user(db, "cp-op")
    db.add(SystemAccess(user_id=op.id, system_id=system.id, level="operate"))
    db.commit()
    c2 = login(app, "cp-op")
    assert 'href="/cloudpanel/"' in c2.get("/").text
    assert c2.post(f"/cloudpanel/{system.id}/do", data={"op": "site_add", "csrf_token": c2.csrf}).status_code == 403
    n = len(calls)
    c2.post(f"/cloudpanel/{system.id}/do", data={"op": "cert", "domain": "shop.example.com", "csrf_token": c2.csrf})
    assert [x[0] for x in calls[n:]] == ["cert"]
    # full access but not administrator: CloudPanel administrators are off limits
    db.query(SystemAccess).filter_by(user_id=op.id).update({"level": "full"})
    db.commit()
    r = c2.post(f"/cloudpanel/{system.id}/do", data={"op": "user_password", "user": "admin", "csrf_token": c2.csrf},
                follow_redirects=True)
    assert "nur Administratoren" in r.text and last()[0] == "cert"
    r = c2.post(f"/cloudpanel/{system.id}/do", data={"op": "user_add", "user": "boss", "email": "b@example.com",
                                                     "role": "admin", "csrf_token": c2.csrf}, follow_redirects=True)
    assert "Administratoren legen nur Administratoren an" in r.text
    r = c2.post(f"/cloudpanel/{system.id}/do", data={"op": "user_password", "user": "anna", "csrf_token": c2.csrf},
                follow_redirects=True)
    assert last()[0] == "user_password" and last()[1]["SM_PASSWORD"] in r.text
    db.query(SystemAccess).filter_by(user_id=op.id).delete()
    db.commit()


@pytest.fixture(scope="module")
def mock():
    srv = m.MockServer().start()
    yield srv
    srv.stop()


def test_users_from_authentik(app, db, mock, cp):
    from servermanager.models import SsoServer
    system, calls = cp
    st = mock.state
    ak = SsoServer(name="auth", api_url=mock.url, public_url="https://auth.example.com",
                   token_enc=security.encrypt(m.AK_TOKEN), fingerprint=mock.fingerprint)
    db.add(ak)
    db.commit()
    saved = list(st.ak_users)
    st.ak_users += [{"pk": 50, "username": "anna", "name": "Anna B", "email": "anna@example.com", "is_active": True},
                    {"pk": 51, "username": "max.m", "name": "Max Muster", "email": "max@example.com",
                     "is_active": True},
                    {"pk": 52, "username": "ohnemail", "name": "X", "email": "", "is_active": True}]
    try:
        make_user(db, "cp-admin", "admin")
        c = login(app, "cp-admin")
        assert f"/cloudpanel/{system.id}/from-authentik?sso={ak.id}" in \
            c.get(f"/cloudpanel/{system.id}?tab=users").text.replace("&amp;", "&")
        page = c.get(f"/cloudpanel/{system.id}/from-authentik?sso={ak.id}").text
        assert 'value="anna" disabled' in page and "E-Mail fehlt" in page   # exists already / no e-mail
        r = c.post(f"/cloudpanel/{system.id}/from-authentik", data={
            "sso": ak.id, "users": ["max.m", "anna", "ohnemail"], "role": "user", "sites": ["shop.example.com"],
            "csrf_token": c.csrf})
        assert "1 Benutzer angelegt" in r.text and "Startpasswörter" in r.text
        task, env = next(x for x in reversed(calls) if x[0] != "status")
        assert task == "user_add" and env["SM_USER"] == "max.m" and env["SM_FIRST"] == "Max"
        assert env["SM_LAST"] == "Muster" and env["SM_SITES"] == "shop.example.com" and env["SM_PASSWORD"] in r.text
    finally:
        st.ak_users[:] = saved
        db.delete(ak)
        db.commit()
