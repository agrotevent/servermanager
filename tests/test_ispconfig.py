"""ISPConfig: remote API client, SSH setup of the remote user, automatic setup, web pages."""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from servermanager import security
from servermanager.ispconfig_api import IspConfig, IspError, normalize_url
from tests import mock_apis as m
from tests.test_web import login, make_user

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "servermanager" / "modules" / "scripts"


@pytest.fixture(scope="module")
def mock():
    srv = m.MockServer().start()
    yield srv
    srv.stop()


def _api(mock, password=m.ISP_PASS) -> IspConfig:
    return IspConfig(f"{mock.url}/remote/json.php", m.ISP_USER, password, fingerprint=mock.fingerprint)


def test_normalize_url():
    assert normalize_url("10.0.0.5") == "https://10.0.0.5:8080/remote/json.php"
    assert normalize_url("https://panel.example.com:8081/") == "https://panel.example.com:8081/remote/json.php"
    assert normalize_url("https://p:8080/remote/json.php") == "https://p:8080/remote/json.php"


def test_client(mock):
    with pytest.raises(IspError, match="Remote-Benutzer, Passwort und erlaubte IP"):
        _api(mock, "falsch").login()
    with _api(mock) as api:
        assert api.version() == "3.2.12p1"
        assert [w["domain"] for w in api.websites()] == ["muster.de"]  # aliases are not listed
        domain = api.mail_domains()[0]
        api.add_mailbox(domain, "Eva", "Eva Muster", "Geheim123456", 512)
        box = next(b for b in api.mailboxes() if b["email"] == "eva@muster.de")
        assert box["maildir"] == "/var/vmail/muster.de/eva" and box["quota"] == 512 * 1024 * 1024
        assert box["_client_id"] == 1  # owner of the domain, not the admin
        api.set_mailbox_password(box, "NeuesPasswort123")
        api.delete_mailbox(int(box["mailuser_id"]))
        assert not any(b["email"] == "eva@muster.de" for b in api.mailboxes())
        with pytest.raises(IspError, match="Ungültiger Name"):
            api.add_mailbox(domain, "a b", "", "x" * 12, 1)
        with pytest.raises(IspError, match="E-Mail"):
            api.add_client("", "Max", "keine-mail", "max", "pw")
    assert not mock.state.isp["sessions"]  # logged out


@pytest.fixture()
def isp(db, mock):
    from servermanager.models import IspServer, System
    system = System(name="web01", host="127.0.0.1", types=["debian", "ispconfig"],
                    facts={"ispconfig_version": "3.2.12p1"})
    db.add(system)
    db.flush()
    i = IspServer(name="Webserver", system_id=system.id, api_url=f"{mock.url}/remote/json.php",
                  username=m.ISP_USER, password_enc=security.encrypt(m.ISP_PASS), fingerprint=mock.fingerprint)
    db.add(i)
    db.commit()
    yield {"isp": i, "system": system}
    for o in (i, system):
        if db.get(type(o), o.id) is not None:
            db.delete(o)
    db.commit()


def test_poll(db, isp):
    from servermanager import integrations
    i = isp["isp"]
    integrations.poll(db, i)
    assert i.status == "online", i.status_message
    d = i.data
    assert (d["version"], d["clients"], d["websites"], d["mailboxes"], d["dns_zones"], d["databases"]) == \
        ("3.2.12p1", 1, 1, 1, 1, 1)


def test_web(app, db, mock, isp):
    from servermanager.models import IntegrationAccess
    make_user(db, "isp-admin", "admin")
    c = login(app, "isp-admin")
    iid = isp["isp"].id
    assert "ISPConfig" in c.get("/").text
    for tab in ("overview", "clients", "sites", "mail", "dns", "databases", "access"):
        r = c.get(f"/ispconfig/{iid}?tab={tab}")
        assert r.status_code == 200, (tab, r.text[:300])
    assert "muster.de" in c.get(f"/ispconfig/{iid}?tab=sites").text
    r = c.post(f"/ispconfig/{iid}/do", data={"action": "mb_add", "local": "support", "domain_id": "5",
                                             "name": "Support", "quota": "100", "csrf_token": c.csrf},
               follow_redirects=True)
    assert "Postfach support@muster.de angelegt" in r.text and "wird nur jetzt angezeigt" in r.text
    r = c.post(f"/ispconfig/{iid}/do", data={"action": "site_active", "id": "3", "active": "0",
                                             "csrf_token": c.csrf}, follow_redirects=True)
    assert "muster.de deaktiviert" in r.text
    assert mock.state.isp["sites"][0]["active"] == "n"
    mock.state.isp["sites"][0]["active"] = "y"
    r = c.post(f"/ispconfig/{iid}/do", data={"action": "client_add", "contact": "Anna", "email": "anna@example.com",
                                             "username": "anna", "csrf_token": c.csrf}, follow_redirects=True)
    assert "Kunde anna angelegt" in r.text
    viewer = make_user(db, "isp-viewer")
    db.add(IntegrationAccess(user_id=viewer.id, kind="ispconfig", obj_id=iid, level="view"))
    db.commit()
    v = login(app, "isp-viewer")
    page = v.get(f"/ispconfig/{iid}?tab=mail").text
    assert "info@muster.de" in page and "Postfach anlegen" not in page and "Neues Passwort" not in page
    assert v.post(f"/ispconfig/{iid}/do", data={"action": "mb_delete", "id": "7",
                                                "csrf_token": v.csrf}).status_code == 403


def test_setup_job_via_ssh(db, mock, isp, monkeypatch):
    """The job creates the remote user (script faked), pins the certificate and stores only the new login."""
    from servermanager.jobs import enqueue, log_path
    from servermanager.models import IspServer, Job
    from servermanager.worker import Worker
    from tests.test_integrations import _run
    fresh = IspServer(name="neu", system_id=isp["system"].id, monitor=True)
    db.add(fresh)
    db.commit()
    seen = {}

    class FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def run_script(self, body, env=None, root=False, on_output=None, timeout=0, **kw):
            seen.update(env)
            mock.state.isp["users"][env["SM_ISPC_USER"]] = env["SM_ISPC_PASS"]
            on_output(f"==> Remote-Benutzer angelegt\nversion=3.2.12p1\nport={mock.port}\ngroups=6\nSM_OK\n")
            return 0
    monkeypatch.setattr(Worker, "_connect", lambda self, ctx, system: FakeConn())
    job = enqueue(db, kind="ispconfig_setup", title="setup", system=isp["system"], payload={"isp_id": fresh.id})
    db.commit()
    try:
        _run(job.id)
        db.expire_all()
        job = db.get(Job, job.id)
        log = log_path(job.id).read_text()
        assert job.status == "success", log
        fresh = db.get(IspServer, fresh.id)
        assert fresh.api_url == f"https://127.0.0.1:{mock.port}/remote/json.php"
        assert fresh.fingerprint == mock.fingerprint and fresh.username == "servermanager"
        assert security.decrypt(fresh.password_enc) == seen["SM_ISPC_PASS"] and len(seen["SM_ISPC_PASS"]) == 32
        assert seen["SM_ISPC_PASS"] not in log
        assert "sites_web_domain_get" in seen["SM_ISPC_FUNCS"] and seen["SM_ISPC_IPS"]
        assert fresh.status == "online" and fresh.data["websites"] == 1
    finally:
        mock.state.isp["users"] = {m.ISP_USER: m.ISP_PASS}
        db.delete(db.get(IspServer, fresh.id))
        db.commit()


def test_auto_setup_on_detection(db, isp):
    from servermanager import integrations, settings
    from servermanager.models import IspServer, Job, System
    s = System(name="panel2", host="10.20.0.71", types=["debian", "ispconfig"])
    db.add(s)
    db.flush()
    job_id = integrations.ispconfig_auto(db, s)
    assert job_id and db.get(Job, job_id).kind == "ispconfig_setup"
    assert integrations.ispconfig_auto(db, s) is None  # only once
    created = db.query(IspServer).filter_by(system_id=s.id).one()
    settings.set(db, "ispconfig.auto_setup", False)
    s2 = System(name="panel3", host="10.20.0.72", types=["ispconfig"])
    db.add(s2)
    db.flush()
    assert integrations.ispconfig_auto(db, s2) is None
    settings.set(db, "ispconfig.auto_setup", True)
    db.delete(db.get(Job, job_id))
    db.delete(created)
    db.delete(s)
    db.delete(s2)
    db.commit()


@pytest.mark.skipif(not shutil.which("php") or not shutil.which("openssl"), reason="php/openssl missing")
def test_remote_user_script(tmp_path):
    ispc = tmp_path / "ispconfig"
    (ispc / "server/lib").mkdir(parents=True)
    (ispc / "server/lib/config.inc.php").write_text(
        "<?php\ndefine('ISPC_APP_VERSION', '3.2.12p1');\n$conf['db_user'] = 'ispconfig';\n"
        "$conf['db_password'] = 'dbpw';\n$conf['db_database'] = 'dbispconfig';\n$conf['db_host'] = 'localhost';\n")
    for mod, keys in {"admin": ["server_get,server_config_set,server_get_all", "admin_record_permissions"],
                      "sites": ["sites_web_domain_get,sites_web_domain_add,sites_web_domain_update",
                                "sites_cron_get,sites_cron_add"],
                      "mail": ["mail_user_get,mail_user_add,mail_user_update,mail_user_delete"]}.items():
        (ispc / f"interface/web/{mod}/lib").mkdir(parents=True)
        (ispc / f"interface/web/{mod}/lib/remote.conf.php").write_text(
            "<?php\n" + "".join(f"$function_list['{k}'] = 'x';\n" for k in keys))
    b = tmp_path / "bin"
    b.mkdir()
    log = tmp_path / "sql.log"
    (b / "mysql").write_text("#!/bin/bash\nq=\"${@: -1}\"\necho \"$MYSQL_PWD|$q\" >> " + str(log) + "\n"
                             "case \"$q\" in *'SHOW COLUMNS'*) echo remote_ips ;; esac\n")
    (b / "mysql").chmod(0o755)
    env = {**os.environ, "PATH": f"{b}:{os.environ['PATH']}", "SM_ISPC_DIR": str(ispc), "SM_TASK": "remote_user",
           "SM_ISPC_USER": "servermanager", "SM_ISPC_PASS": "A" * 10 + "b" * 10 + "1234567890ab",
           "SM_ISPC_FUNCS": "server_get,sites_web_domain_get,mail_user_add,client_get", "SM_ISPC_IPS": "10.66.0.1"}
    body = (SCRIPTS / "lib.sh").read_text() + "\n" + (SCRIPTS / "ispconfig.sh").read_text()
    res = subprocess.run(["bash", "-c", body], capture_output=True, text=True, env=env)
    assert res.returncode == 0 and "SM_OK" in res.stdout, res.stdout + res.stderr
    assert "port=8080" in res.stdout and "groups=3" in res.stdout
    sql = log.read_text()
    assert "dbpw|" in sql  # credentials of the ISPConfig server part
    insert = next(line for line in sql.splitlines() if "INSERT INTO remote_user" in line)
    import re
    groups = set(re.search(r"'([a-z_,;]+)', 'y'\)", insert).group(1).split(";"))
    assert groups == {"server_get,server_config_set,server_get_all",
                      "sites_web_domain_get,sites_web_domain_add,sites_web_domain_update",
                      "mail_user_get,mail_user_add,mail_user_update,mail_user_delete"}
    assert "remote_ips='10.66.0.1'" in sql
    hashed = re.search(r"'(\$6\$[^']+)'", insert).group(1)
    # ISPConfig verifies with PHP crypt()
    check = subprocess.run(["php", "-r", f"echo crypt('{env['SM_ISPC_PASS']}', '{hashed}') === '{hashed}' "
                                         "? 'match' : 'no';"], capture_output=True, text=True)
    assert check.stdout == "match"
    bad = dict(env, SM_ISPC_FUNCS="x;rm -rf /")
    res = subprocess.run(["bash", "-c", body], capture_output=True, text=True, env=bad)
    assert res.returncode == 1 and "Ungültige Funktionsliste" in res.stdout
