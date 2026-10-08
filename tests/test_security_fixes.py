"""Regression tests for the fixes of the security review."""
from datetime import datetime

import pyotp
import pytest

from servermanager import security
from tests.test_web import login, make_user


# -------------------------------------------------------------------- tar options in config backups
def test_backup_paths_cannot_be_tar_options():
    from servermanager import sysbackup
    for bad in ("/--remove-files", "/etc/--index-file", "/-C", "/etc/../root", "/"):
        with pytest.raises(ValueError):
            sysbackup.parse_paths(bad)
    assert sysbackup.parse_paths("/etc /opt/app-1") == ["/etc", "/opt/app-1"]


def test_backup_command_ends_options():
    import inspect
    from servermanager import sysbackup
    assert " -- {rel}" in inspect.getsource(sysbackup.create_backup)


# -------------------------------------------------------------------- open redirect
@pytest.mark.parametrize("target,ok", [("/systems", True), ("/a?next=//x", True), ("//evil", False),
                                       ("/\t/evil", False), ("/\\evil", False), ("https://evil", False),
                                       ("/x\n", False), ("", False)])
def test_is_local_path(target, ok):
    from servermanager.web.auth import is_local_path
    assert is_local_path(target) is ok


def test_login_ignores_foreign_next(app, db):
    make_user(db, "sec-user")
    c = app.test_client()
    from tests.test_web import csrf_of
    tok = csrf_of(c)
    r = c.post("/login?next=/%09/evil.example", data={"username": "sec-user", "password": "Sehr-Geheim-123",
                                                      "csrf_token": tok})
    assert r.status_code == 302 and "evil" not in r.headers["Location"]


# -------------------------------------------------------------------- TOTP
def test_totp_code_only_once(app, db):
    from servermanager.models import User
    from tests.test_web import csrf_of
    u = make_user(db, "sec-2fa")
    secret = pyotp.random_base32()
    u.totp_secret_enc, u.totp_enabled, u.totp_last_step, u.failed_logins = security.encrypt(secret), True, None, 0
    db.commit()
    code = pyotp.TOTP(secret).now()
    step = security.totp_step(secret, code)
    assert step is not None and security.totp_step(secret, code, last_step=step) is None

    def attempt():
        c = app.test_client()
        tok = csrf_of(c)
        c.post("/login", data={"username": "sec-2fa", "password": "Sehr-Geheim-123", "csrf_token": tok})
        import re
        page = c.get("/login/2fa").text
        tok2 = (re.search(r'name="csrf-token" content="([^"]+)"', page)
                or re.search(r'name="csrf_token" value="([^"]+)"', page)).group(1)
        return c.post("/login/2fa", data={"code": code, "csrf_token": tok2})
    assert attempt().status_code == 302
    r = attempt()
    assert r.status_code == 401 and "bereits verwendet" in r.text
    db.expire_all()
    assert db.get(User, u.id).failed_logins == 1


def test_locked_account_answers_like_wrong_password(app, db):
    from datetime import timedelta
    from servermanager.models import utcnow
    from tests.test_web import csrf_of
    u = make_user(db, "sec-locked")
    u.locked_until = utcnow() + timedelta(minutes=10)
    db.commit()
    c = app.test_client()
    r = c.post("/login", data={"username": "sec-locked", "password": "Sehr-Geheim-123", "csrf_token": csrf_of(c)})
    assert r.status_code == 401 and "gesperrt" not in r.text.split("falsch")[0][-50:]
    u.locked_until = None
    db.commit()


def test_logout_invalidates_copied_cookie(app, db):
    make_user(db, "sec-logout")
    c = login(app, "sec-logout")
    cookie = c.get_cookie("sm_session").value
    c.post("/logout", data={"csrf_token": c.csrf})
    thief = app.test_client()
    thief.set_cookie("sm_session", cookie)
    assert thief.get("/").status_code == 302  # back to the login page


# -------------------------------------------------------------------- enrollment token race
def test_single_use_token_cannot_be_used_twice(db):
    from servermanager import enrollment
    admin = make_user(db, "sec-admin", "admin")
    _tok, row = enrollment.create_token(db, admin, name="x", connection="direct", ssh_user_mode="root", types=[],
                                        routed="", tags="", assign=[], valid_hours=1, max_uses=1)
    db.commit()
    enrollment._consume(db, row)
    with pytest.raises(enrollment.EnrollError):
        enrollment._consume(db, row)
    enrollment._release(db, row.id)
    enrollment._consume(db, row)  # released use can be taken again


def test_no_insecure_wget_with_pinned_certificate(db):
    from servermanager import enrollment, settings
    settings.set(db, "enroll.tls_pin", "abc=")
    try:
        cmd = enrollment.install_command(db, "tok")
        assert cmd["wget"] == "" and "--pinnedpubkey" in cmd["curl"]
    finally:
        settings.set(db, "enroll.tls_pin", "")


# -------------------------------------------------------------------- credentials need full access
def test_password_resets_need_full_access():
    from servermanager.models import LEVEL_FULL
    from servermanager.web.views import ispconfig, mailcow, nextcloud_users, pbx, sso
    assert sso.USER_ACTIONS["password"] == LEVEL_FULL
    assert mailcow.ACTIONS["mb_password"] == LEVEL_FULL
    assert ispconfig.ACTIONS["mb_password"] == LEVEL_FULL
    assert pbx.ACTIONS["ext_secret"] == LEVEL_FULL
    assert nextcloud_users.ACTIONS["resetpw"] == LEVEL_FULL


# -------------------------------------------------------------------- unauthenticated endpoints
def test_webhook_body_limit(app):
    c = app.test_client()
    r = c.post("/api/zammad/1/webhook", data=b"x" * (2 * 1024 * 1024), content_type="application/json")
    assert r.status_code == 413
    r = c.post("/api/zammad/1/webhook", data=b"{}", content_type="application/json",
               headers={"X-Hub-Signature": "sha1=äöü"})
    assert r.status_code == 403  # non-ASCII signature: rejected, no server error


# -------------------------------------------------------------------- RouterOS / MikroTik
def test_quote_cli_has_no_line_breaks():
    from servermanager.routeros import quote_cli
    assert "\n" not in quote_cli("x\n/system reset-configuration") and "\r" not in quote_cli("a\rb")


def test_mikrotik_login_never_over_unverified_tls():
    from servermanager.mikrotik import MikroTik, MikroTikError
    with pytest.raises(MikroTikError, match="gepinnt"):
        MikroTik("https://10.0.0.1", "u", "p", verify_tls=False)


# -------------------------------------------------------------------- maintenance plans
def test_manual_run_does_not_lend_admin_rights(db):
    from servermanager import schedules
    from servermanager.models import Job, MaintenanceSchedule, System, SystemAccess
    user = make_user(db, "sec-planner")
    admin = make_user(db, "sec-admin", "admin")
    mine = System(name="sec-prod-1", host="10.9.0.1", tags="sec-prod")
    other = System(name="sec-prod-2", host="10.9.0.2", tags="sec-prod")
    db.add_all([mine, other])
    db.flush()
    db.add(SystemAccess(user_id=user.id, system_id=mine.id, level="operate"))
    s = MaintenanceSchedule(name="sec", tag="sec-prod", steps=[{"module": "debian", "action": "upgrade"}],
                            created_by=user.id)
    db.add(s)
    db.commit()
    run = schedules.start_run(db, s, datetime(2026, 9, 30, 12, 0), manual_user=admin)
    targets = {j.system_id for j in db.query(Job).filter(Job.run_id == run.id)}
    assert targets == {mine.id}
    for j in db.query(Job).filter(Job.run_id == run.id):
        db.delete(j)
    db.commit()


# -------------------------------------------------------------------- guest import
def test_guest_import_cannot_take_over_other_system(db, monkeypatch):
    """A non-admin import must neither use a typed-in address nor bind to another system's address."""
    from servermanager import mgmt
    from servermanager.models import PveServer, System
    from servermanager.worker import JobFailed, Worker
    victim = System(name="sec-victim", host="10.9.9.9", host_keys="ssh-ed25519 AAAAvictim")
    server = PveServer(name="sec-pve", api_url="https://127.0.0.1:1", token_id="a@pve!b",
                       token_secret_enc=security.encrypt("x"), fingerprint="AA:" * 31 + "AA")
    user = make_user(db, "sec-importer")
    db.add_all([victim, server])
    db.commit()
    res = {"host_keys": ["ssh-ed25519 AAAAguest"], "ips": ["10.9.9.9"], "root_login": "", "added": True,
           "sshd_installed": False, "no_sshd": False}
    monkeypatch.setattr(mgmt, "inject_key_vm", lambda *a, **k: res)

    class Ctx:
        def say(self, m):
            pass
        write = say
    w = Worker.__new__(Worker)
    g = {"node": "pve1", "type": "qemu", "vmid": 321, "name": "guest", "ip": "10.9.9.9"}
    with pytest.raises(JobFailed, match="gehört bereits"):
        w._import_guest(Ctx(), server, None, {}, g, False, user.id)
    db.refresh(victim)
    assert victim.host_keys == "ssh-ed25519 AAAAvictim" and victim.pve_vmid is None
    # manual address from a non-admin is ignored: the guest's own address is used
    res["ips"] = ["10.9.9.10"]
    g["ip"] = "10.9.9.9"
    monkeypatch.setattr("servermanager.inventory.connect", lambda *a, **k: (_ for _ in ()).throw(
        __import__("servermanager.ssh", fromlist=["SSHError"]).SSHError("no ssh in tests")))
    with pytest.raises(JobFailed, match="SSH-Prüfung"):
        w._import_guest(Ctx(), server, None, {}, g, False, user.id)
    created = db.query(System).filter_by(pve_vmid=321).one()
    assert created.host == "10.9.9.10"
    # no host keys from the guest: no access is created
    res["host_keys"] = []
    g2 = dict(g, vmid=322)
    with pytest.raises(JobFailed, match="Hostkeys"):
        w._import_guest(Ctx(), server, None, {}, g2, False, user.id)
    for o in (created, victim, server):
        db.delete(o)
    db.commit()


def test_tls_pin_follows_the_certificate_at_the_public_address(app, db, monkeypatch):
    """'curl: (90) public key does not match pinned public key': the pin must match what clients get at the
    public address (e.g. behind Pangolin), and a publicly trusted certificate needs no pin at all."""
    import ssl
    from urllib.parse import urlsplit

    from servermanager import enrollment, settings
    from tests import mock_apis as m
    from tests.test_web import login, make_user
    srv = m.MockServer().start()
    try:
        parts = urlsplit(srv.url)
        served = enrollment.spki_pin(ssl.PEM_cert_to_DER_cert(ssl.get_server_certificate((parts.hostname, parts.port))))
        settings.set(db, "general.base_url", srv.url)
        settings.set(db, "enroll.tls_pin", "abc=")      # stale pin, e.g. of the local certificate
        db.commit()
        enrollment._TLS_CACHE.clear()
        st = enrollment.pin_status(db)
        assert st["checked"] and not st["trusted"] and st["pin"] == served and st["mismatch"]
        make_user(db, "pin-admin", "admin")
        c = login(app, "pin-admin")
        assert "Der Pin passt nicht" in c.get("/settings").text
        r = c.post("/settings/tls-pin", data={"csrf_token": c.csrf}, follow_redirects=True)
        assert f"Zertifikat unter {srv.url}" in r.text and settings.get(db, "enroll.tls_pin") == served
        assert f"--pinnedpubkey 'sha256//{served}'" in enrollment.install_command(db, "tok")["curl"]
        assert "Pin passt zum Zertifikat" in c.get("/settings").text
        # publicly trusted certificate at the public address: no pin (it would break with every renewal)
        monkeypatch.setattr(enrollment, "served_tls", lambda base, timeout=6: {"checked": True, "trusted": True,
                                                                                "pin": "new=", "host": "x:443"})
        assert "--pinnedpubkey" not in enrollment.install_command(db, "tok")["curl"]
        r = c.post("/settings/tls-pin", data={"csrf_token": c.csrf}, follow_redirects=True)
        assert "kein Pin nötig" in r.text and settings.get(db, "enroll.tls_pin") == ""
    finally:
        settings.set(db, "enroll.tls_pin", "")
        settings.set(db, "general.base_url", "")
        db.commit()
        enrollment._TLS_CACHE.clear()
        srv.stop()
