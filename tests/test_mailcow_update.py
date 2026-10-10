"""mailcow-dockerized on the host: update check and update via update.sh, backup, detection."""
import os
import subprocess
from pathlib import Path

from servermanager.modules import MODULES
from servermanager.modules.debian import detect_types

ROOT = Path(__file__).resolve().parent.parent


def _install(tmp_path, check_rc=0, update_rc=(0,)):
    mc = tmp_path / "mailcow-dockerized"
    (mc / "data/web/inc").mkdir(parents=True)
    (mc / "helper-scripts").mkdir()
    (mc / "mailcow.conf").write_text("MAILCOW_HOSTNAME=mail.example.com\n")
    (mc / "data/web/inc/app_info.inc.php").write_text('<?php\n  $MAILCOW_GIT_VERSION="2025-03a";\n')
    runs = tmp_path / "runs"
    rcs = " ".join(str(x) for x in update_rc)
    (mc / "update.sh").write_text(f"""#!/bin/bash
echo "update.sh $*" >> {runs}
if [ "$1" = "--check" ]; then exit {check_rc}; fi
rcs=({rcs}); n=$(grep -c -- "--force" {runs}); rc=${{rcs[$((n-1))]:-0}}
[ "$rc" = 0 ] && sed -i 's/2025-03a/2025-09/' data/web/inc/app_info.inc.php
exit $rc
""")
    (mc / "helper-scripts/backup_and_restore.sh").write_text(
        f"#!/bin/bash\necho \"backup $* -> $MAILCOW_BACKUP_LOCATION\" >> {runs}\n")
    for f in (mc / "update.sh", mc / "helper-scripts/backup_and_restore.sh"):
        f.chmod(0o755)
    b = tmp_path / "bin"
    b.mkdir()
    (b / "docker").write_text("#!/bin/bash\n[ \"$1\" = compose ] && [ \"$2\" = version ] && exit 0\n"
                              "printf 'nginx-mailcow|running\\npostfix-mailcow|exited\\n'\n")
    (b / "docker").chmod(0o755)
    return mc, runs, {**os.environ, "PATH": f"{b}:{os.environ['PATH']}", "SM_MC_PATH": str(mc)}


def _run(env, task, **extra):
    lib = ROOT / "servermanager/modules/scripts/lib.sh"
    script = ROOT / "servermanager/modules/scripts/mailcow.sh"
    return subprocess.run(["bash", "-c", f"source {lib}; source {script}"], capture_output=True, text=True,
                          env={**env, "SM_TASK": task, **extra})


def test_check_and_update(tmp_path):
    from servermanager.modules.base import parse_kv
    mc, runs, env = _install(tmp_path, check_rc=0, update_rc=(2, 0))
    kv = parse_kv(_run(env, "check").stdout)
    assert kv["mailcow_version"] == ["2025-03a"] and kv["mailcow_update"] == ["yes"]
    res = _run(env, "update", SM_BACKUP="1", SM_BACKUP_DIR=str(tmp_path / "backup"), SM_SKIP_PING="1")
    assert res.returncode == 0 and "SM_OK" in res.stdout, res.stdout + res.stderr
    lines = runs.read_text().splitlines()
    # backup first, then update.sh --force twice (it replaced itself with a newer version the first time)
    assert lines[1] == f"backup backup all -> {tmp_path / 'backup'}"
    assert lines[2:] == ["update.sh --force --skip-ping-check", "update.sh --force --skip-ping-check"]
    assert "Fertig: mailcow 2025-09" in res.stdout and "Nicht laufende Container: postfix-mailcow" in res.stdout
    assert "postfix-mailcow|exited" in _run(env, "status").stdout


def test_check_without_update_and_failures(tmp_path):
    from servermanager.modules.base import parse_kv
    _mc, _runs, env = _install(tmp_path, check_rc=3, update_rc=(1,))
    assert parse_kv(_run(env, "check").stdout)["mailcow_update"] == ["no"]
    res = _run(env, "update")
    assert res.returncode == 1 and "update.sh fehlgeschlagen (Exit-Code 1)" in res.stdout
    res = _run(env, "update", SM_BACKUP="1", SM_BACKUP_DIR="/tmp/x;rm -rf /")
    assert res.returncode == 1 and "Ungültiger Sicherungsordner" in res.stdout
    res = _run({**env, "SM_MC_PATH": str(tmp_path / "nichts")}, "check")
    assert res.returncode == 1 and "Keine mailcow-Installation" in res.stdout


def test_detection_and_summary():
    from servermanager.models import System
    assert "mailcow" in detect_types({"mailcow_path": "/opt/mailcow-dockerized", "mailcow_version": "2025-03a"})
    mod = MODULES["mailcow"]
    s = System(name="mail", host="10.0.0.3", types=["debian", "mailcow"],
               updates={"mailcow": {"installed": "2025-03a", "available": True, "checked": 1}})
    assert mod.summary(s)["text"] == "Mailcow-Update"
    assert mod.action("update").level == "full" and mod.action("update").detached
    assert mod.env(s) == {"SM_MC_PATH": "/opt/mailcow-dockerized"}


def test_mailcow_page_shows_update_state(app, db):
    from servermanager import security
    from servermanager.models import MailcowServer, System
    from tests.test_web import login, make_user
    host = System(name="mail01", host="10.20.0.30", types=["debian", "mailcow"],
                  facts={"mailcow_version": "2025-03a"},
                  updates={"mailcow": {"installed": "2025-03a", "available": True, "checked": 1760000000}})
    db.add(host)
    db.flush()
    mc = MailcowServer(name="mc-upd", api_url="https://127.0.0.1:9", api_key_enc=security.encrypt("x"),
                       system_id=host.id)
    other = System(name="mail02", host="10.20.0.31", types=["debian"])
    db.add_all([mc, other])
    db.commit()
    try:
        make_user(db, "mcu-admin", "admin")
        c = login(app, "mcu-admin")
        page = c.get(f"/mailcow/{mc.id}").text
        assert "mailcow 2025-03a" in page and "Update verfügbar" in page
        assert f"/systems/{host.id}?tab=mailcow" in page.replace("&amp;", "&")
        mc.system_id = other.id
        db.commit()
        page = c.get(f"/mailcow/{mc.id}").text
        assert "noch nicht erkannt" in page and f"/systems/{other.id}/check" in page
        page = c.get(f"/systems/{host.id}?tab=mailcow").text
        assert "Mailcow aktualisieren" in page and "Vorher sichern" in page
    finally:
        db.delete(mc)
        db.delete(host)
        db.delete(other)
        db.commit()


def test_update_action_refreshes_the_update_state(db, monkeypatch):
    """After a successful action in the group Updates the module's check runs again (overview stays current)."""
    from servermanager.models import System
    from servermanager.worker import Worker
    mod = MODULES["mailcow"]
    s = System(name="mail-rc", host="10.0.0.9", types=["debian", "mailcow"],
               updates={"mailcow": {"installed": "2025-03a", "available": True, "checked": 1}, "apt": {"count": 2}})
    db.add(s)
    db.commit()
    monkeypatch.setattr(type(mod), "check", lambda self, conn, system, ctx: {"installed": "2025-09",
                                                                            "available": False, "checked": 2})

    class Ctx:
        def say(self, msg):
            pass
    try:
        Worker._recheck_module(Worker.__new__(Worker), Ctx(), None, s.id, mod)
        db.expire_all()
        upd = db.get(System, s.id).updates
        assert upd["mailcow"] == {"installed": "2025-09", "available": False, "checked": 2} and upd["apt"]["count"] == 2
    finally:
        db.delete(db.get(System, s.id))
        db.commit()


def test_additional_san(tmp_path):
    mc, _runs, env = _install(tmp_path)
    (mc / "mailcow.conf").write_text("MAILCOW_HOSTNAME=post.example.com\nADDITIONAL_SAN=smtp.*\n")
    res = _run(env, "san_add", SM_SAN="post.*")
    assert res.returncode == 0 and "SM_OK" in res.stdout, res.stdout + res.stderr
    assert "ADDITIONAL_SAN=smtp.*,post.*" in (mc / "mailcow.conf").read_text()
    assert list(mc.glob("mailcow.conf.bak-servermanager-*"))          # backup of the file first
    res = _run(env, "san_add", SM_SAN="post.*")
    assert "enthält post.* bereits" in res.stdout and (mc / "mailcow.conf").read_text().count("post.*") == 1
    (mc / "mailcow.conf").write_text("MAILCOW_HOSTNAME=post.example.com\n")
    _run(env, "san_add", SM_SAN="post.*")
    assert "ADDITIONAL_SAN=post.*" in (mc / "mailcow.conf").read_text()
    assert _run(env, "san_add", SM_SAN="post.*;reboot").returncode == 1
