import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = sorted((ROOT / "servermanager" / "modules" / "scripts").glob("*.sh")) + \
    [ROOT / "install.sh", ROOT / "bin" / "sm-helper", ROOT / "bin" / "sm-update"]


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda p: p.name)
def test_bash_syntax(path):
    subprocess.run(["bash", "-n", str(path)], check=True)


@pytest.mark.skipif(not shutil.which("shellcheck"), reason="shellcheck not installed")
@pytest.mark.parametrize("path", SCRIPTS, ids=lambda p: p.name)
def test_shellcheck(path):
    res = subprocess.run(["shellcheck", "-S", "warning", "-s", "bash", str(path)], capture_output=True, text=True,
                         env={"LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/bin"})
    assert res.returncode == 0, res.stdout


def test_wg_validation_regex_rejects_hooks(tmp_path):
    helper = (ROOT / "bin" / "sm-helper").read_text()
    import re
    regex = re.search(r"grep -vE '(.+?)' \"\$f\"", helper).group(1)
    good = tmp_path / "good.conf"
    good.write_text("[Interface]\nPrivateKey = abc=\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = x=\n"
                    "Endpoint = [2001:db8::1]:51820\nAllowedIPs = 10.0.0.0/24, 192.168.1.0/24\n")
    bad = tmp_path / "bad.conf"
    bad.write_text("[Interface]\nPostUp = touch /tmp/x\n")
    assert subprocess.run(["grep", "-vE", regex, str(good)], capture_output=True).stdout == b""
    assert b"PostUp" in subprocess.run(["grep", "-vE", regex, str(bad)], capture_output=True).stdout


def _fake_bin(tmp_path, apt_script: str) -> dict:
    import os
    b = tmp_path / "bin"
    b.mkdir()
    (b / "apt-get").write_text("#!/bin/bash\n" + apt_script)
    (b / "dpkg").write_text(f"#!/bin/bash\ntouch {tmp_path}/fixed\necho configured\n")
    for f in b.iterdir():
        f.chmod(0o755)
    return {**os.environ, "PATH": f"{b}:{os.environ['PATH']}"}


def test_apt_run_repairs_interrupted_dpkg(tmp_path):
    env = _fake_bin(tmp_path, f"[ -f {tmp_path}/fixed ] && exit 0\n"
                              "echo \"E: dpkg was interrupted, you must manually run 'dpkg --configure -a'\"; exit 100\n")
    lib = ROOT / "servermanager" / "modules" / "scripts" / "lib.sh"
    res = subprocess.run(["bash", "-c", f"source {lib}; apt_run -y upgrade || apt_fail 'upgrade fehlgeschlagen'"],
                         capture_output=True, text=True, env=env)
    assert res.returncode == 0, res.stdout
    assert "Reparaturversuch: dpkg --configure -a" in res.stdout


def test_apt_run_reports_reason(tmp_path):
    env = _fake_bin(tmp_path, "printf 'dpkg: error processing package nginx (--configure):\\n"
                              "Errors were encountered while processing:\\n nginx\\n"
                              "E: Sub-process /usr/bin/dpkg returned an error code (1)\\n'; exit 100\n")
    lib = ROOT / "servermanager" / "modules" / "scripts" / "lib.sh"
    res = subprocess.run(["bash", "-c", f"source {lib}; apt_run -y upgrade || apt_fail 'upgrade fehlgeschlagen'"],
                         capture_output=True, text=True, env=env)
    assert res.returncode == 1
    assert "[FEHLER] upgrade fehlgeschlagen: Fehler beim Einrichten von: nginx" in res.stdout


def test_step_failure_names_reason(tmp_path, data_dir):
    from servermanager.jobs import log_path
    from servermanager.worker import Worker

    class Ctx:
        job_id = 987654
    log_path(Ctx.job_id).write_text("── Schritt 1: alt\n[FEHLER] alt\n── Schritt 2: Updates\n"
                                    "[FEHLER] apt-get upgrade fehlgeschlagen: kein freier Speicherplatz\n")
    assert Worker._last_error(Ctx()) == "apt-get upgrade fehlgeschlagen: kein freier Speicherplatz"
    log_path(Ctx.job_id).write_text("── Schritt 1: x\nnix\n")
    assert Worker._last_error(Ctx()) == ""
