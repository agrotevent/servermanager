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
