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


def test_apt_run_skips_downgrades(tmp_path):
    """'Packages were downgraded and -y was used without --allow-downgrades': hold exactly those, upgrade the rest."""
    import os
    b = tmp_path / "bin"
    b.mkdir()
    state = tmp_path / "held"
    (b / "apt-get").write_text(f"""#!/bin/bash
if [[ " $* " == *" -s "* ]]; then
  if [[ " $* " == *" -y "* && " $* " != *" --allow-downgrades "* ]]; then
    echo "E: Packages were downgraded and -y was used without --allow-downgrades."; exit 100   # like real apt
  fi
  echo "Inst openssl [3.5.1-1] (3.5.2-1 Debian:13/stable [amd64])"
  echo "Inst libfoo [2.0-1] (1.9-3 local-repo [amd64])"
  exit 0
fi
if grep -q libfoo {state} 2>/dev/null; then echo "upgraded openssl"; exit 0; fi
echo "The following packages will be DOWNGRADED:"; echo "  libfoo"
echo "E: Packages were downgraded and -y was used without --allow-downgrades."; exit 100
""")
    (b / "apt-mark").write_text(f"""#!/bin/bash
case "$1" in
  showhold) cat {state} 2>/dev/null ;;
  hold) shift; printf '%s\\n' "$@" >> {state}; cp {state} {tmp_path}/was_held ;;
  unhold) shift; for p in "$@"; do sed -i "/^$p$/d" {state}; done ;;
esac
""")
    (b / "apt-cache").write_text("#!/bin/bash\nprintf 'libfoo:\\n  Installed: 2.0-1\\n  Candidate: 1.9-3\\n"
                                 "  Version table:\\n *** 2.0-1 100\\n        100 /var/lib/dpkg/status\\n"
                                 "     1.9-3 1001\\n       1001 http://repo.example.com/debian trixie/main amd64 Packages\\n'\n")
    for f in b.iterdir():
        f.chmod(0o755)
    env = {**os.environ, "PATH": f"{b}:{os.environ['PATH']}"}
    lib = ROOT / "servermanager" / "modules" / "scripts" / "lib.sh"
    res = subprocess.run(["bash", "-c", f"source {lib}; apt_run -y --with-new-pkgs upgrade || apt_fail 'x'; "
                                        "echo SKIPPED=$APT_SKIPPED"], capture_output=True, text=True, env=env)
    assert res.returncode == 0, res.stdout + res.stderr
    out = res.stdout
    assert "Nicht aktualisiert: libfoo – apt würde von 2.0-1 auf die ältere Version 1.9-3 zurückstufen" in out
    assert "Priorität 1001 aus http://repo.example.com/debian trixie/main" in out
    assert "openssl" not in out.split("Nicht aktualisiert")[1].split("\n")[0]  # only the real downgrade
    assert "SKIPPED=libfoo" in out and "upgraded openssl" in out
    assert (tmp_path / "was_held").read_text().split() == ["libfoo"]
    assert state.read_text().strip() == ""  # hold released again


def _apt_update_env(tmp_path, with_gpg: bool) -> dict:
    """Fake apt-get update like the report: Debian fine, nginx key missing, sury key expired, MariaDB mirror gone."""
    import base64
    import os
    etc = tmp_path / "etc"
    (etc / "sources.list.d").mkdir(parents=True)
    (etc / "trusted.gpg.d").mkdir()
    nginx_kr = tmp_path / "keyrings" / "nginx-archive-keyring.gpg"
    (etc / "sources.list").write_text("deb http://ftp.debian.org/debian trixie main\n")
    (etc / "sources.list.d" / "nginx.list").write_text(
        f"deb [signed-by={nginx_kr}] http://nginx.org/packages/mainline/debian trixie nginx\n")
    (etc / "sources.list.d" / "php.list").write_text("deb https://packages.sury.org/php/ trixie main\n")
    (etc / "sources.list.d" / "mariadb.sources").write_text(
        "Types: deb\nURIs: http://mirror2.hs-esslingen.de/mariadb/repo/10.4/debian\nSuites: trixie\n")
    sury_kr = etc / "trusted.gpg.d" / "servermanager-packages.sury.org.gpg"
    b = tmp_path / "bin"
    b.mkdir()
    (b / "apt-get").write_text(f"""#!/bin/bash
echo "Hit:1 http://ftp.debian.org/debian trixie InRelease"
rc=0
if ! grep -q NGINXKEY {nginx_kr} 2>/dev/null; then
  echo "Err:4 http://nginx.org/packages/mainline/debian trixie InRelease"
  echo "  Sub-process /usr/bin/sqv returned an error code (1), error message is: Missing key 8540A6F18833A80E9C1653A42FD21310B49F6B46, which is needed to verify signature."
  rc=100
fi
if ! grep -q SURYNEW {sury_kr} 2>/dev/null; then
  echo "Err:5 https://packages.sury.org/php trixie InRelease"
  echo "  Sub-process /usr/bin/sqv returned an error code (1), error message is: Signing key on 15058500A0235D97F5D10063B188E2B695BD4743 is bad:            The primary key is not live   because: Expired on 2026-02-04T10:25:46Z"
  rc=100
fi
echo "Ign:6 http://mirror2.hs-esslingen.de/mariadb/repo/10.4/debian trixie InRelease"
echo "Err:6 http://mirror2.hs-esslingen.de/mariadb/repo/10.4/debian trixie InRelease"
echo "  Could not connect to mirror2.hs-esslingen.de:80 (129.143.116.113), connection timed out"
echo "  Unable to connect to mirror2.hs-esslingen.de:http:"
[ $rc -ne 0 ] && echo "E: The repository 'http://nginx.org/packages/mainline/debian trixie InRelease' is not signed."
exit $rc
""")
    armored = base64.b64encode(b"NGINXKEY-binary").decode()
    (b / "curl").write_text(f"""#!/bin/bash
out=""; url=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2 ;; -*) [ "$1" = "--max-time" ] || [ "$1" = "--proto" ] && shift; shift ;; *) url="$1"; shift ;; esac; done
echo "$url" >> {tmp_path}/fetched
case "$url" in
  https://nginx.org/keys/nginx_signing.key) printf -- '-----BEGIN PGP PUBLIC KEY BLOCK-----\\n\\n{armored}\\n=abcd\\n-----END PGP PUBLIC KEY BLOCK-----\\n' > "$out" ;;
  https://packages.sury.org/php/apt.gpg) printf 'SURYNEW' > "$out" ;;
  *) exit 22 ;;
esac
""")
    for f in b.iterdir():
        f.chmod(0o755)
    path = f"{b}:{os.environ['PATH']}"
    if not with_gpg:   # a host without gpg: only the tools the library needs
        tools = tmp_path / "tools"
        tools.mkdir()
        for t in ("bash", "awk", "sed", "grep", "base64", "mktemp", "tee", "sort", "tr", "cut", "install", "mkdir",
                  "cp", "rm", "date", "basename", "dirname", "cat", "head", "sleep"):
            (tools / t).symlink_to(shutil.which(t))
        path = f"{b}:{tools}"
    return {**os.environ, "PATH": path, "SM_APT_ETC": str(etc), "SM_APT_RETRY_WAIT": "0",
            "SM_APT_KEY_BACKUP": str(tmp_path / "backup")}, nginx_kr, sury_kr


def test_apt_update_renews_vendor_keys_and_skips_broken_sources(tmp_path):
    env, nginx_kr, sury_kr = _apt_update_env(tmp_path, with_gpg=False)
    lib = ROOT / "servermanager" / "modules" / "scripts" / "lib.sh"
    res = subprocess.run(["bash", "-c", f"source {lib}; apt_update || exit 7; echo REPOS=$APT_REPOS_SKIPPED"],
                         capture_output=True, text=True, env=env)
    out = res.stdout
    assert res.returncode == 0, out + res.stderr
    assert nginx_kr.read_bytes() == b"NGINXKEY-binary" and sury_kr.read_bytes() == b"SURYNEW"
    assert "Schlüssel erneuert" in out and "Neuer Versuch mit erneuerten Signaturschlüsseln" in out
    assert ("Paketquelle übersprungen: http://mirror2.hs-esslingen.de/mariadb/repo/10.4/debian trixie – nicht "
            "erreichbar (eingetragen in") in out and "mariadb.sources" in out
    assert "REPOS=http://mirror2.hs-esslingen.de/mariadb/repo/10.4/debian" in out
    assert "nginx.org" not in out.split("REPOS=")[1]


def test_apt_update_skips_sources_it_cannot_repair_but_not_debian(tmp_path):
    env, nginx_kr, sury_kr = _apt_update_env(tmp_path, with_gpg=False)
    (tmp_path / "bin" / "curl").write_text("#!/bin/bash\nexit 22\n")   # vendor not reachable
    lib = ROOT / "servermanager" / "modules" / "scripts" / "lib.sh"
    res = subprocess.run(["bash", "-c", f"source {lib}; apt_update || exit 7; echo REPOS=$APT_REPOS_SKIPPED"],
                         capture_output=True, text=True, env=env)
    out = res.stdout
    assert res.returncode == 0, out
    assert "Schlüssel nicht ladbar: https://nginx.org/keys/nginx_signing.key" in out
    assert "Paketquelle übersprungen: http://nginx.org/packages/mainline/debian trixie – Signaturschlüssel fehlt" in out
    assert "https://packages.sury.org/php trixie – Signaturschlüssel abgelaufen" in out
    assert "Updates aus den übrigen Quellen werden installiert" in out
    # Debian's own source broken: no update with half the lists
    apt = tmp_path / "bin" / "apt-get"
    apt.write_text(apt.read_text().replace('echo "Hit:1 http://ftp.debian.org/debian trixie InRelease"',
                                           'echo "Err:1 http://ftp.debian.org/debian trixie InRelease"\n'
                                           'echo "  Could not resolve ftp.debian.org"'))
    res = subprocess.run(["bash", "-c", f"source {lib}; apt_update || exit 7"], capture_output=True, text=True, env=env)
    assert res.returncode == 7 and "apt-get update fehlgeschlagen (Versuch 3/3)" in res.stdout


@pytest.mark.skipif(not shutil.which("gpg"), reason="gpg not installed")
def test_apt_update_checks_the_missing_fingerprint_with_gpg(tmp_path):
    env, nginx_kr, _sury = _apt_update_env(tmp_path, with_gpg=True)
    lib = ROOT / "servermanager" / "modules" / "scripts" / "lib.sh"
    res = subprocess.run(["bash", "-c", f"source {lib}; apt_update || exit 7"], capture_output=True, text=True,
                         env={**env, "GNUPGHOME": str(tmp_path / "gnupg")})
    assert "enthält 8540A6F18833A80E9C1653A42FD21310B49F6B46 nicht – nicht übernommen" in res.stdout
    assert not nginx_kr.exists() and res.returncode == 0   # skipped like any other broken source


def test_apt_run_skips_downgrade_named_only_in_the_refused_run(tmp_path):
    """Report from Debian 13 (apt 3): the dry run does not show the downgrade, only the refused run names it."""
    import os
    b = tmp_path / "bin"
    b.mkdir()
    state = tmp_path / "held"
    (b / "apt-get").write_text(f"""#!/bin/bash
if [[ " $* " == *" -s "* ]]; then
  echo "Inst liblzma5 [5.8.1-1] (5.8.1-1+deb13u1 Debian:13.1/stable [amd64])"   # no line for sgml-base
  exit 0
fi
if grep -q sgml-base {state} 2>/dev/null; then echo "4 upgraded, 0 newly installed"; echo "upgraded rest"; exit 0; fi
cat <<'OUT'
The following packages will be upgraded:
  liblzma5 redis-server redis-tools xz-utils
The following packages will be DOWNGRADED:
  sgml-base
4 upgraded, 0 newly installed, 1 downgraded, 0 to remove and 0 not upgraded.
E: Packages were downgraded and -y was used without --allow-downgrades.
OUT
exit 100
""")
    (b / "dpkg-query").write_text("#!/bin/bash\n[ \"${@: -1}\" = sgml-base ] && printf '1.31+nmu1' && exit 0\nexit 1\n")
    (b / "apt-cache").write_text("#!/bin/bash\nprintf 'sgml-base:\\n  Installed: 1.31+nmu1\\n  Candidate: 1.31\\n"
                                 "  Version table:\\n *** 1.31+nmu1 100\\n        100 /var/lib/dpkg/status\\n"
                                 "     1.31 1001\\n       1001 http://deb.debian.org/debian bookworm/main amd64 Packages\\n'\n")
    (b / "apt-mark").write_text(f"""#!/bin/bash
case "$1" in
  showhold) cat {state} 2>/dev/null ;;
  hold) shift; printf '%s\\n' "$@" >> {state} ;;
  unhold) shift; for p in "$@"; do sed -i "/^$p$/d" {state}; done ;;
esac
""")
    for f in b.iterdir():
        f.chmod(0o755)
    env = {**os.environ, "PATH": f"{b}:{os.environ['PATH']}"}
    lib = ROOT / "servermanager" / "modules" / "scripts" / "lib.sh"
    res = subprocess.run(["bash", "-c", f"set -o pipefail; source {lib}; apt_run -y --with-new-pkgs upgrade || "
                                        "apt_fail 'apt-get upgrade fehlgeschlagen'; echo SKIPPED=$APT_SKIPPED"],
                         capture_output=True, text=True, env=env)
    out = res.stdout
    assert res.returncode == 0, out + res.stderr
    assert "Nicht aktualisiert: sgml-base – apt würde von 1.31+nmu1 auf die ältere Version 1.31 zurückstufen" in out
    assert "Priorität 1001 aus http://deb.debian.org/debian bookworm/main" in out
    assert "upgraded rest" in out and "SKIPPED=sgml-base" in out and state.read_text().strip() == ""


def test_apt_update_ignores_errors_apt_recovered_from(tmp_path):
    """apt retries: an Err followed by a successful Get of the same file is not a broken source."""
    out = tmp_path / "update.txt"
    out.write_text("Get:3 file:/srv/repo ./ Packages\nErr:3 file:/srv/repo ./ Packages\n  Method gave a blank filename\n"
                   "Get:3 file:/srv/repo ./ Packages [618 B]\n"
                   "Get:4 http://nginx.org/packages/mainline/debian trixie InRelease [3294 B]\n"
                   "Err:4 http://nginx.org/packages/mainline/debian trixie InRelease\n  Missing key ABC\n")
    lib = ROOT / "servermanager" / "modules" / "scripts" / "lib.sh"
    res = subprocess.run(["bash", "-c", f"source {lib}; apt_failed_repos {out}"], capture_output=True, text=True)
    assert res.stdout == "http://nginx.org/packages/mainline/debian trixie\tMissing key ABC\n"


def test_apt_run_holds_same_version_from_other_source(tmp_path):
    """Report from Debian 13: apt 3 lists sgml-base as DOWNGRADED although the version string is the same - the
    candidate is another build from a vendor repository with high priority (CloudPanel's CloudFront source)."""
    import os
    b = tmp_path / "bin"
    b.mkdir()
    state = tmp_path / "held"
    (b / "apt-get").write_text(f"""#!/bin/bash
if [[ " $* " == *" -s "* ]]; then
  echo "Inst liblzma5 [5.8.1-1+deb13u1] (5.8.1-1+deb13u2 Debian-Security:13/stable-security [amd64])"
  echo "Inst sgml-base [1.31+nmu1] (1.31+nmu1 d17k9fuiwb52nc.cloudfront.net [all])"
  exit 0
fi
if grep -q sgml-base {state} 2>/dev/null; then echo "upgraded rest"; exit 0; fi
cat <<'OUT'
The following packages will be upgraded:
  liblzma5 redis-server redis-tools xz-utils
The following packages will be DOWNGRADED:
  sgml-base
4 upgraded, 0 newly installed, 1 downgraded, 0 to remove and 0 not upgraded.
E: Packages were downgraded and -y was used without --allow-downgrades.
OUT
exit 100
""")
    (b / "dpkg-query").write_text("#!/bin/bash\n[ \"${@: -1}\" = sgml-base ] && printf '1.31+nmu1' && exit 0\nexit 1\n")
    (b / "apt-cache").write_text("#!/bin/bash\nprintf 'sgml-base:\\n  Installed: 1.31+nmu1\\n  Candidate: 1.31+nmu1\\n"
                                 "  Version table:\\n     1.31+nmu1 1001\\n"
                                 "       1001 https://d17k9fuiwb52nc.cloudfront.net trixie/main amd64 Packages\\n"
                                 " *** 1.31+nmu1 500\\n        500 http://deb.debian.org/debian trixie/main amd64 Packages\\n"
                                 "        100 /var/lib/dpkg/status\\n'\n")
    (b / "apt-mark").write_text(f"""#!/bin/bash
case "$1" in
  showhold) cat {state} 2>/dev/null ;;
  hold) shift; printf '%s\\n' "$@" >> {state} ;;
  unhold) shift; for p in "$@"; do sed -i "/^$p$/d" {state}; done ;;
esac
""")
    for f in b.iterdir():
        f.chmod(0o755)
    env = {**os.environ, "PATH": f"{b}:{os.environ['PATH']}"}
    lib = ROOT / "servermanager" / "modules" / "scripts" / "lib.sh"
    res = subprocess.run(["bash", "-c", f"set -o pipefail; source {lib}; apt_run -y --with-new-pkgs upgrade || "
                                        "apt_fail 'apt-get upgrade fehlgeschlagen'; echo SKIPPED=$APT_SKIPPED"],
                         capture_output=True, text=True, env=env)
    out = res.stdout
    assert res.returncode == 0, out + res.stderr
    assert ("Nicht aktualisiert: sgml-base – apt würde 1.31+nmu1 durch einen anderen Build derselben Version "
            "ersetzen (Priorität 1001 aus https://d17k9fuiwb52nc.cloudfront.net trixie/main)") in out
    assert "upgraded rest" in out and "SKIPPED=sgml-base" in out and state.read_text().strip() == ""


def test_apt_explain_kept_back(tmp_path):
    """Packages kept back by apt-get upgrade: say what a full upgrade would remove before anybody runs it."""
    import os
    b = tmp_path / "bin"
    b.mkdir()
    sim = tmp_path / "sim"
    (b / "apt-get").write_text(f"#!/bin/bash\ncat {sim}\n")
    (b / "apt-mark").write_text("#!/bin/bash\n[ \"$1\" = showhold ] && echo samba-libs\nexit 0\n")
    for f in b.iterdir():
        f.chmod(0o755)
    env = {**os.environ, "PATH": f"{b}:{os.environ['PATH']}"}
    lib = ROOT / "servermanager" / "modules" / "scripts" / "lib.sh"

    def run(text, skipped=""):
        sim.write_text(text)
        return subprocess.run(["bash", "-c", f"source {lib}; APT_SKIPPED='{skipped}'; apt_explain_kept_back"],
                              capture_output=True, text=True, env=env).stdout
    out = run("Inst php8.3-fpm [8.3.20-1] (8.3.26-1 packages.sury.org [amd64])\n"
              "Inst libicu76 (76.1-4 Debian:13.1/stable [amd64])\n"
              "Remv php-smbclient [1.1.1-1]\nInst sgml-base [1.31+nmu1] (1.31+nmu1 cdn [all])\n", skipped="sgml-base")
    assert "Zurückgehalten: 1 Paket(e) (php8.3-fpm)" in out and "ENTFERNEN: php-smbclient" in out
    assert "neu installieren: libicu76" in out and "festgehalten (apt-mark hold): samba-libs" in out
    out = run("Inst nginx [1.26.3-1] (1.28.0-1 nginx.org [amd64])\nInst libssl3t64 (3.5.1-1 Debian:13 [amd64])\n")
    assert "Zurückgehalten: 1 Paket(e) (nginx) – sie brauchen neue Pakete (libssl3t64)" in out
    assert "ohne etwas zu entfernen" in out and "ENTFERNEN" not in out
    assert "Zurückgehalten" not in run("")
