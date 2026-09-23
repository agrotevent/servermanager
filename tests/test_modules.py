import pytest

from servermanager.models import System
from servermanager.modules import MODULES, ParamError, schedulable_actions
from servermanager.modules.base import load_script
from servermanager.modules.debian import detect_types, parse_facts, release_upgrade_info
from servermanager.modules.docker import parse_update_check
from servermanager.modules.ispconfig import is_newer
from servermanager.modules.nextcloud import parse_check

FACTS = """os_id=debian
os_version=12
os_name=Debian GNU/Linux 12 (bookworm)
kernel=6.1.0-18-amd64
uptime=12345
cpus=4
mem_total=8000000
mem_avail=4000000
disk=/|10000000|5000000|5000000
disk=/var|2000|1900|100
reboot_required=1
apt=1
apt_updated=1700000000
pkg=openssl|3.0.11-1~deb12u1|3.0.13-1~deb12u1|Debian-Security:12/stable-security|1
pkg=curl|7.88.1-10|7.88.1-10+deb12u5|Debian:12.5/stable|0
docker_version=26.1.0
docker_running=3
nextcloud=/var/www/nextcloud|29.0.4
ispconfig_version=3.2.11p2
garbage line without equals
"""


def test_parse_facts():
    facts, apt = parse_facts(FACTS)
    assert facts["os_version"] == "12" and facts["uptime"] == 12345
    assert facts["reboot_required"] is True
    assert facts["disks"][1]["pct"] == 95
    assert facts["nextcloud"] == [{"path": "/var/www/nextcloud", "version": "29.0.4"}]
    assert apt["count"] == 2 and apt["security"] == 1
    assert apt["packages"][0]["name"] == "openssl"
    assert set(detect_types(facts)) == {"debian", "docker", "nextcloud", "ispconfig"}


def test_release_upgrade_detection():
    s = System(name="x", facts={"os_id": "debian", "os_version": "12"})
    assert release_upgrade_info(s)["to"] == "13"
    s.facts = {"os_id": "debian", "os_version": "13"}
    assert release_upgrade_info(s) is None
    s.facts = {"os_id": "debian", "os_version": "12", "pve_version": "8.2.4"}
    assert release_upgrade_info(s) is None  # proxmox uses its own upgrade path


def test_nextcloud_parse():
    out = """__STATUS__
{"installed":true,"version":"29.0.4.1","versionstring":"29.0.4","maintenance":false,"needsDbUpgrade":false}
__UPDATES__
Nextcloud 29.0.8 is available. Get more information on how to update at https://docs.nextcloud.com
Update for calendar to version 4.7.16 is available.
Update for contacts to version 6.0.1 is available.
3 updates available
"""
    r = parse_check(out)
    assert r["installed"] == "29.0.4" and r["core"] == "29.0.8"
    assert [a["app"] for a in r["apps"]] == ["calendar", "contacts"]
    assert parse_check("__STATUS__\n{}\n__UPDATES__\nEverything up to date")["core"] is None


def test_docker_parse():
    r = parse_update_check("update=web|nginx:latest\ncurrent=db|postgres:16\nunchecked=local|myimg\n")
    assert r["updates"] == [{"container": "web", "image": "nginx:latest"}]
    assert r["unchecked"] == ["local"]


def test_ispconfig_versions():
    assert is_newer("3.2.12", "3.2.11p2")
    assert is_newer("3.2.11p2", "3.2.11p1")
    assert not is_newer("3.2.11", "3.2.11")
    assert not is_newer("", "3.2.11")


def test_param_validation_blocks_injection():
    act = MODULES["docker"].action("container_restart")
    assert act.clean_params({"container": "web-1"}) == {"container": "web-1"}
    for bad in ["web; rm -rf /", "$(id)", "a b", "`x`", "../x", ""]:
        with pytest.raises(ParamError):
            act.clean_params({"container": bad})
    guest = MODULES["proxmox"].action("guest_action")
    with pytest.raises(ParamError):
        guest.clean_params({"node": "pve", "type": "qemu", "vmid": "100", "op": "destroy"})
    ok = guest.clean_params({"node": "pve", "type": "lxc", "vmid": "101", "op": "start"})
    assert ok["op"] == "start"


def test_bool_and_select_params():
    act = MODULES["debian"].action("release_upgrade")
    p = act.clean_params({"third_party": "disable", "force": "on"})
    assert p == {"third_party": "disable", "force": "1", "modernize": "0"}
    with pytest.raises(ParamError):
        act.clean_params({"third_party": "evil"})


def test_scripts_exist_and_env():
    for mod in MODULES.values():
        for a in mod.actions:
            if a.script:
                assert load_script(a.script)
    s = System(name="x", types=["debian", "nextcloud"], nextcloud_path="/srv/nc", occ_command="")
    body, env = MODULES["nextcloud"].script_for(MODULES["nextcloud"].action("apps_update"), s, {})
    assert env["SM_NC_PATH"] == "/srv/nc" and env["SM_TASK"] == "apps_update"
    assert "occ()" in body and "log()" in body


def test_schedulable_actions_exclude_hidden():
    keys = {(m.key, a.key) for m, a in schedulable_actions()}
    assert ("debian", "upgrade") in keys
    assert ("docker", "container_remove") not in keys
    assert ("debian", "reboot") not in keys
