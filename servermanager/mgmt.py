"""Management access for existing infrastructure.

* Proxmox: API token created with a one-time administrator login (password is
  not stored; the certificate is verified/pinned before it is sent).
* RouterOS: dedicated API user/group created with a one-time admin login.
* Existing containers/VMs: the servermanager SSH key is installed through a
  trusted channel - ``pct exec`` on the Proxmox host (LXC) or the QEMU guest
  agent (VM) - and the SSH host keys are read through the same channel and
  pinned, so the first SSH connection is already verified.
"""
from __future__ import annotations

import base64
import re
import secrets
import shlex
from typing import Callable, Optional

from . import security, sshkeys
from .mikrotik import MikroTik, MikroTikError
from .models import PveServer, RouterDevice
from .pveapi import NODE_RE, PveClient, PveError

HOSTKEY_RE = re.compile(r"^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/=]+")
ROUTER_POLICY = "read,write,api,rest-api,test"
ROUTER_POLICY_BACKUP = ROUTER_POLICY + ",ftp,sensitive"


class MgmtError(Exception):
    pass


# --------------------------------------------------------------------------
# Proxmox API token via admin login
# --------------------------------------------------------------------------
def pve_token_via_login(server: PveServer, username: str, password: str, otp: str = "",
                        role: str = "PVEAdmin") -> str:
    if role not in ("PVEAdmin", "Administrator", "PVEAuditor"):
        raise MgmtError("Ungültige Rolle")
    if not re.match(r"^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+$", username or ""):
        raise MgmtError("Benutzer im Format name@realm angeben, z. B. root@pam")
    try:
        api = PveClient.login(server.api_url, username, password, otp=otp, fingerprint=server.fingerprint or "",
                              verify_ca=bool(server.verify_ca))
        token_id, secret = api.create_api_token(role=role, token_name="sm" + secrets.token_hex(3))
    except PveError as exc:
        raise MgmtError(str(exc)) from exc
    server.token_id = token_id
    server.token_secret_enc = security.encrypt(secret)
    return token_id


# --------------------------------------------------------------------------
# RouterOS API user via admin login
# --------------------------------------------------------------------------
def router_mgmt_user(router: RouterDevice, admin_user: str, admin_password: str, allowed: str,
                     with_backup: bool = False, username: str = "servermanager") -> str:
    """Create/refresh a dedicated API user; returns the user name. The admin login is not stored."""
    if not re.match(r"^[A-Za-z0-9._-]{1,32}$", username):
        raise MgmtError("Ungültiger Benutzername")
    nets = [a.strip() for a in re.split(r"[,\s]+", allowed or "") if a.strip()]
    for n in nets:
        if not re.match(r"^[0-9a-fA-F:.]+(/\d{1,3})?$", n):
            raise MgmtError(f"Ungültige Adresse {n}")
    policy = ROUTER_POLICY_BACKUP if with_backup else ROUTER_POLICY
    password = secrets.token_urlsafe(24)
    try:
        mt = MikroTik(router.api_url, admin_user, admin_password, verify_tls=bool(router.verify_ca),
                      fingerprint=router.fingerprint or "")
        groups = {g.get("name"): g for g in mt.get("user/group")}
        if username in groups:
            mt.patch("user/group", groups[username][".id"], {"policy": policy})
        else:
            mt.create("user/group", {"name": username, "policy": policy, "comment": "servermanager API"})
        data = {"group": username, "password": password, "comment": "servermanager API",
                "address": ",".join(nets)}
        users = {u.get("name"): u for u in mt.get("user")}
        if username in users:
            mt.patch("user", users[username][".id"], data)
        else:
            mt.create("user", {"name": username, **data})
        # verify the new login before storing it
        MikroTik(router.api_url, username, password, verify_tls=bool(router.verify_ca),
                 fingerprint=router.fingerprint or "").identity()
    except MikroTikError as exc:
        raise MgmtError(str(exc)) from exc
    router.username = username
    router.password_enc = security.encrypt(password)
    return username


# --------------------------------------------------------------------------
# SSH key into existing guests
# --------------------------------------------------------------------------
def key_script(install_ssh: bool) -> str:
    pub = sshkeys.public_key().strip()
    if not pub:
        raise MgmtError("Kein SSH-Schlüssel des Servermanagers vorhanden")
    blob = pub.split()[1]
    b64 = base64.b64encode(pub.encode()).decode()
    return f"""set -e
umask 077
mkdir -p /root/.ssh
touch /root/.ssh/authorized_keys
if ! grep -qF '{blob}' /root/.ssh/authorized_keys; then
    echo '{b64}' | base64 -d >> /root/.ssh/authorized_keys
    echo >> /root/.ssh/authorized_keys
    echo "SM_KEY added"
else
    echo "SM_KEY present"
fi
chmod 700 /root/.ssh; chmod 600 /root/.ssh/authorized_keys
if ! command -v sshd >/dev/null 2>&1 && [ ! -x /usr/sbin/sshd ]; then
    if [ "{1 if install_ssh else 0}" = 1 ]; then
        if command -v apt-get >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get -q update >/dev/null && \\
                DEBIAN_FRONTEND=noninteractive apt-get install -y -q openssh-server >/dev/null
        elif command -v apk >/dev/null 2>&1; then
            apk add --no-cache openssh >/dev/null && (rc-update add sshd default || true)
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y -q openssh-server >/dev/null
        else
            echo "SM_NO_SSHD"; exit 3
        fi
        echo "SM_SSHD installed"
    else
        echo "SM_NO_SSHD"; exit 3
    fi
fi
[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A >/dev/null 2>&1 || true
systemctl enable --now ssh >/dev/null 2>&1 || systemctl enable --now sshd >/dev/null 2>&1 || \\
    service ssh start >/dev/null 2>&1 || service sshd start >/dev/null 2>&1 || true
echo "SM_ROOTLOGIN $( (sshd -T 2>/dev/null || /usr/sbin/sshd -T 2>/dev/null) | awk '/^permitrootlogin/{{print $2}}')"
for f in /etc/ssh/ssh_host_*_key.pub; do [ -f "$f" ] && echo "SM_HOSTKEY $(cut -d' ' -f1,2 "$f")"; done
ip -4 -o addr show scope global 2>/dev/null | awk '{{print "SM_IP " $4}}'
"""


def parse_key_output(out: str) -> dict:
    res = {"host_keys": [], "ips": [], "root_login": "", "added": "SM_KEY added" in out,
           "sshd_installed": "SM_SSHD installed" in out, "no_sshd": "SM_NO_SSHD" in out}
    for line in out.splitlines():
        if line.startswith("SM_HOSTKEY "):
            k = line[len("SM_HOSTKEY "):].strip()
            if HOSTKEY_RE.match(k):
                res["host_keys"].append(k)
        elif line.startswith("SM_IP "):
            res["ips"].append(line[6:].split("/")[0].strip())
        elif line.startswith("SM_ROOTLOGIN "):
            res["root_login"] = line[len("SM_ROOTLOGIN "):].strip()
    return res


def inject_key_lxc(host_conn, local_node: str, node: str, vmid: int, install_ssh: bool) -> dict:
    """Run the key script in a container via ``pct exec`` on the Proxmox host (or a cluster peer)."""
    if not NODE_RE.match(node or ""):
        raise MgmtError("Ungültiger Node")
    cmd = f"pct exec {int(vmid)} -- /bin/sh -s"
    if node != local_node:
        # cluster nodes trust each other's root keys (/etc/pve/priv/known_hosts)
        cmd = f"ssh -o BatchMode=yes -o ConnectTimeout=10 root@{shlex.quote(node)} {shlex.quote(cmd)}"
    res = host_conn.exec(cmd, root=True, stdin=key_script(install_ssh).encode(), timeout=600)
    out = parse_key_output(res.stdout)
    if out["no_sshd"]:
        raise MgmtError("Im Container ist kein SSH-Server installiert (Installation nicht freigegeben)")
    if not res.ok:
        raise MgmtError(f"pct exec fehlgeschlagen: {(res.stderr or res.stdout).strip()[-300:]}")
    return out


def inject_key_vm(api: PveClient, node: str, vmid: int, install_ssh: bool) -> dict:
    if not api.agent_ping(node, vmid):
        raise MgmtError("QEMU-Guest-Agent antwortet nicht (in der VM installieren und in den VM-Optionen aktivieren)")
    code, out, err = api.agent_exec(node, vmid, key_script(install_ssh), timeout=600)
    parsed = parse_key_output(out)
    if parsed["no_sshd"]:
        raise MgmtError("In der VM ist kein SSH-Server installiert (Installation nicht freigegeben)")
    if code != 0:
        raise MgmtError(f"Guest-Agent-Befehl fehlgeschlagen ({code}): {(err or out).strip()[-300:]}")
    return parsed


def pick_ip(candidates: list[str], prefer: Optional[Callable[[str], bool]] = None) -> str:
    ips = [ip for ip in candidates if ip and not ip.startswith("127.")]
    if prefer:
        for ip in ips:
            if prefer(ip):
                return ip
    return ips[0] if ips else ""
