"""In-process HTTPS mock of the Proxmox VE, RouterOS REST and Pangolin integration APIs.

Only the calls the servermanager uses are implemented - with enough state to
run the complete flows (create container -> DHCP lease -> make static ->
publish in Pangolin) in tests and for manual end-to-end checks:

    python -m tests.mock_apis 8443     # serves https://127.0.0.1:8443 (prints the cert fingerprint)
"""
from __future__ import annotations

import copy
import datetime
import hashlib
import json
import ssl
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from werkzeug.serving import make_server
from werkzeug.wrappers import Request, Response

PVE_TOKEN = "servermanager@pve!sm"
PVE_SECRET = "11111111-2222-3333-4444-555555555555"
ROS_USER, ROS_PASS = "servermanager", "routerpass"
PG_KEY = "pgkey.secret"
MC_KEY = "mc-api-key"
AK_TOKEN = "ak-token"
PG_ORG = "acme"

EXPORT = (Path(__file__).parent / "data" / "chr_export.rsc").read_text()


def make_cert(tmpdir: str) -> tuple[str, str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mock.local")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("mock.local")]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = f"{tmpdir}/cert.pem", f"{tmpdir}/key.pem"
    Path(cert_path).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    Path(key_path).write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                 serialization.NoEncryption()))
    digest = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest().upper()
    return cert_path, key_path, ":".join(digest[i:i + 2] for i in range(0, 64, 2))


# ==========================================================================
class State:
    def __init__(self, legacy_pangolin: bool = False):
        from servermanager import routeros
        self.lock = threading.RLock()
        self.calls: list[tuple[str, str, Any]] = []
        self.legacy_pangolin = legacy_pangolin
        # ---------------- proxmox
        self.guests: dict[int, dict] = {
            100: {"vmid": 100, "name": "newt", "type": "lxc", "node": "pve1", "status": "running", "cpu": 0.02,
                  "maxcpu": 1, "mem": 200 * 2 ** 20, "maxmem": 512 * 2 ** 20, "disk": 1.9 * 2 ** 30,
                  "maxdisk": 2 * 2 ** 30, "uptime": 3600, "netin": 1000, "netout": 2000,
                  "config": {"hostname": "newt", "cores": 1, "memory": 512, "swap": 512, "onboot": 1,
                             "net0": "name=eth0,bridge=vmbr1,hwaddr=BC:24:11:00:00:64,ip=dhcp", "unprivileged": 1,
                             "rootfs": "local-lvm:vm-100-disk-0,size=2G", "ostype": "debian"},
                  "snapshots": [], "ip": "10.20.0.100"},
            101: {"vmid": 101, "name": "wiki", "type": "lxc", "node": "pve1", "status": "running", "cpu": 0.01,
                  "maxcpu": 1, "mem": 100 * 2 ** 20, "maxmem": 512 * 2 ** 20, "disk": 0.5 * 2 ** 30,
                  "maxdisk": 4 * 2 ** 30, "uptime": 100, "netin": 0, "netout": 0,
                  "config": {"hostname": "wiki", "cores": 1, "memory": 512, "onboot": 0, "unprivileged": 1,
                             "net0": "name=eth0,bridge=vmbr4000,hwaddr=BC:24:11:00:00:65,ip=dhcp"},
                  "snapshots": [], "ip": "10.20.0.101"},
            200: {"vmid": 200, "name": "win", "type": "qemu", "node": "pve1", "status": "stopped", "cpu": 0,
                  "maxcpu": 2, "mem": 0, "maxmem": 4 * 2 ** 30, "disk": 0, "maxdisk": 32 * 2 ** 30, "uptime": 0,
                  "config": {"name": "win", "cores": 2, "memory": 4096}, "snapshots": []},
        }
        self.templates = ["local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst"]
        self.backup_jobs: list[dict] = []
        self.networks = {n: [{"iface": "vmbr0", "type": "bridge", "bridge_ports": "enp0s31f6", "active": 1},
                             {"iface": "vmbr1", "type": "bridge", "bridge_ports": "", "active": 1},
                             {"iface": "enp0s31f6", "type": "eth", "active": 1}] for n in ("pve1", "pve2")}
        self.pve_users: dict[str, dict] = {"root@pam": {"userid": "root@pam"}}
        self.acl: list[dict] = []
        self.tokens: dict[str, str] = {}
        self.agent_hostkeys = "SM_HOSTKEY ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockHostKeyForTestsOnly0000000000000000"
        self.tasks: dict[str, dict] = {}
        self.next_task = 1
        # ---------------- routeros
        snap = routeros.parse_export(EXPORT)
        self.ros: dict[str, list[dict]] = {}
        self.ros_seq = 1
        for menu, items in snap["menus"].items():
            self.ros[menu] = []
            for it in items:
                self._ros_add(menu, {k: self._ros_val(v) for k, v in it.items()})
        self._ros_add("ip/dhcp-server/lease", {"address": "10.20.0.100", "mac-address": "BC:24:11:00:00:64",
                                               "host-name": "newt", "server": "dhcp1", "dynamic": "true",
                                               "status": "bound"})
        self.ros["system/resource"] = [{"version": "7.16.1 (stable)", "cpu-load": "3", "free-memory": "800000000",
                                        "total-memory": "1073741824", "uptime": "3d2h", "board-name": "CHR",
                                        "architecture-name": "x86_64"}]
        self.ros["system/ntp/client"] = [{"enabled": "false", "servers": ""}]
        # ---------------- pangolin
        self.sites = [{"siteId": 1, "name": "home-newt", "online": True, "type": "newt", "subnet": "100.89.0.0/30"}]
        self.domains = [{"domainId": "dom1", "baseDomain": "example.com", "verified": True}]
        self.resources: dict[int, dict] = {}
        self.targets: dict[int, dict] = {}
        self.pg_seq = 1
        # ---------------- mailcow
        self.mc_domains = [{"domain_name": "example.com", "active": 1, "mboxes_in_domain": 1, "aliases_in_domain": 0}]
        self.mc_mailboxes = [{"username": "info@example.com", "name": "Info", "domain": "example.com",
                              "local_part": "info", "active": 1, "quota": 1073741824, "quota_used": 1024}]
        self.mc_aliases: list[dict] = []
        self.mc_idp: dict = {}
        # ---------------- authentik
        self.ak_legacy = False
        self.ak_users = [{"pk": 1, "username": "akadmin", "name": "admin", "email": "", "is_active": True,
                          "is_superuser": True, "type": "internal", "groups_obj": []}]
        self.ak_groups = [{"pk": "11111111-aaaa-bbbb-cccc-000000000001", "name": "mitarbeiter", "users": []}]
        self.ak_providers: dict[int, dict] = {}
        self.ak_apps: dict[str, dict] = {}
        self.ak_passwords: dict[int, str] = {}
        self.ak_seq = 10

    @staticmethod
    def _ros_val(v: Any) -> Any:
        return {"yes": "true", "no": "false"}.get(v, v) if isinstance(v, str) else v

    def _ros_add(self, menu: str, item: dict) -> dict:
        item = dict(item)
        item[".id"] = f"*{self.ros_seq:X}"
        self.ros_seq += 1
        item.setdefault("disabled", "false")
        self.ros.setdefault(menu, []).append(item)
        return item

    # ------------------------------------------------------------------ pve tasks
    def task(self, node: str, kind: str, vmid: Any, lines: list[str], on_done=None, duration: float = 0.3) -> str:
        upid = f"UPID:{node}:0000{self.next_task:04X}:00001234:6700{self.next_task:04X}:{kind}:{vmid}:{PVE_TOKEN}:"
        self.next_task += 1
        self.tasks[upid] = {"start": time.time(), "duration": duration, "lines": lines, "done": on_done,
                            "exit": "OK", "finished": False}
        return upid

    def task_state(self, upid: str) -> dict:
        t = self.tasks[upid]
        if not t["finished"] and time.time() - t["start"] >= t["duration"]:
            t["finished"] = True
            if t["done"]:
                t["done"]()
        return t


# ==========================================================================
def _json(data: Any, status: int = 200) -> Response:
    return Response(json.dumps(data), status=status, mimetype="application/json")


def _form(req: Request) -> dict:
    if req.is_json:
        return req.get_json(silent=True) or {}
    return {**req.args.to_dict(), **req.form.to_dict()}


class MockApp:
    def __init__(self, state: State):
        self.s = state

    def __call__(self, environ, start_response):
        req = Request(environ)
        with self.s.lock:
            self.s.calls.append((req.method, req.path, _form(req)))
            if req.path.startswith("/api2/json/"):
                resp = self.pve(req, req.path[len("/api2/json/"):])
            elif req.path.startswith("/rest/"):
                resp = self.ros(req, req.path[len("/rest/"):])
            elif req.path.startswith("/v1/"):
                resp = self.pangolin(req, req.path[len("/v1/"):])
            elif req.path.startswith("/api/v1/"):
                resp = self.mailcow(req, req.path[len("/api/v1/"):])
            elif req.path.startswith("/api/v3/"):
                resp = self.authentik(req, req.path[len("/api/v3/"):])
            else:
                resp = Response("not found", 404)
        return resp(environ, start_response)

    # ------------------------------------------------------------------ proxmox
    def pve(self, req: Request, path: str) -> Response:
        s = self.s
        if path == "access/ticket" and req.method == "POST":
            f0 = _form(req)
            if f0.get("username") == "root@pam" and f0.get("password") == "rootpw":
                return _json({"data": {"ticket": "PVE:root@pam:TICKET", "CSRFPreventionToken": "CSRF1",
                                       "username": "root@pam"}})
            return Response("authentication failure", 401)
        auth = req.headers.get("Authorization", "")
        token_ok = auth == f"PVEAPIToken={PVE_TOKEN}={PVE_SECRET}" or any(
            auth == f"PVEAPIToken={tid}={sec}" for tid, sec in s.tokens.items())
        ticket_ok = req.cookies.get("PVEAuthCookie") == "PVE:root@pam:TICKET" and (
            req.method == "GET" or req.headers.get("CSRFPreventionToken") == "CSRF1")
        if not (token_ok or ticket_ok):
            return Response("no ticket", 401)
        p = path.strip("/").split("/")
        f = _form(req)
        ok = lambda d: _json({"data": d})  # noqa: E731
        if path == "version":
            return ok({"version": "9.0.10", "release": "9.0"})
        if path == "cluster/status":
            return ok([{"type": "node", "name": "pve1", "online": 1}])
        if path == "cluster/nextid":
            return ok(str(max(s.guests) + 1))
        if path == "pools":
            return ok([{"poolid": "kunden"}])
        if path == "access/users":
            if req.method == "POST":
                s.pve_users[f["userid"]] = {"userid": f["userid"]}
                return ok(None)
            return ok(list(s.pve_users.values()))
        if path == "access/acl" and req.method == "PUT":
            s.acl.append(dict(f))
            return ok(None)
        if len(p) == 5 and p[:2] == ["access", "users"] and p[3] == "token" and req.method == "POST":
            tid = f"{p[2]}!{p[4]}"
            s.tokens[tid] = "sec-" + p[4]
            return ok({"full-tokenid": tid, "value": s.tokens[tid]})
        if path == "cluster/backup":
            if req.method == "POST":
                job = {"id": f"backup-{len(s.backup_jobs) + 1}", **f}
                s.backup_jobs.append(job)
                return ok(None)
            return ok(s.backup_jobs)
        if len(p) == 3 and p[:2] == ["cluster", "backup"] and req.method == "PUT":
            for j in s.backup_jobs:
                if j["id"] == p[2]:
                    j.update(f)
            return ok(None)
        if path == "cluster/resources":
            items = [{"type": "node", "node": n, "status": "online", "cpu": 0.05, "maxcpu": 8,
                      "mem": m * 2 ** 30, "maxmem": 32 * 2 ** 30, "disk": 10 * 2 ** 30, "maxdisk": 100 * 2 ** 30,
                      "uptime": 86400} for n, m in (("pve1", 8), ("pve2", 4))] + [
                     {"type": "storage", "node": "pve1", "storage": "local", "status": "available",
                      "disk": 20 * 2 ** 30, "maxdisk": 100 * 2 ** 30, "content": "vztmpl,backup,iso",
                      "plugintype": "dir"},
                     {"type": "storage", "node": "pve1", "storage": "local-lvm", "status": "available",
                      "disk": 40 * 2 ** 30, "maxdisk": 400 * 2 ** 30, "content": "rootdir,images",
                      "plugintype": "lvmthin"}]
            for g in s.guests.values():
                items.append({k: v for k, v in g.items() if k not in ("config", "snapshots", "ip")})
            return ok(items)
        if len(p) < 2 or p[0] != "nodes" or p[1] not in ("pve1", "pve2"):
            return _json({"errors": {"node": "unknown"}}, 400)
        rest = p[2:]
        node = p[1]
        if rest == ["status"]:
            return ok({"cpu": 0.05, "uptime": 86400})
        if rest == ["storage"]:
            content = f.get("content", "")
            st = [{"storage": "local", "content": "vztmpl,backup,iso", "active": 1},
                  {"storage": "local-lvm", "content": "rootdir,images", "active": 1}]
            return ok([x for x in st if not content or content in x["content"]])
        if len(rest) == 3 and rest[0] == "storage" and rest[2] == "content":
            if rest[1] == "local":
                return ok([{"volid": t, "content": "vztmpl"} for t in s.templates])
            return ok([])
        if rest == ["aptinfo"]:
            if req.method == "GET":
                return ok([{"template": "debian-13-standard_13.1-2_amd64.tar.zst", "section": "system",
                            "headline": "Debian 13 (standard)"},
                           {"template": "debian-12-standard_12.7-1_amd64.tar.zst", "section": "system",
                            "headline": "Debian 12"},
                           {"template": "turnkey-nextcloud_18.0-1_amd64.tar.gz", "section": "turnkeylinux"}])
            vol = f"{f['storage']}:vztmpl/{f['template']}"
            return ok(s.task(node, "download", "", [f"downloading {f['template']}", "download finished"],
                             lambda: s.templates.append(vol)))
        if rest == ["network"]:
            if req.method == "POST":
                s.networks[node].append({k: v for k, v in f.items()})
                return ok(None)
            if req.method == "PUT":
                return ok(s.task(node, "srvreload", "", ["ifreload -a"]))
            return ok(s.networks[node])
        if rest == ["rrddata"]:
            return ok(self._rrd(None))
        if rest == ["vzdump"]:
            return ok(s.task(node, "vzdump", f.get("vmid"), ["INFO: starting new backup job", "INFO: Backup finished"]))
        if len(rest) == 3 and rest[0] == "tasks" and rest[2] == "status":
            if rest[1] not in s.tasks:
                return _json({"errors": {"upid": "no such task"}}, 400)
            t = s.task_state(rest[1])
            return ok({"status": "stopped" if t["finished"] else "running",
                       **({"exitstatus": t["exit"]} if t["finished"] else {})})
        if len(rest) == 3 and rest[0] == "tasks" and rest[2] == "log":
            t = s.task_state(rest[1])
            start = int(f.get("start", 0))
            lines = [{"n": i + 1, "t": ln} for i, ln in enumerate(t["lines"])] + \
                    ([{"n": len(t["lines"]) + 1, "t": "TASK OK"}] if t["finished"] else [])
            return ok([ln for ln in lines if ln["n"] > start])
        if len(rest) == 2 and rest[0] == "tasks" and req.method == "DELETE":
            s.tasks[rest[1]]["exit"] = "interrupted by signal"
            s.tasks[rest[1]]["duration"] = 0
            return ok(None)
        if rest and rest[0] in ("lxc", "qemu"):
            gtype = rest[0]
            if len(rest) == 1 and req.method == "POST" and gtype == "lxc":
                vmid = int(f["vmid"])
                if f["ostemplate"] not in s.templates:
                    return _json({"errors": {"ostemplate": "no such template"}}, 500)
                mac = f"BC:24:11:00:{vmid // 256:02X}:{vmid % 256:02X}"
                cfg = {k: v for k, v in f.items() if k not in ("password", "ssh-public-keys", "vmid", "start")}
                cfg["net0"] = f["net0"].replace("name=eth0,", f"name=eth0,hwaddr={mac},")

                def done():
                    s.guests[vmid] = {"vmid": vmid, "name": f["hostname"], "type": "lxc", "node": node,
                                      "status": "stopped", "cpu": 0, "maxcpu": int(f.get("cores", 1)), "mem": 0,
                                      "maxmem": int(f.get("memory", 512)) * 2 ** 20, "disk": 0,
                                      "maxdisk": int(f["rootfs"].split(":")[1]) * 2 ** 30, "uptime": 0,
                                      "config": cfg, "snapshots": [], "ip": "", "mac": mac,
                                      "keys": f.get("ssh-public-keys", "")}
                return ok(s.task(node, "vzcreate", vmid, ["extracting archive", "Creating SSH host keys"], done))
            vmid = int(rest[1])
            g = s.guests.get(vmid)
            if g is not None and g["node"] != node:
                g = None
            if g is None or g["type"] != gtype:
                return _json({"errors": {"vmid": f"CT {vmid} does not exist"}}, 500)
            sub = rest[2:]
            if not sub and req.method == "DELETE":
                return ok(s.task(node, "vzdestroy", vmid, ["destroying"], lambda: s.guests.pop(vmid, None)))
            if sub == ["status", "current"]:
                return ok({**{k: v for k, v in g.items() if k not in ("config", "snapshots")}, "cpus": g["maxcpu"]})
            if len(sub) == 2 and sub[0] == "status" and req.method == "POST":
                op = sub[1]
                new = {"start": "running", "stop": "stopped", "shutdown": "stopped", "reboot": "running",
                       "suspend": "paused", "resume": "running"}[op]

                def done_status():
                    g["status"] = new
                    if new == "running" and g["type"] == "lxc" and not g.get("ip"):
                        g["ip"] = f"10.20.0.{110 + vmid % 50}"
                        s._ros_add("ip/dhcp-server/lease", {"address": g["ip"], "mac-address": g.get("mac", ""),
                                                            "host-name": g["name"], "server": "dhcp1",
                                                            "dynamic": "true", "status": "bound"})
                return ok(s.task(node, f"vz{op}", vmid, [f"{op} {vmid}"], done_status))
            if sub == ["config"]:
                if req.method == "PUT":
                    g["config"].update(f)
                    return ok(None)
                return ok(g["config"])
            if sub == ["rrddata"]:
                return ok(self._rrd(g))
            if sub == ["interfaces"]:
                ifs = [{"name": "lo", "inet": "127.0.0.1/8"}]
                if g.get("ip") and g["status"] == "running":
                    ifs.append({"name": "eth0", "inet": g["ip"] + "/24", "hwaddr": g.get("mac", "")})
                return ok(ifs)
            if sub == ["snapshot"]:
                if req.method == "POST":
                    return ok(s.task(node, "vzsnapshot", vmid, ["snapshot"], lambda: g["snapshots"].append(
                        {"name": f["snapname"], "description": f.get("description", ""), "snaptime": int(time.time())})))
                return ok(g["snapshots"] + [{"name": "current"}])
            if len(sub) >= 2 and sub[0] == "snapshot":
                name = sub[1]
                if req.method == "DELETE":
                    return ok(s.task(node, "vzdelsnapshot", vmid, ["delete"],
                                     lambda: g["snapshots"].__setitem__(slice(None), [x for x in g["snapshots"] if x["name"] != name])))
                return ok(s.task(node, "vzrollback", vmid, ["rollback"]))
            if sub == ["resize"]:
                return ok(s.task(node, "resize", vmid, [f"resize {f.get('size')}"]))
            if sub == ["migrate"]:
                return ok(s.task(node, "vzmigrate", vmid, [f"migrate to {f['target']}"],
                                 lambda: g.__setitem__("node", f["target"])))
            if sub[:1] == ["agent"]:
                if sub == ["agent", "ping"]:
                    return ok(None) if g["config"].get("agent") in (1, "1") else \
                        _json({"errors": {"agent": "QEMU guest agent is not running"}}, 500)
                if sub == ["agent", "exec"]:
                    g["_exec"] = req.form.getlist("command")
                    return ok({"pid": 4711})
                if sub == ["agent", "exec-status"]:
                    return ok({"exited": 1, "exitcode": 0, "out-data": "SM_KEY added\n" + s.agent_hostkeys +
                               "\nSM_ROOTLOGIN prohibit-password\nSM_IP 10.20.0.200/24\n"})
                if sub == ["agent", "network-get-interfaces"]:
                    return ok({"result": [{"name": "eth0", "ip-addresses": [{"ip-address-type": "ipv4",
                                                                              "ip-address": "10.20.0.200"}]}]})
        return _json({"errors": {"path": path}}, 501)

    def _rrd(self, g) -> list[dict]:
        now = int(time.time()) // 60 * 60
        out = []
        for i in range(70):
            t = now - (69 - i) * 60
            out.append({"time": t, "cpu": 0.05 + 0.04 * ((i % 10) / 10), "maxcpu": 1, "mem": (180 + i) * 2 ** 20,
                        "maxmem": 512 * 2 ** 20, "netin": 1000 + 50 * (i % 7), "netout": 2000 + 80 * (i % 5),
                        "disk": 1.2 * 2 ** 30, "maxdisk": 2 * 2 ** 30})
        return out

    # ------------------------------------------------------------------ routeros
    def ros(self, req: Request, path: str) -> Response:
        auth = req.authorization
        s = self.s
        users = {u.get("name"): u.get("password") for u in s.ros.get("user", [])}
        users.setdefault("admin", "adminpw")
        if not auth or (users.get(auth.username) != auth.password
                        and (auth.username, auth.password) != (ROS_USER, ROS_PASS)):
            return _json({"error": 401, "message": "Unauthorized"}, 401)
        path = path.strip("/")
        body = req.get_json(silent=True) or {}
        if req.method == "GET":
            if path in s.ros:
                items = s.ros[path]
                from servermanager.routeros import SINGLETONS
                if path in SINGLETONS:
                    return _json(items[0] if items else {})
                flt = req.args.to_dict()
                return _json([i for i in items if all(i.get(k) == v for k, v in flt.items())])
            menu, _, iid = path.rpartition("/")
            if not iid.startswith("*"):
                return _json([])  # existing but empty menu
            for it in s.ros.get(menu, []):
                if it[".id"] == iid:
                    return _json(it)
            return _json({"error": 404, "message": "Not Found"}, 404)
        if req.method == "PUT":
            item = s._ros_add(path, {k: str(v) for k, v in body.items()})
            return _json(item, 201)
        if req.method == "PATCH":
            menu, _, iid = path.rpartition("/")
            for it in s.ros.get(menu, []):
                if it[".id"] == iid:
                    it.update({k: s._ros_val(str(v)) for k, v in body.items()})
                    return _json(it)
            return _json({"error": 404, "message": "no such item"}, 404)
        if req.method == "DELETE":
            menu, _, iid = path.rpartition("/")
            s.ros[menu] = [it for it in s.ros.get(menu, []) if it[".id"] != iid]
            return Response(status=204)
        # POST = console command
        if path == "ip/dhcp-server/lease/make-static":
            for it in s.ros["ip/dhcp-server/lease"]:
                if it[".id"] == body.get(".id"):
                    it["dynamic"] = "false"
                    return _json([])
            return _json({"error": 400, "message": "no such item"}, 400)
        if path.endswith("/set"):
            menu = path[:-4]
            s.ros.setdefault(menu, [{}])
            s.ros[menu][0].update({k: s._ros_val(str(v)) for k, v in body.items()})
            return _json([])
        if path == "system/backup/save":
            s.ros.setdefault("_backups", []).append({"name": body.get("name")})
            return _json([])
        if path == "export":
            return _json([])
        if path == "ping":
            return _json([{"seq": "0", "sent": "1", "received": "1"}, {"sent": "3", "received": "3", "avg-rtt": "5ms"}])
        return _json({"error": 400, "message": f"no such command {path}"}, 400)

    # ------------------------------------------------------------------ pangolin
    def pangolin(self, req: Request, path: str) -> Response:
        if req.headers.get("Authorization") != f"Bearer {PG_KEY}":
            return _json({"error": True, "message": "Unauthorized", "status": 401}, 401)
        s = self.s
        p = path.strip("/").split("/")
        body = req.get_json(silent=True) or {}

        def ok(d, status=200):
            return _json({"data": d, "success": True, "error": False, "message": "ok", "status": status}, status)

        def err(msg, status=400):
            return _json({"data": None, "success": False, "error": True, "message": msg, "status": status}, status)

        if p[:2] == ["org", PG_ORG]:
            rest = p[2:]
            if rest == ["sites"]:
                return ok({"sites": s.sites, "pagination": {"total": len(s.sites)}})
            if rest == ["domains"]:
                return ok({"domains": s.domains, "pagination": {"total": len(s.domains)}})
            if rest == ["resources"]:
                return ok({"resources": list(s.resources.values()), "pagination": {"total": len(s.resources)}})
            if rest == ["resource"] and req.method == "PUT":
                if s.legacy_pangolin:
                    return err("Not Found", 404)
                return ok(self._pg_create(body), 201)
            if len(rest) == 3 and rest[0] == "site" and rest[2] == "resource" and req.method == "PUT":
                return ok(self._pg_create({**body, "siteId": int(rest[1])}), 201)
            return err("Not Found", 404)
        if p[0] == "resource" and len(p) >= 2:
            rid = int(p[1])
            res = s.resources.get(rid)
            if res is None:
                return err("Resource not found", 404)
            if len(p) == 2:
                if req.method == "GET":
                    return ok(res)
                if req.method == "POST":
                    res.update(body)
                    return ok(res)
                if req.method == "DELETE":
                    s.resources.pop(rid)
                    return ok(None)
            if p[2:] == ["target"] and req.method == "PUT":
                if s.legacy_pangolin and "siteId" in body:
                    return err("Unrecognized key(s) in object: 'siteId'", 400)
                if body.get("port") == 9:
                    return err("Target rejected", 400)
                tid = s.pg_seq
                s.pg_seq += 1
                s.targets[tid] = {"targetId": tid, "resourceId": rid, **body}
                return ok(s.targets[tid], 201)
            if p[2:] == ["targets"]:
                return ok({"targets": [t for t in s.targets.values() if t["resourceId"] == rid]})
        if p[0] == "target" and len(p) == 2 and req.method == "DELETE":
            s.targets.pop(int(p[1]), None)
            return ok(None)
        return err("Not Found", 404)

    # ------------------------------------------------------------------ mailcow
    def mailcow(self, req: Request, path: str) -> Response:
        if req.headers.get("X-API-Key") != MC_KEY:
            return _json({"type": "error", "msg": "authentication failed"}, 401)
        s = self.s
        body = req.get_json(silent=True)
        ok = lambda m: _json([{"type": "success", "log": [], "msg": m}])  # noqa: E731
        danger = lambda m: _json([{"type": "danger", "log": [], "msg": m}])  # noqa: E731
        if path == "get/status/version":
            return _json({"version": "2025-03"})
        if path == "get/domain/all":
            return _json(s.mc_domains)
        if path == "get/mailbox/all":
            return _json(s.mc_mailboxes)
        if path == "get/alias/all":
            return _json(s.mc_aliases)
        if path == "get/identity-provider":
            return _json(s.mc_idp)
        if path == "add/mailbox":
            addr = f"{body['local_part']}@{body['domain']}"
            if body["domain"] not in {d["domain_name"] for d in s.mc_domains}:
                return danger(["domain_not_found", body["domain"]])
            if any(m["username"] == addr for m in s.mc_mailboxes):
                return danger(["object_exists", addr])
            s.mc_mailboxes.append({"username": addr, "name": body.get("name"), "domain": body["domain"],
                                   "local_part": body["local_part"], "active": int(body.get("active", 1)),
                                   "quota": int(body.get("quota", 0)) * 1024 * 1024, "quota_used": 0,
                                   "_password": body["password"]})
            return ok(["mailbox_added", addr])
        if path == "edit/mailbox":
            for m in s.mc_mailboxes:
                if m["username"] in body["items"]:
                    attr = body["attr"]
                    if "active" in attr:
                        m["active"] = int(attr["active"])
                    if "password" in attr:
                        m["_password"] = attr["password"]
            return ok(["mailbox_modified"])
        if path == "delete/mailbox":
            s.mc_mailboxes = [m for m in s.mc_mailboxes if m["username"] not in body]
            return ok(["mailbox_removed"])
        if path == "add/alias":
            s.mc_aliases.append({"id": len(s.mc_aliases) + 1, "address": body["address"], "goto": body["goto"],
                                 "active": 1})
            return ok(["alias_added"])
        if path == "delete/alias":
            s.mc_aliases = [a for a in s.mc_aliases if str(a["id"]) not in body]
            return ok(["alias_removed"])
        if path == "edit/identity-provider":
            s.mc_idp = dict(body["attr"])
            return ok(["object_modified"])
        return _json({"type": "error", "msg": "route not found"}, 404)

    # ------------------------------------------------------------------ authentik
    def authentik(self, req: Request, path: str) -> Response:
        if req.headers.get("Authorization") != f"Bearer {AK_TOKEN}":
            return _json({"detail": "Token invalid/expired"}, 403)
        s = self.s
        body = req.get_json(silent=True) or {}
        p = path.strip("/").split("/")

        def page(items):
            return _json({"pagination": {"next": 0, "count": len(items)}, "results": items})
        if path == "admin/version/":
            return _json({"version_current": "2025.2.1"})
        if path == "flows/instances/":
            d = req.args.get("designation")
            flows = {"authorization": [{"pk": "flow-auth", "slug": "default-provider-authorization-implicit-consent"}],
                     "invalidation": [] if s.ak_legacy else [{"pk": "flow-inv", "slug": "default-provider-invalidation-flow"}]}
            return page(flows.get(d, []))
        if path == "propertymappings/provider/scope/":
            if s.ak_legacy:
                return _json({"detail": "Not found."}, 404)
            return page([{"pk": f"pm-{i}", "managed": m} for i, m in enumerate(
                ["goauthentik.io/providers/oauth2/scope-openid", "goauthentik.io/providers/oauth2/scope-email",
                 "goauthentik.io/providers/oauth2/scope-profile", "goauthentik.io/providers/oauth2/scope-offline_access"])])
        if path == "propertymappings/scope/":
            return page([{"pk": "pm-old", "managed": "goauthentik.io/providers/oauth2/scope-openid"}])
        if path == "crypto/certificatekeypairs/":
            return page([{"pk": "cert-1", "name": "authentik Self-signed Certificate"}])
        if path == "providers/oauth2/" and req.method == "POST":
            ru = body.get("redirect_uris")
            if s.ak_legacy and not isinstance(ru, str):
                return _json({"redirect_uris": ["Not a valid string."]}, 400)
            s.ak_seq += 1
            prov = {"pk": s.ak_seq, **body, "client_id": f"cid{s.ak_seq}", "client_secret": f"csec{s.ak_seq}"}
            s.ak_providers[s.ak_seq] = prov
            return _json(prov, 201)
        if p[:2] == ["providers", "oauth2"] and len(p) == 3 and req.method == "DELETE":
            if s.ak_providers.pop(int(p[2]), None) is None:
                return _json({"detail": "Not found."}, 404)
            return Response(status=204)
        if path == "core/applications/":
            if req.method == "POST":
                s.ak_apps[body["slug"]] = dict(body)
                return _json(body, 201)
            return page(list(s.ak_apps.values()))
        if p[:2] == ["core", "applications"] and len(p) == 3 and req.method == "DELETE":
            if s.ak_apps.pop(p[2], None) is None:
                return _json({"detail": "Not found."}, 404)
            return Response(status=204)
        if path == "core/users/":
            if req.method == "POST":
                if any(u["username"] == body["username"] for u in s.ak_users):
                    return _json({"username": ["This field must be unique."]}, 400)
                s.ak_seq += 1
                u = {"pk": s.ak_seq, **body, "is_superuser": False, "type": "internal", "groups_obj": []}
                s.ak_users.append(u)
                return _json(u, 201)
            return page(s.ak_users)
        if path == "core/groups/":
            return page(s.ak_groups)
        if p[:2] == ["core", "groups"] and len(p) == 4 and p[3] == "add_user":
            g = next(x for x in s.ak_groups if x["pk"] == p[2])
            g["users"].append(body["pk"])
            return Response(status=204)
        if p[:2] == ["core", "users"] and len(p) >= 3:
            pk = int(p[2])
            u = next((x for x in s.ak_users if x["pk"] == pk), None)
            if u is None:
                return _json({"detail": "Not found."}, 404)
            if len(p) == 4 and p[3] == "set_password":
                s.ak_passwords[pk] = body["password"]
                return Response(status=204)
            if req.method == "PATCH":
                u.update(body)
                return _json(u)
            if req.method == "DELETE":
                s.ak_users.remove(u)
                return Response(status=204)
        return _json({"detail": "Not found."}, 404)

    def _pg_create(self, body: dict) -> dict:
        s = self.s
        rid = s.pg_seq
        s.pg_seq += 1
        dom = next((d["baseDomain"] for d in s.domains if d["domainId"] == body.get("domainId")), "")
        full = (f"{body['subdomain']}.{dom}" if body.get("subdomain") else dom) if body.get("http") else None
        res = {"resourceId": rid, "name": body["name"], "subdomain": body.get("subdomain"), "fullDomain": full,
               "http": bool(body.get("http")), "protocol": body.get("protocol"), "proxyPort": body.get("proxyPort"),
               "ssl": True, "sso": True, "enabled": True, "siteId": body.get("siteId"), "domainId": body.get("domainId")}
        s.resources[rid] = res
        return copy.deepcopy(res)


# ==========================================================================
class MockServer:
    def __init__(self, port: int = 0, legacy_pangolin: bool = False):
        self.tmp = tempfile.mkdtemp()
        cert, key, self.fingerprint = make_cert(self.tmp)
        self.state = State(legacy_pangolin=legacy_pangolin)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        self.server = make_server("127.0.0.1", port, MockApp(self.state), threaded=True, ssl_context=ctx)
        self.port = self.server.server_port
        self.url = f"https://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> "MockServer":
        self.thread.start()
        return self

    def stop(self) -> None:
        self.server.shutdown()


if __name__ == "__main__":
    import sys
    srv = MockServer(int(sys.argv[1]) if len(sys.argv) > 1 else 8443).start()
    print(f"Mock-APIs auf {srv.url}\nFingerabdruck: {srv.fingerprint}\n"
          f"Proxmox: {PVE_TOKEN} / {PVE_SECRET}\nRouterOS: {ROS_USER} / {ROS_PASS}\nPangolin: org {PG_ORG}, key {PG_KEY}",
          flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        srv.stop()
