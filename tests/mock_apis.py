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
            200: {"vmid": 200, "name": "win", "type": "qemu", "node": "pve1", "status": "stopped", "cpu": 0,
                  "maxcpu": 2, "mem": 0, "maxmem": 4 * 2 ** 30, "disk": 0, "maxdisk": 32 * 2 ** 30, "uptime": 0,
                  "config": {"name": "win", "cores": 2, "memory": 4096}, "snapshots": []},
        }
        self.templates = ["local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst"]
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
            else:
                resp = Response("not found", 404)
        return resp(environ, start_response)

    # ------------------------------------------------------------------ proxmox
    def pve(self, req: Request, path: str) -> Response:
        if req.headers.get("Authorization") != f"PVEAPIToken={PVE_TOKEN}={PVE_SECRET}":
            return Response("no ticket", 401)
        s = self.s
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
        if path == "cluster/resources":
            items = [{"type": "node", "node": "pve1", "status": "online", "cpu": 0.05, "maxcpu": 8,
                      "mem": 8 * 2 ** 30, "maxmem": 32 * 2 ** 30, "disk": 10 * 2 ** 30, "maxdisk": 100 * 2 ** 30,
                      "uptime": 86400},
                     {"type": "storage", "node": "pve1", "storage": "local", "status": "available",
                      "disk": 20 * 2 ** 30, "maxdisk": 100 * 2 ** 30, "content": "vztmpl,backup,iso",
                      "plugintype": "dir"},
                     {"type": "storage", "node": "pve1", "storage": "local-lvm", "status": "available",
                      "disk": 40 * 2 ** 30, "maxdisk": 400 * 2 ** 30, "content": "rootdir,images",
                      "plugintype": "lvmthin"}]
            for g in s.guests.values():
                items.append({k: v for k, v in g.items() if k not in ("config", "snapshots", "ip")})
            return ok(items)
        if len(p) < 2 or p[0] != "nodes" or p[1] != "pve1":
            return _json({"errors": {"node": "unknown"}}, 400)
        rest = p[2:]
        node = "pve1"
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
            return ok([{"iface": "vmbr0", "type": "bridge"}, {"iface": "vmbr1", "type": "bridge"},
                       {"iface": "eno1", "type": "eth"}])
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
        if not auth or auth.username != ROS_USER or auth.password != ROS_PASS:
            return _json({"error": 401, "message": "Unauthorized"}, 401)
        s = self.s
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
