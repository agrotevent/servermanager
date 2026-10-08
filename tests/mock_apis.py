"""In-process HTTPS mock of the Proxmox VE, RouterOS REST and Pangolin integration APIs.

Only the calls the servermanager uses are implemented - with enough state to
run the complete flows (create container -> DHCP lease -> make static ->
publish in Pangolin) in tests and for manual end-to-end checks:

    python -m tests.mock_apis 8443     # serves https://127.0.0.1:8443 (prints the cert fingerprint)
"""
from __future__ import annotations

import base64
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
ZBX_TOKEN = "zbx-token-123"
ISP_USER, ISP_PASS = "servermanager", "IspPass1234567890abcdef"
ZAM_TOKEN = "zam-token-xyz"
PG_KEY = "pgkey.secret"
MC_KEY = "mc-api-key"
AK_TOKEN = "ak-token"
PG_ORG = "acme"
HZ_USER, HZ_PASS = "#ws+test", "robot-secret"
HC_TOKEN, HC_RO_TOKEN = "hc-rw-token", "hc-ro-token"
NC_USER, NC_PASS = "ncadmin", "Nc-App-Pass-12345"
HD_KEY = "hd-api-key-123"
INWX_USER, INWX_PASS, INWX_TOTP = "inwx-api", "Inwx-Pass-123", "JBSWY3DPEHPK3PXP"

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
        self.pve_domains: dict[str, dict] = {"pam": {"realm": "pam", "type": "pam"},
                                             "pve": {"realm": "pve", "type": "pve"}}
        self.pve_old = False          # Proxmox before 8.1: no groups claim for OpenID realms
        self.pve_no_realm_perm = False
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
        self.pg_idps: dict[int, dict] = {}
        self.pg_idp_policies: dict[tuple[int, str], dict] = {}
        self.pg_idp_forbidden = False
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
        self.ak_bindings: list[dict] = []
        self.ak_passwords: dict[int, str] = {}
        self.ak_seq = 10
        # ---------------- hetzner robot
        self.hz_servers = [
            {"server_ip": "88.99.10.1", "server_ipv6_net": "2a01:4f8:10:1::", "server_number": 321,
             "server_name": "pve-fsn", "product": "AX42", "dc": "FSN1-DC14", "traffic": "unlimited",
             "status": "ready", "cancelled": False, "paid_until": "2026-12-31", "ip": ["88.99.10.1", "88.99.10.7"],
             "subnet": [{"ip": "2a01:4f8:10:1::", "mask": "64"}]},
            {"server_ip": "5.9.20.2", "server_ipv6_net": "2a01:4f8:20:2::", "server_number": 654,
             "server_name": "", "product": "EX44", "dc": "NBG1-DC3", "traffic": "30 GB", "status": "ready",
             "cancelled": True, "paid_until": "2026-10-31", "ip": ["5.9.20.2"], "subnet": []}]
        self.hz_ips = {ip: {"ip": ip, "server_ip": s["server_ip"], "server_number": s["server_number"],
                            "locked": False, "separate_mac": None, "traffic_warnings": False, "traffic_hourly": 200,
                            "traffic_daily": 2000, "traffic_monthly": 20}
                       for s in self.hz_servers for ip in s["ip"]}
        self.hz_rdns = {"88.99.10.1": "pve-fsn.example.com", "2a01:4f8:10:1::2": "mail.example.com"}
        self.hz_resets: list[tuple[int, str]] = []
        self.hz_reject_subnets: set[str] = set()      # subnets the traffic query refuses
        self.hz_notfound_subnets: set[str] = set()    # subnets without traffic data (404 NOT_FOUND)
        self.hz_vswitches = [{"id": 50301, "name": "pve-lan", "vlan": 4001, "cancelled": False,
                              "server": [{"server_number": 321, "server_ip": "88.99.10.1",
                                          "server_ipv6_net": "2a01:4f8:10:1::", "status": "ready"},
                                         {"server_number": 654, "server_ip": "5.9.20.2",
                                          "server_ipv6_net": "2a01:4f8:20:2::", "status": "failed"}],
                              "subnet": [{"ip": "88.99.200.0", "mask": 29, "gateway": "88.99.200.1"},
                                         {"ip": "2a01:4f8:fff0:53::", "mask": 64, "gateway": "2a01:4f8:fff0:53::1"}],
                              "cloud_network": [{"id": 9, "ip": "10.1.0.0", "mask": 24, "gateway": "10.1.0.1"}]}]
        self.hz_traffic_queries: list[dict] = []
        # ---------------- hetzner cloud
        self.hc_servers = [
            {"id": 1001, "name": "web-1", "status": "running", "created": "2026-01-01T00:00:00+00:00",
             "public_net": {"ipv4": {"ip": "49.12.0.10", "dns_ptr": "static.10.0.12.49.clients.your-server.de",
                                     "blocked": False},
                            "ipv6": {"ip": "2a01:4f8:c0c:1::/64", "blocked": False,
                                     "dns_ptr": [{"ip": "2a01:4f8:c0c:1::1", "dns_ptr": "web-1.example.com"}]},
                            "floating_ips": [77]},
             "private_net": [{"network": 5, "ip": "10.0.0.2"}],
             "server_type": {"name": "cx32", "cores": 4, "memory": 8.0, "disk": 80},
             "datacenter": {"name": "fsn1-dc14", "location": {"name": "fsn1", "city": "Falkenstein"}},
             "image": {"name": "debian-13", "description": "Debian 13"}, "protection": {"delete": True},
             "locked": False, "rescue_enabled": False, "backup_window": None, "labels": {},
             "outgoing_traffic": 300 * 1024 ** 3, "ingoing_traffic": 20 * 1024 ** 3,
             "included_traffic": 20 * 1024 ** 4},
            {"id": 1002, "name": "db-1", "status": "off", "created": "2026-01-01T00:00:00+00:00",
             "public_net": {"ipv4": {"ip": "49.12.0.11", "dns_ptr": "", "blocked": False},
                            "ipv6": {"ip": "2a01:4f8:c0c:2::/64", "dns_ptr": [], "blocked": False}, "floating_ips": []},
             "private_net": [], "server_type": {"name": "cx22"}, "datacenter": {"name": "nbg1-dc3",
                                                                               "location": {"city": "Nürnberg"}},
             "image": None, "protection": {"delete": False}, "locked": False, "labels": {},
             "outgoing_traffic": 19 * 1024 ** 4, "ingoing_traffic": 0, "included_traffic": 20 * 1024 ** 4}]
        self.hc_floating = [{"id": 77, "name": "mail-ip", "ip": "78.46.0.5", "type": "ipv4", "server": 1001,
                             "dns_ptr": [{"ip": "78.46.0.5", "dns_ptr": "mail.example.com"}], "blocked": False}]
        self.hc_actions: list[tuple] = []
        # ---------------- nextcloud (OCS)
        self.nc_groups = ["admin", "Buchhaltung", "Mitarbeiter", "Vertrieb Nord"]
        self.nc_users = {
            "ncadmin": {"id": "ncadmin", "enabled": True, "displayname": "NC Admin", "email": "admin@example.com",
                        "groups": ["admin"], "quota": {"used": 1000, "quota": -3}, "lastLogin": 1760000000000,
                        "backend": "Database"},
            "anna": {"id": "anna", "enabled": True, "displayname": "Anna Beispiel", "email": "anna@example.com",
                     "groups": ["Mitarbeiter", "Buchhaltung"], "quota": {"used": 9 * 1024 ** 3,
                                                                         "quota": 10 * 1024 ** 3},
                     "lastLogin": 1760000000000, "backend": "Database"},
            "bernd": {"id": "bernd", "enabled": True, "displayname": "Bernd", "email": "",
                      "groups": ["Mitarbeiter", "Vertrieb Nord"], "quota": {"used": 0, "quota": "default"},
                      "lastLogin": 0, "backend": "Database"},
            "carl.old": {"id": "carl.old", "enabled": False, "displayname": "Carl", "email": "carl@example.com",
                         "groups": ["Mitarbeiter"], "quota": {"used": 0, "quota": "none"}, "lastLogin": 0,
                         "backend": "Database"}}
        self.nc_passwords: dict[str, str] = {}
        # ---------------- hosting.de platform (FRESH Internet)
        self.hd_seq = 100
        self.hd_zones = {
            "example.com": {"zoneConfig": {"id": "zc-example", "name": "example.com", "nameUnicode": "example.com",
                                           "status": "active", "type": "NATIVE", "soaValues": {"ttl": 3600}},
                            "records": [
                                {"id": "r1", "name": "example.com", "type": "NS", "content": "ns1.hosting.de", "ttl": 86400},
                                {"id": "r2", "name": "example.com", "type": "A", "content": "203.0.113.5", "ttl": 3600},
                                {"id": "r3", "name": "example.com", "type": "TXT", "content": '"v=spf1 mx -all"', "ttl": 3600},
                                {"id": "r4", "name": "www.example.com", "type": "CNAME", "content": "example.com", "ttl": 3600},
                                {"id": "r5", "name": "example.com", "type": "MX", "content": "mx.other.net", "priority": 10, "ttl": 3600}]},
            "setnetz.de": {"zoneConfig": {"id": "zc-setnetz", "name": "setnetz.de", "nameUnicode": "setnetz.de",
                                          "status": "active", "type": "NATIVE"},
                           "records": [{"id": "r9", "name": "*.setnetz.de", "type": "CNAME", "content": "pangolin.setnetz.de", "ttl": 3600}]}}
        self.hd_domains = [
            {"name": "example.com", "nameUnicode": "example.com", "status": "active", "transferLockEnabled": True,
             "currentContractPeriodEnd": "2027-03-01T00:00:00Z", "nameservers": [{"name": "ns1.hosting.de"}]},
            {"name": "alt-domain.de", "nameUnicode": "alt-domain.de", "status": "active", "transferLockEnabled": False,
             "currentContractPeriodEnd": "2026-10-20T00:00:00Z", "deletionDate": "2026-10-20T00:00:00Z",
             "nameservers": [{"name": "ns1.hosting.de"}]}]
        self.hd_updates: list[dict] = []
        # ---------------- INWX
        self.inwx_tfa = False
        self.inwx_sessions: dict[str, bool] = {}    # session id -> unlocked
        self.inwx_seq = 500
        self.inwx_zones = {"inwx-kunde.de": [
            {"id": 401, "name": "inwx-kunde.de", "type": "SOA", "content": "ns.inwx.de hostmaster.inwx.de 2026", "TTL": 86400, "prio": 0},
            {"id": 402, "name": "inwx-kunde.de", "type": "A", "content": "198.51.100.7", "TTL": 3600, "prio": 0}]}
        self.inwx_domains = [{"domain": "inwx-kunde.de", "status": "OK", "exDate": "2026-10-30 00:00:00",
                              "renewalMode": "AUTORENEW", "ns": ["ns.inwx.de", "ns2.inwx.de"], "transferLock": 1}]
        self.inwx_logins = 0
        self.mc_dkim = {"example.com": {"dkim_selector": "dkim", "length": "2048",
                                        "dkim_txt": "v=DKIM1;k=rsa;t=s;s=email;p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtest"}}
        self.ak_codes: dict[str, dict] = {}     # code -> {"user", "challenge", "nonce", "client_id", "redirect"}
        self.ak_tokens: dict[str, dict] = {}    # access token -> user info

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
            elif req.path.startswith("/dash/"):  # dashboard / login proxy in front: 401 for API calls
                resp = (Response("<html>Login</html>", 404, content_type="text/html") if "/docs" in req.path
                        else _json({"message": "Unauthorized"}, 401))
            elif req.path.startswith("/v1/"):
                resp = self.pangolin(req, req.path[len("/v1/"):])
            elif req.path.startswith("/api/v1/cti/"):
                if req.headers.get("Authorization"):
                    resp = _json({"error": "credentials must not be sent to the CTI endpoint"}, 400)
                elif req.path.rsplit("/", 1)[-1] != "cti-token-123":
                    resp = _json({"error": "Not authorized"}, 401)
                else:
                    self.s.__dict__.setdefault("cti", []).append(dict(req.form))
                    resp = _json({})
            elif req.path.startswith("/api/v1/") and req.headers.get("Authorization", "").startswith("Token "):
                resp = self.zammad(req, req.path[len("/api/v1/"):])
            elif req.path.startswith("/api/v1/"):
                resp = self.mailcow(req, req.path[len("/api/v1/"):])
            elif req.path.startswith("/api/v3/"):
                resp = self.authentik(req, req.path[len("/api/v3/"):])
            elif req.path.startswith("/hcloud/v1/"):
                resp = self.hcloud(req, req.path[len("/hcloud/v1/"):])
            elif req.path.startswith("/robot/"):
                resp = self.robot(req, req.path[len("/robot/"):])
            elif req.path.startswith("/application/o/"):
                resp = self.authentik_oauth(req, req.path[len("/application/o/"):])
            elif req.path.startswith("/api/dns/v1/json/") or req.path.startswith("/api/domain/v1/json/"):
                resp = self.hostingde(req, req.path.split("/")[2], req.path.rsplit("/", 1)[-1])
            elif req.path == "/jsonrpc/":
                resp = self.inwx(req)
            elif req.path.startswith("/ocs/v2.php/"):
                resp = self.nextcloud(req, req.path[len("/ocs/v2.php/"):])
            elif req.path == "/zabbix/api_jsonrpc.php":
                resp = self.zabbix(req)
            elif req.path == "/remote/json.php":
                resp = self.ispconfig(req)
            else:
                resp = Response("not found", 404)
        return resp(environ, start_response)

    # ------------------------------------------------------------------ hosting.de platform
    def hostingde(self, req: Request, service: str, method: str) -> Response:
        s = self.s
        body = req.get_json(silent=True) or {}

        def ok(resp: Any) -> Response:
            return _json({"errors": [], "metadata": {}, "warnings": [], "status": "success", "response": resp})

        def err(code: int, text: str, value: str = "") -> Response:
            return _json({"errors": [{"code": code, "text": text, "value": value}], "status": "error",
                          "response": None})

        def page(rows: list) -> Response:
            lim, pg = int(body.get("limit") or 25), int(body.get("page") or 1)
            total = max(1, -(-len(rows) // lim))
            return ok({"data": rows[(pg - 1) * lim: pg * lim], "limit": lim, "page": pg, "totalEntries": len(rows),
                       "totalPages": total, "type": "FindResult"})
        if body.get("authToken") != HD_KEY:
            return err(10109, "Authentication failed", "authToken")
        flt = body.get("filter") or {}
        if service == "dns" and method == "zoneConfigsFind":
            return page([z["zoneConfig"] for z in s.hd_zones.values()])
        if service == "dns" and method == "zonesFind":
            name = str(flt.get("value") or "").lower()
            return page([z for n, z in s.hd_zones.items() if not name or n == name])
        if service == "dns" and method == "zoneUpdate":
            name = (body.get("zoneConfig") or {}).get("name")
            z = s.hd_zones.get(name)
            if z is None:
                return err(10300, "Zone not found", name or "")
            s.hd_updates.append(body)
            recs = z["records"]
            for d in body.get("recordsToDelete") or []:
                before = len(recs)
                recs[:] = [r for r in recs if not (r["id"] == d.get("id") or (
                    r["name"] == d["name"] and r["type"] == d["type"] and r["content"] == d["content"]))]
                if len(recs) == before:
                    return err(10310, "Record not found", d.get("name", ""))
            for m in body.get("recordsToModify") or []:
                r = next((x for x in recs if x["id"] == m.get("id")), None)
                if r is None:
                    return err(10310, "Record not found", m.get("id", ""))
                r.update({k: v for k, v in m.items() if k != "id"})
            for a in body.get("recordsToAdd") or []:
                if a["type"] == "TXT" and not a["content"].startswith('"'):
                    return err(10320, "TXT record content must be quoted", a["content"])
                s.hd_seq += 1
                recs.append({**a, "id": f"r{s.hd_seq}"})
            return ok({"zoneConfig": z["zoneConfig"], "records": recs})
        if service == "domain" and method == "domainsFind":
            return page(list(s.hd_domains))
        return err(10000, "Unknown method", method)

    # ------------------------------------------------------------------ INWX (JSON-RPC)
    def inwx(self, req: Request) -> Response:
        import pyotp
        s = self.s
        body = req.get_json(silent=True) or {}
        method, params = body.get("method", ""), body.get("params") or {}

        def res(code: int = 1000, msg: str = "Command completed successfully", data: Any = None, cookie: str = ""):
            r = _json({"code": code, "msg": msg, **({"resData": data} if data is not None else {})})
            if cookie:
                r.set_cookie("domrobot", cookie)
            return r
        if method == "account.login":
            if params.get("user") != INWX_USER or params.get("pass") != INWX_PASS:
                return res(2200, "Authentication error")
            s.inwx_logins += 1
            sid = f"sess{s.inwx_logins}"
            s.inwx_sessions[sid] = not s.inwx_tfa
            return res(data={"customerId": 1, "accountId": 2, "tfa": "GOOGLE-AUTH" if s.inwx_tfa else "0"}, cookie=sid)
        sid = req.cookies.get("domrobot", "")
        if sid not in s.inwx_sessions:
            return res(2200, "Authentication error")
        if method == "account.unlock":
            if not pyotp.TOTP(INWX_TOTP).verify(str(params.get("tan")), valid_window=1):
                return res(2200, "Authentication error", data={})
            s.inwx_sessions[sid] = True
            return res()
        if not s.inwx_sessions[sid]:
            return res(2200, "Authentication error")
        if method == "nameserver.list":
            return res(data={"count": len(s.inwx_zones), "domains": [{"domain": d, "roId": i + 1, "type": "MASTER"}
                                                                    for i, d in enumerate(sorted(s.inwx_zones))]})
        if method == "nameserver.info":
            recs = s.inwx_zones.get(params.get("domain"))
            if recs is None:
                return res(2303, "Object does not exist")
            return res(data={"domain": params["domain"], "count": len(recs), "record": recs})
        if method == "nameserver.createRecord":
            recs = s.inwx_zones.get(params.get("domain"))
            if recs is None:
                return res(2303, "Object does not exist")
            s.inwx_seq += 1
            recs.append({"id": s.inwx_seq, "name": params["name"], "type": params["type"], "content": params["content"],
                         "TTL": params.get("ttl", 3600), "prio": params.get("prio", 0)})
            return res(data={"id": s.inwx_seq})
        if method in ("nameserver.updateRecord", "nameserver.deleteRecord"):
            for recs in s.inwx_zones.values():
                r = next((x for x in recs if x["id"] == params.get("id")), None)
                if r is not None:
                    if method == "nameserver.deleteRecord":
                        recs.remove(r)
                    else:
                        r.update({"name": params.get("name", r["name"]), "type": params.get("type", r["type"]),
                                  "content": params.get("content", r["content"]), "TTL": params.get("ttl", r["TTL"]),
                                  "prio": params.get("prio", r["prio"])})
                    return res()
            return res(2303, "Object does not exist")
        if method == "domain.list":
            return res(data={"count": len(s.inwx_domains), "domain": s.inwx_domains})
        return res(2000, "Unknown command")

    # ------------------------------------------------------------------ nextcloud (OCS v2)
    def nextcloud(self, req: Request, path: str) -> Response:
        s = self.s

        def ok(data: Any = None) -> Response:
            return _json({"ocs": {"meta": {"status": "ok", "statuscode": 200, "message": "OK"}, "data": data or []}})

        def fail(status: int, msg: str) -> Response:
            return _json({"ocs": {"meta": {"status": "failure", "statuscode": status, "message": msg}, "data": []}},
                         status)
        auth = req.authorization
        if req.headers.get("OCS-APIRequest") != "true":
            return fail(401, "CSRF check failed")
        if auth is None or auth.username != NC_USER or auth.password != NC_PASS:
            return Response("", 401)
        f = {**req.form.to_dict(), "groups[]": req.form.getlist("groups[]")}
        p = path.strip("/").split("/")
        if path == "apps/serverinfo/api/v1/info":
            return ok({"nextcloud": {"system": {"version": "31.0.9.1", "freespace": 500 * 1024 ** 3,
                                                "apps": {"num_installed": 60, "num_updates_available": 1,
                                                         "app_updates": {"calendar": "5.5.1"}},
                                                "update": {"available": True, "available_version": "32.0.0"}},
                                     "storage": {"num_users": len(s.nc_users), "num_files": 1234},
                                     "shares": {"num_shares": 7}},
                       "server": {"webserver": "Apache", "php": {"version": "8.3.6"},
                                  "database": {"type": "mysql", "version": "10.11.6"}},
                       "activeUsers": {"last5minutes": 1, "last1hour": 2, "last24hours": 3}})
        if path == "cloud/users/details":
            off, lim = int(req.args.get("offset", 0)), int(req.args.get("limit", 500))
            keys = sorted(s.nc_users)[off:off + lim]
            return ok({"users": {k: s.nc_users[k] for k in keys}})
        if path == "cloud/groups/details":
            return ok({"groups": [{"id": g_, "displayname": g_, "disabled": False,
                                   "usercount": sum(1 for u in s.nc_users.values() if g_ in u["groups"])}
                                  for g_ in s.nc_groups]})
        if path == "cloud/groups" and req.method == "POST":
            if f.get("groupid") in s.nc_groups:
                return fail(400, "group exists")
            s.nc_groups.append(f["groupid"])
            return ok()
        if path == "cloud/users" and req.method == "POST":
            uid = f.get("userid", "")
            if uid in s.nc_users:
                return fail(400, "User already exists")
            for g_ in f["groups[]"]:
                if g_ not in s.nc_groups:
                    return fail(400, "group " + g_ + " does not exist")
            s.nc_users[uid] = {"id": uid, "enabled": True, "displayname": f.get("displayName", uid),
                               "email": f.get("email", ""), "groups": f["groups[]"],
                               "quota": {"used": 0, "quota": f.get("quota") or "default"}, "lastLogin": 0,
                               "backend": "Database"}
            s.nc_passwords[uid] = f.get("password", "")
            return ok({"id": uid})
        if p[:2] == ["cloud", "users"] and len(p) >= 3:
            u = s.nc_users.get(p[2])
            if u is None:
                return fail(404, "User does not exist")
            if len(p) == 3 and req.method == "GET":
                return ok(u)
            if len(p) == 3 and req.method == "DELETE":
                del s.nc_users[p[2]]
                return ok()
            if len(p) == 3 and req.method == "PUT":
                key, value = f.get("key"), f.get("value", "")
                if key == "password":
                    s.nc_passwords[p[2]] = value
                elif key == "quota":
                    u["quota"]["quota"] = value
                elif key in ("displayname", "email"):
                    u[key] = value
                else:
                    return fail(400, "unknown key")
                return ok()
            if len(p) == 4 and p[3] in ("enable", "disable") and req.method == "PUT":
                u["enabled"] = p[3] == "enable"
                return ok()
            if len(p) == 4 and p[3] == "groups":
                gid = f.get("groupid", "")
                if gid not in s.nc_groups:
                    return fail(400, "group does not exist")
                if req.method == "POST" and gid not in u["groups"]:
                    u["groups"].append(gid)
                elif req.method == "DELETE" and gid in u["groups"]:
                    u["groups"].remove(gid)
                return ok()
        return fail(404, "not found")

    # ------------------------------------------------------------------ zammad
    def zammad(self, req: Request, path: str) -> Response:
        s = self.s
        z = s.__dict__.setdefault("zam", {
            "seq": 100, "tickets": {}, "articles": [], "tags": [], "webhooks": [], "triggers": [],
            "users": [{"id": 3, "login": "servermanager-api", "email": "api@example.com", "active": True},
                      {"id": 5, "login": "tk-admin", "email": "tk-admin@example.com", "active": True}],
            "states": [{"id": 1, "name": "new"}, {"id": 2, "name": "open"}, {"id": 4, "name": "closed"}]})
        if req.headers.get("Authorization") != f"Token token={ZAM_TOKEN}":
            return _json({"error": "Invalid token!"}, 401)
        body = req.get_json(silent=True) or {}
        path = path.strip("/")

        def new_id() -> int:
            z["seq"] += 1
            return z["seq"]
        if path == "users/me":
            return _json(z["users"][0])
        settings = z.setdefault("settings", [
            {"id": 1, "name": "fqdn", "state_current": {"value": "support.example.com"}},
            {"id": 2, "name": "http_type", "state_current": {"value": "https"}},
            {"id": 3, "name": "auth_saml", "state_current": {"value": False}},
            {"id": 4, "name": "auth_openid_connect", "state_current": {"value": False}},
            {"id": 5, "name": "auth_openid_connect_credentials", "state_current": {"value": {}}},
            {"id": 6, "name": "auth_third_party_auto_link_at_inital_login", "state_current": {"value": False}}])
        if path == "settings":
            if z.get("no_admin"):
                return _json({"error": "Not authorized (user)!"}, 403)
            return _json([x for x in settings if not z.get("old_version") or x["name"] != "auth_openid_connect"])
        if path.startswith("settings/") and req.method == "PUT":
            row = next((x for x in settings if x["id"] == int(path.split("/")[1])), None)
            if row is None or body.get("name") != row["name"]:
                return _json({"error": "not found"}, 404)
            row["state_current"] = body["state_current"]
            return _json(row)
        if path == "users/search":
            q = req.args.get("query", "")
            return _json([u for u in z["users"] if q and q in u["email"]])
        if path == "groups":
            return _json([{"id": 1, "name": "Users", "active": True}, {"id": 2, "name": "Technik", "active": True}])
        if path == "ticket_states":
            return _json(z["states"])
        if path == "tickets" and req.method == "POST":
            if body.get("group") not in ("Users", "Technik"):
                return _json({"error": "No such group"}, 422)
            tid = new_id()
            t = {"id": tid, "number": f"3100{tid}", "title": body["title"], "group": body["group"],
                 "customer_id": body["customer_id"], "priority": body["priority"], "state": body["state"],
                 "owner_id": 1}
            z["tickets"][tid] = t
            z["articles"].append(dict(body["article"], ticket_id=tid))
            return _json(t, 201)
        if path.startswith("tickets/"):
            tid = int(path.split("/")[1])
            if tid not in z["tickets"]:
                return _json({"error": "Not found"}, 404)
            if req.method == "PUT":
                z["tickets"][tid].update(body)
            return _json(z["tickets"][tid])
        if path == "ticket_articles":
            z["articles"].append(body)
            return _json(dict(body, id=new_id()), 201)
        if path == "tags/add":
            z["tags"].append((body["o_id"], body["item"]))
            return _json(True, 201)
        for coll in ("webhooks", "triggers"):
            if path == coll:
                if req.method == "GET":
                    return _json(z[coll])
                item = dict(body, id=new_id())
                z[coll].append(item)
                return _json(item, 201)
            if path.startswith(coll + "/") and req.method == "PUT":
                item = next(i for i in z[coll] if i["id"] == int(path.split("/")[1]))
                item.update(body)
                return _json(item)
        return _json({"error": f"unknown {path}"}, 404)

    # ------------------------------------------------------------------ ispconfig
    def ispconfig(self, req: Request) -> Response:
        s = self.s
        st = s.__dict__.setdefault("isp", {
            "users": {ISP_USER: ISP_PASS}, "sessions": set(), "seq": 10,
            "clients": [{"client_id": "1", "company_name": "Muster GmbH", "contact_name": "Max Muster",
                         "username": "muster", "email": "max@muster.de", "locked": "n", "canceled": "n"}],
            "sites": [{"domain_id": "3", "domain": "muster.de", "type": "vhost", "active": "y", "ssl": "y",
                       "ssl_letsencrypt": "y", "php": "php-fpm", "sys_groupid": "2", "hd_quota": "-1",
                       "document_root": "/var/www/clients/client1/web1"},
                      {"domain_id": "4", "domain": "alias.muster.de", "type": "alias", "active": "y"}],
            "mail_domains": [{"domain_id": "5", "domain": "muster.de", "server_id": "1", "sys_groupid": "2",
                              "active": "y", "dkim": "y"}],
            "mail_users": [{"mailuser_id": "7", "email": "info@muster.de", "name": "Info", "quota": "1073741824",
                            "sys_groupid": "2", "disableimap": "n", "disablesmtp": "n"}],
            "dns": [{"id": "9", "origin": "muster.de.", "ns": "ns1.muster.de.", "serial": "2026092601",
                     "active": "Y", "dnssec_wanted": "N"}],
            "dbs": [{"database_id": "11", "database_name": "c1_wp", "type": "mysql", "active": "y",
                     "remote_access": "n"}],
            "calls": []})
        function = req.query_string.decode()
        body = req.get_json(silent=True, force=True) or {}
        st["calls"].append((function, body))

        def ok(resp):
            return _json({"code": "ok", "message": "", "response": resp})

        def fail(msg):
            return _json({"code": "remote_fault", "message": msg, "response": False}, 500)
        if function == "login":
            if st["users"].get(body.get("username")) != body.get("password"):
                return fail("The login failed. Username or password wrong.")
            sid = f"sess{len(st['sessions']) + 1}"
            st["sessions"].add(sid)
            return ok(sid)
        if body.get("session_id") not in st["sessions"]:
            return fail("The session ID is empty or wrong.")
        if function == "logout":
            st["sessions"].discard(body["session_id"])
            return ok(True)
        tables = {"client_get": "clients", "sites_web_domain_get": "sites", "mail_domain_get": "mail_domains",
                  "mail_user_get": "mail_users", "dns_zone_get": "dns", "sites_database_get": "dbs"}
        if function in tables:
            # like json.php: arguments are matched by the PHP parameter name (client_get($session_id, $client_id))
            key = "client_id" if function == "client_get" else "primary_id"
            if not isinstance(body.get(key), (int, list, dict)):
                return fail("The ID must be either an integer or an array.")
            return ok(st[tables[function]] if body.get(key) == -1 else [])
        if function == "server_get_app_version":
            return ok({"ispc_app_version": "3.2.12p1", "ispc_app_version_major": "3"})
        if function == "server_get_all":
            return ok([{"server_id": "1", "server_name": "web01.muster.de"}])
        if function == "client_get_by_groupid":
            return ok({"client_id": "1"} if body.get("group_id") == 2 else False)
        if function == "sites_web_domain_update":
            site = next(w for w in st["sites"] if w["domain_id"] == str(body["primary_id"]))
            site.update(body["params"])
            return ok(1)
        if function == "mail_user_add":
            st["seq"] += 1
            st["mail_users"].append(dict(body["params"], mailuser_id=str(st["seq"]), sys_groupid="2",
                                         _client_id=body.get("client_id")))
            return ok(st["seq"])
        if function == "mail_user_update":
            box = next(b for b in st["mail_users"] if b["mailuser_id"] == str(body["primary_id"]))
            box.update(body["params"])
            return ok(1)
        if function == "mail_user_delete":
            st["mail_users"] = [b for b in st["mail_users"] if b["mailuser_id"] != str(body["primary_id"])]
            return ok(1)
        if function == "client_add":
            st["seq"] += 1
            st["clients"].append(dict(body["params"], client_id=str(st["seq"])))
            return ok(st["seq"])
        return fail(f"You do not have the permissions to access this function ({function}).")

    # ------------------------------------------------------------------ zabbix
    def zabbix(self, req: Request) -> Response:
        s = self.s
        z = s.__dict__.setdefault("zbx", {
            "seq": 100, "hostgroups": [{"groupid": "2", "name": "Linux servers"}],
            "templates": [{"templateid": "10001", "host": "Linux by Zabbix agent", "name": "Linux by Zabbix agent"}],
            "hosts": [], "problems": [], "triggers": {}, "acks": [], "mediatypes": [], "usergroups": [],
            "users": [], "actions": [], "roles": [{"roleid": "1", "name": "User role", "type": "1"},
                                                  {"roleid": "3", "name": "Super admin role", "type": "3"}]})
        body = req.get_json(silent=True, force=True) or {}
        method, params, rid = body.get("method"), body.get("params") or {}, body.get("id")

        def ok(result):
            return _json({"jsonrpc": "2.0", "result": result, "id": rid})

        def err(data, code=-32602):
            return _json({"jsonrpc": "2.0", "error": {"code": code, "message": "Invalid params.", "data": data},
                          "id": rid})
        if method == "apiinfo.version":
            return ok(z.get("version", "7.0.5"))
        if req.headers.get("Authorization") != f"Bearer {ZBX_TOKEN}":
            return err("Not authorized.", -32602)

        def new_id() -> str:
            z["seq"] += 1
            return str(z["seq"])

        def by_name(coll, key="name"):
            names = (params.get("filter") or {}).get(key)
            items = z[coll]
            return [i for i in items if names is None or i.get(key) in names]
        obj, _, op = method.partition(".")
        colls = {"hostgroup": ("hostgroups", "groupid"), "mediatype": ("mediatypes", "mediatypeid"),
                 "usergroup": ("usergroups", "usrgrpid"), "user": ("users", "userid"),
                 "action": ("actions", "actionid")}
        if obj in colls:
            coll, idk = colls[obj]
            if op == "get":
                return ok(by_name(coll, "username" if obj == "user" else "name"))
            if op == "create":
                item = dict(params, **{idk: new_id()})
                z[coll].append(item)
                return ok({idk + "s": [item[idk]]})
            if op == "update":
                item = next(i for i in z[coll] if i[idk] == params[idk])
                item.update(params)
                return ok({idk + "s": [item[idk]]})
        if method == "role.get":
            return ok(z["roles"])
        if method == "template.get":
            return ok(by_name("templates"))
        if method == "host.get":
            hosts = [h for h in z["hosts"] if not (params.get("filter") or {}).get("host")
                     or h["host"] in params["filter"]["host"]]
            out = []
            for h in hosts:
                h2 = dict(h)
                h2["hostgroups"] = [g for g in z["hostgroups"] if g["groupid"] in {x["groupid"] for x in h["groups"]}]
                h2["parentTemplates"] = [t for t in z["templates"]
                                         if t["templateid"] in {x["templateid"] for x in h.get("templates", [])}]
                out.append(h2)
            return ok(out)
        if method == "host.create":
            if any(h["host"] == params["host"] for h in z["hosts"]):
                return err("Host already exists.")
            h = dict(params, hostid=new_id(), status="0")
            h["interfaces"] = [dict(i, interfaceid=new_id(), available="0") for i in params["interfaces"]]
            z["hosts"].append(h)
            return ok({"hostids": [h["hostid"]]})
        if method == "host.update":
            h = next(h for h in z["hosts"] if h["hostid"] == params["hostid"])
            h.update(params)
            return ok({"hostids": [h["hostid"]]})
        if method in ("hostinterface.update", "hostinterface.create"):
            return ok({"interfaceids": [params.get("interfaceid") or new_id()]})
        if method == "problem.get":
            return ok([p for p in z["problems"] if int(p["severity"]) in params.get("severities", range(6))])
        if method == "trigger.get":
            return ok([z["triggers"][t] for t in params["triggerids"] if t in z["triggers"]])
        if method == "event.acknowledge":
            ev = params["eventids"][0]
            prob = next((p for p in z["problems"] if p["eventid"] == ev), None)
            if params["action"] & 1:
                trig = z["triggers"].get(prob["objectid"]) if prob else None
                if not trig or trig.get("manual_close") != "1":
                    return err("Cannot close problem: trigger does not allow manual closing.")
                z["problems"].remove(prob)
            z["acks"].append(params)
            return ok({"eventids": [ev]})
        return err(f"unknown method {method}", -32601)

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
        if p[:2] == ["access", "domains"]:
            if s.pve_no_realm_perm and req.method != "GET":
                return Response("Permission check failed (/access/realm, Realm.Allocate)", 403)
            if len(p) == 2 and req.method == "GET":
                return ok(list(s.pve_domains.values()))
            if len(p) == 2 and req.method == "POST":
                if s.pve_old and "groups-claim" in f:
                    return _json({"data": None, "errors": {"groups-claim": "property is not defined in schema"}},
                                 400)
                if f["realm"] in s.pve_domains:
                    return _json({"data": None, "errors": {"realm": "domain already exists"}}, 400)
                s.pve_domains[f["realm"]] = dict(f)
                return ok(None)
            if len(p) == 3:
                d = s.pve_domains.get(p[2])
                if d is None:
                    return _json({"data": None, "message": f"domain '{p[2]}' does not exist"}, 500)
                if req.method == "PUT":
                    d.update(f)
                    return ok(None)
                if req.method == "DELETE":
                    s.pve_domains.pop(p[2])
                    return ok(None)
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
            if body.get("address") in s.ros.get("_unreachable", []):
                n = body.get("count", "3")
                return _json([{"seq": "0", "sent": "1", "received": "0", "status": "timeout"},
                              {"sent": n, "received": "0", "packet-loss": "100", "status": "timeout"}])
            return _json([{"seq": "0", "sent": "1", "received": "1"}, {"sent": "3", "received": "3", "avg-rtt": "5ms"}])
        return _json({"error": 400, "message": f"no such command {path}"}, 400)

    # ------------------------------------------------------------------ pangolin
    def pangolin(self, req: Request, path: str) -> Response:
        if path.startswith("docs"):  # Swagger UI of the integration API (no authentication)
            return Response("<!doctype html><html><head><title>Swagger UI</title></head></html>",
                            content_type="text/html")
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
        if p[0] == "idp":
            if s.pg_idp_forbidden:
                return err("Key does not have permission", 403)
            if p == ["idp"] and req.method == "GET":
                return ok({"idps": list(s.pg_idps.values()), "pagination": {"total": len(s.pg_idps)}})
            if p == ["idp", "oidc"] and req.method == "PUT":
                iid = s.pg_seq
                s.pg_seq += 1
                s.pg_idps[iid] = {"idpId": iid, "type": "oidc", **body}
                return ok({"idpId": iid, "redirectUrl": f"https://pangolin.example.com/auth/idp/{iid}/oidc/callback"},
                          201)
            iid = int(p[1])
            if iid not in s.pg_idps:
                return err("IdP not found", 404)
            if p[2:] == ["oidc"] and req.method == "POST":
                s.pg_idps[iid].update(body)
                return ok(None)
            if len(p) == 2 and req.method == "DELETE":
                s.pg_idps.pop(iid)
                return ok(None)
            if len(p) == 4 and p[2] == "org" and req.method == "PUT":
                s.pg_idp_policies[(iid, p[3])] = body
                return ok(None, 201)
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
        if path.startswith("get/dkim/"):
            return _json(s.mc_dkim.get(path.split("/", 2)[2], {}))
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
                    if "quota" in attr:
                        if int(attr["quota"]) > 10240:
                            return danger(["mailbox_quota_exceeded", "10240"])
                        m["quota"] = int(attr["quota"]) * 1024 * 1024
                    if "name" in attr:
                        m["name"] = attr["name"]
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
                if body["slug"] in s.ak_apps:
                    return _json({"slug": ["Application with this slug already exists."]}, 400)
                s.ak_seq += 1
                s.ak_apps[body["slug"]] = {"provider": None, **body, "pk": f"app-{s.ak_seq}",
                                           "pbm_uuid": f"app-{s.ak_seq}"}
                return _json(s.ak_apps[body["slug"]], 201)
            # like authentik: the list only shows applications the token user may access
            return page([a for a in s.ak_apps.values()
                         if not any(b["target"] == a.get("pbm_uuid") for b in s.ak_bindings)])
        if p[:2] == ["core", "applications"] and len(p) == 3 and req.method in ("GET", "PATCH"):
            a = s.ak_apps.get(p[2])
            if a is None:
                return _json({"detail": "Not found."}, 404)
            if req.method == "PATCH":
                a.update(body)
            return _json(a)
        if path == "policies/bindings/":
            if req.method == "POST":
                s.ak_seq += 1
                b = {"pk": f"bind-{s.ak_seq}", "policy": None, "user": None, **body}
                s.ak_bindings.append(b)
                return _json(b, 201)
            return page([b for b in s.ak_bindings if b["target"] == req.args.get("target")])
        if p[:2] == ["policies", "bindings"] and len(p) == 3 and req.method == "DELETE":
            s.ak_bindings[:] = [b for b in s.ak_bindings if b["pk"] != p[2]]
            return Response(status=204)
        if p[:2] == ["core", "applications"] and len(p) == 3 and req.method == "DELETE":
            a = s.ak_apps.pop(p[2], None)
            if a is None:
                return _json({"detail": "Not found."}, 404)
            s.ak_bindings[:] = [b for b in s.ak_bindings if b["target"] != a.get("pbm_uuid")]
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
            if req.method == "POST":
                if any(x["name"] == body["name"] for x in s.ak_groups):
                    return _json({"name": ["group with this name already exists."]}, 400)
                s.ak_seq += 1
                grp = {"pk": f"22222222-aaaa-bbbb-cccc-{s.ak_seq:012d}", "name": body["name"],
                       "is_superuser": bool(body.get("is_superuser")), "users": list(body.get("users") or [])}
                s.ak_groups.append(grp)
                return _json(grp, 201)
            return page(s.ak_groups)
        if p[:2] == ["core", "groups"] and len(p) == 4 and p[3] == "add_user":
            g = next(x for x in s.ak_groups if x["pk"] == p[2])
            g["users"].append(body["pk"])
            return Response(status=204)
        if p[:2] == ["core", "groups"] and len(p) == 3:
            g = next((x for x in s.ak_groups if x["pk"] == p[2]), None)
            if g is None:
                return _json({"detail": "Not found."}, 404)
            if req.method == "PATCH":
                unknown = [x for x in body.get("users", []) if not any(u["pk"] == x for u in s.ak_users)]
                if unknown:
                    return _json({"users": [f"Invalid pk \"{unknown[0]}\" - object does not exist."]}, 400)
                g.update(body)
            return _json(g)
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

    def hcloud(self, req: Request, path: str) -> Response:
        s = self.s
        token = req.headers.get("Authorization", "").removeprefix("Bearer ")
        if token not in (HC_TOKEN, HC_RO_TOKEN):
            return _json({"error": {"code": "unauthorized", "message": "unable to authenticate"}}, 401)
        if req.method != "GET" and token == HC_RO_TOKEN:
            return _json({"error": {"code": "forbidden", "message": "insufficient permissions"}}, 403)
        p = path.strip("/").split("/")
        body = req.get_json(silent=True) or {}

        def page(key, items):  # one item per page to exercise the pagination
            n = int(req.args.get("page", 1))
            nxt = n + 1 if n < len(items) else None
            return _json({key: items[n - 1:n], "meta": {"pagination": {"page": n, "per_page": 1, "next_page": nxt,
                                                                          "total_entries": len(items)}}})
        srv = {x["id"]: x for x in s.hc_servers}

        def action(cmd):
            return _json({"action": {"id": len(s.hc_actions), "command": cmd, "status": "running"}}, 201)
        if p == ["servers"]:
            return page("servers", s.hc_servers)
        if p == ["floating_ips"]:
            return page("floating_ips", s.hc_floating)
        if p[0] == "servers" and len(p) >= 2:
            x = srv.get(int(p[1]))
            if x is None:
                return _json({"error": {"code": "not_found", "message": "server not found"}}, 404)
            if len(p) == 2 and req.method == "PUT":
                x["name"] = body.get("name", x["name"])
                return _json({"server": x})
            if p[2:] == ["metrics"]:
                start = int(__import__("datetime").datetime.fromisoformat(req.args["start"]).timestamp())
                step = int(req.args["step"])
                vals = [[start + i * step, str(10 + i)] for i in range(6)]
                return _json({"metrics": {"start": req.args["start"], "end": req.args["end"], "step": step,
                                          "time_series": {"cpu": {"values": vals},
                                                          "network.0.bandwidth.in": {"values": vals},
                                                          "network.0.bandwidth.out": {"values": vals}}}})
            if len(p) == 4 and p[2] == "actions":
                if p[3] == "change_dns_ptr":
                    s.hc_actions.append((x["id"], "ptr", body.get("ip"), body.get("dns_ptr")))
                    v4 = x["public_net"]["ipv4"]
                    if body.get("ip") == v4["ip"]:
                        v4["dns_ptr"] = body.get("dns_ptr") or ""
                    else:
                        lst = x["public_net"]["ipv6"]["dns_ptr"]
                        lst[:] = [e for e in lst if e["ip"] != body.get("ip")]
                        if body.get("dns_ptr"):
                            lst.append({"ip": body["ip"], "dns_ptr": body["dns_ptr"]})
                    return action("change_dns_ptr")
                if p[3] in ("reboot", "reset", "shutdown", "poweron", "poweroff"):
                    s.hc_actions.append((x["id"], p[3]))
                    return action(p[3])
        if p[0] == "floating_ips" and len(p) == 4 and p[3] == "change_dns_ptr":
            f = next((x for x in s.hc_floating if x["id"] == int(p[1])), None)
            if f is None:
                return _json({"error": {"code": "not_found", "message": "floating ip not found"}}, 404)
            s.hc_actions.append((f["id"], "fptr", body.get("ip"), body.get("dns_ptr")))
            f["dns_ptr"] = [{"ip": body["ip"], "dns_ptr": body.get("dns_ptr") or ""}]
            return action("change_dns_ptr")
        return _json({"error": {"code": "not_found", "message": "not found"}}, 404)

    def robot(self, req: Request, path: str) -> Response:
        s = self.s
        auth = req.authorization
        if not auth or auth.username != HZ_USER or auth.password != HZ_PASS:
            return _json({"error": {"status": 401, "code": "UNAUTHORIZED", "message": "Unauthorized"}}, 401)
        p = path.strip("/").split("/")
        f = req.form

        def err(status, code, msg="error"):
            return _json({"error": {"status": status, "code": code, "message": msg}}, status)
        srv = {x["server_number"]: x for x in s.hz_servers}
        if p == ["server"]:
            return _json([{"server": x} for x in s.hz_servers])
        if p[0] == "server" and len(p) == 2:
            x = srv.get(int(p[1]))
            if x is None:
                return err(404, "SERVER_NOT_FOUND")
            if req.method == "POST":
                x["server_name"] = f.get("server_name", "")
            return _json({"server": x})
        if p == ["ip"]:
            return _json([{"ip": x} for x in s.hz_ips.values()])
        if p[0] == "ip" and len(p) == 2 and req.method == "POST":
            x = s.hz_ips.get(p[1])
            if x is None:
                return err(404, "IP_NOT_FOUND")
            x["traffic_warnings"] = f.get("traffic_warnings") == "true"
            for k in ("traffic_hourly", "traffic_daily", "traffic_monthly"):
                if k in f:
                    x[k] = int(f[k])
            return _json({"ip": x})
        if p == ["subnet"]:
            subs = [{"ip": n["ip"], "mask": int(n["mask"]), "gateway": "fe80::1", "server_ip": x["server_ip"],
                     "server_number": x["server_number"], "failover": False, "locked": False,
                     "traffic_warnings": False, "traffic_hourly": 0, "traffic_daily": 0, "traffic_monthly": 0}
                    for x in s.hz_servers for n in x["subnet"]]
            return _json([{"subnet": n} for n in subs]) if subs else err(404, "SUBNET_NOT_FOUND")
        if p == ["rdns"]:
            if not s.hz_rdns:
                return err(404, "RDNS_NOT_FOUND")
            return _json([{"rdns": {"ip": k, "ptr": v}} for k, v in s.hz_rdns.items()])
        if p[0] == "rdns" and len(p) == 2:
            if req.method in ("POST", "PUT"):
                if not f.get("ptr"):
                    return _json({"error": {"status": 400, "code": "INVALID_INPUT", "message": "invalid input",
                                            "missing": ["ptr"], "invalid": None}}, 400)
                s.hz_rdns[p[1]] = f["ptr"]
                return _json({"rdns": {"ip": p[1], "ptr": f["ptr"]}})
            if req.method == "DELETE":
                if s.hz_rdns.pop(p[1], None) is None:
                    return err(404, "RDNS_NOT_FOUND")
                return Response(status=200)
        if p == ["vswitch"]:
            return _json([{k: v[k] for k in ("id", "name", "vlan", "cancelled")} for v in s.hz_vswitches])
        if p[0] == "vswitch" and len(p) == 2:
            v = next((x for x in s.hz_vswitches if x["id"] == int(p[1])), None)
            return _json(v) if v else err(404, "NOT_FOUND")
        if p == ["reset"]:
            return _json([{"reset": {"server_ip": x["server_ip"], "server_number": x["server_number"],
                                     "type": ["sw", "hw", "man"] if x["server_number"] == 321 else ["hw", "man"]}}
                          for x in s.hz_servers])
        if p[0] == "reset" and len(p) == 2 and req.method == "POST":
            if len(s.hz_resets) >= 50:
                return _json({"error": {"status": 403, "code": "RATE_LIMIT_EXCEEDED", "message": "rate limit",
                                        "max_request": 50, "interval": 3600}}, 403)
            s.hz_resets.append((int(p[1]), f.get("type", "")))
            return _json({"reset": {"server_ip": srv[int(p[1])]["server_ip"], "type": f.get("type")}})
        if p[0] == "wol" and len(p) == 2 and req.method == "POST":
            s.hz_resets.append((int(p[1]), "wol"))
            return _json({"wol": {"server_ip": srv[int(p[1])]["server_ip"], "server_number": int(p[1])}})
        if p == ["traffic"] and req.method == "POST":
            q = {"type": f.get("type"), "from": f.get("from"), "to": f.get("to"), "ip": f.getlist("ip[]"),
                 "subnet": f.getlist("subnet[]"), "single_values": f.get("single_values")}
            s.hz_traffic_queries.append(q)
            if any(n in s.hz_notfound_subnets for n in q["subnet"]):
                return err(404, "NOT_FOUND", "Not Found")
            bad = [n for n in q["subnet"] if "/" in n or n in s.hz_reject_subnets]
            if bad:  # Robot wants the bare network address and refuses some subnets
                return _json({"error": {"status": 400, "code": "INVALID_INPUT", "message": "invalid input",
                                        "missing": None, "invalid": ["subnet"]}}, 400)
            slots = ["01", "02", "03"] if q["type"] != "year" else ["01", "02"]
            data = {a: {sl: {"in": 1.5, "out": 10.0, "sum": 11.5} for sl in slots} for a in q["ip"]}
            data.update({n.split("/")[0]: {sl: {"in": 0.5, "out": 1.0, "sum": 1.5} for sl in slots}
                         for n in q["subnet"]})
            return _json({"traffic": {"type": q["type"], "from": q["from"], "to": q["to"], "data": data}})
        return err(404, "NOT_FOUND")

    def authentik_oauth(self, req: Request, path: str) -> Response:
        s = self.s
        if path == "token/" and req.method == "POST":
            if req.headers.get("Authorization"):
                return _json({"error": "invalid_request", "error_description": "API token sent"}, 400)
            f = req.form
            c = s.ak_codes.pop(f.get("code", ""), None)
            prov = next((p for p in s.ak_providers.values() if p["client_id"] == f.get("client_id")), None)
            if not c or not prov or prov["client_secret"] != f.get("client_secret") \
                    or c["client_id"] != f.get("client_id") or c["redirect"] != f.get("redirect_uri"):
                return _json({"error": "invalid_grant"}, 400)
            digest = hashlib.sha256(f.get("code_verifier", "").encode()).digest()
            if base64.urlsafe_b64encode(digest).rstrip(b"=").decode() != c["challenge"]:
                return _json({"error": "invalid_grant", "error_description": "PKCE"}, 400)
            info = {"sub": c["user"]["sub"], "preferred_username": c["user"]["username"],
                    "name": c["user"].get("name", ""), "email": c["user"].get("email", ""),
                    "groups": c["user"].get("groups", [])}
            access = f"at-{len(s.ak_tokens) + 1}"
            s.ak_tokens[access] = info

            def b64(d):
                return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
            claims = {"sub": info["sub"], "aud": c.get("aud", f.get("client_id")), "nonce": c["nonce"]}
            return _json({"access_token": access, "token_type": "Bearer",
                          "id_token": f"{b64({'alg': 'RS256'})}.{b64(claims)}.sig"})
        if path == "userinfo/":
            info = s.ak_tokens.get(req.headers.get("Authorization", "").removeprefix("Bearer "))
            return _json(info) if info else _json({"error": "invalid_token"}, 401)
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
