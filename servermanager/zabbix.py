"""Zabbix JSON-RPC API (6.0 LTS - 7.x): hosts, problems, acknowledgements, ticket webhook setup."""
from __future__ import annotations

import secrets
import string
from typing import Any, Optional
from urllib.parse import urlsplit

import requests

from . import tlspin

SEVERITIES = {0: "Nicht klassifiziert", 1: "Information", 2: "Warnung", 3: "Durchschnitt", 4: "Hoch",
              5: "Katastrophe"}
SEVERITY_CLASS = {0: "", 1: "info", 2: "warning", 3: "warning", 4: "danger", 5: "danger"}
MEDIA_NAME = "Servermanager Tickets"
GROUP_NAME = "Servermanager Tickets"
USER_NAME = "servermanager-tickets"
ACTION_NAME = "Servermanager: Probleme als Tickets"
# Zabbix acknowledge actions (bit mask)
ACK_CLOSE, ACK_ACK, ACK_MESSAGE = 1, 2, 4

WEBHOOK_SCRIPT = """var p = JSON.parse(value);
var req = new HttpRequest();
req.addHeader('Content-Type: application/json');
req.addHeader('Authorization: Bearer ' + p.Token);
var body = {};
for (var k in p) {
    if (k !== 'Token' && k !== 'URL') {
        body[k] = p[k];
    }
}
var resp = req.post(p.URL, JSON.stringify(body));
if (req.getStatus() < 200 || req.getStatus() > 299) {
    throw 'Servermanager: HTTP ' + req.getStatus() + ' ' + resp;
}
return 'OK';
"""
WEBHOOK_PARAMS = [
    ("event_id", "{EVENT.ID}"), ("event_value", "{EVENT.VALUE}"), ("event_update_status", "{EVENT.UPDATE.STATUS}"),
    ("event_name", "{EVENT.NAME}"), ("severity", "{EVENT.NSEVERITY}"), ("host", "{HOST.HOST}"),
    ("host_name", "{HOST.NAME}"), ("host_ip", "{HOST.IP}"), ("trigger_id", "{TRIGGER.ID}"),
    ("event_time", "{EVENT.DATE} {EVENT.TIME}"), ("opdata", "{EVENT.OPDATA}"),
    ("update_message", "{EVENT.UPDATE.MESSAGE}"), ("update_user", "{USER.FULLNAME}"),
]


class ZabbixError(Exception):
    def __init__(self, message: str, code: int = 0):
        super().__init__(message)
        self.code = code


def normalize_url(url: str) -> str:
    url = (url or "").strip().rstrip("/")
    if not url:
        raise ZabbixError("Keine API-Adresse angegeben")
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ZabbixError("Ungültige API-Adresse")
    if parts.username or parts.password:
        raise ZabbixError("Zugangsdaten gehören nicht in die Adresse")
    path = parts.path.rstrip("/")
    if not path.endswith("api_jsonrpc.php"):
        path = path + "/api_jsonrpc.php"
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://{parts.hostname}{port}{path}"


def version_tuple(v: str) -> tuple[int, int]:
    try:
        major, minor = v.split(".")[:2]
        return int(major), int(minor)
    except (ValueError, AttributeError):
        return 0, 0


class Zabbix:
    def __init__(self, url: str, token: str, fingerprint: str = "", verify_ca: bool = True, timeout: int = 20):
        self.url = normalize_url(url)
        self.token = (token or "").strip()
        if not self.token:
            raise ZabbixError("Kein API-Token hinterlegt")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.verify = verify_ca
        if fingerprint and self.url.startswith("https://"):
            try:
                adapter = tlspin.PinnedAdapter(fingerprint)
            except tlspin.PinError as exc:
                raise ZabbixError(str(exc)) from exc
            self.session.verify = False
            parts = urlsplit(self.url)
            self.session.mount(f"https://{parts.netloc}/", adapter)
        self._id = 0
        self._version: Optional[str] = None

    # ------------------------------------------------------------------ raw
    def call(self, method: str, params: Any = None, auth: bool = True) -> Any:
        self._id += 1
        body: dict = {"jsonrpc": "2.0", "method": method, "params": params if params is not None else {},
                      "id": self._id}
        headers = {"Content-Type": "application/json-rpc"}
        if auth:
            if version_tuple(self.version()) >= (6, 4):
                headers["Authorization"] = f"Bearer {self.token}"
            else:
                body["auth"] = self.token
        try:
            r = self.session.post(self.url, json=body, headers=headers, timeout=self.timeout, allow_redirects=False)
        except requests.exceptions.SSLError as exc:
            raise ZabbixError(tlspin.tls_message(self.url, exc)) from exc
        except requests.RequestException as exc:
            raise ZabbixError(f"Zabbix-API nicht erreichbar ({self.url}): {exc}") from exc
        try:
            j = r.json()
        except ValueError:
            raise ZabbixError(f"Zabbix: keine JSON-Antwort (HTTP {r.status_code}) – ist {self.url} die API-Adresse "
                              "(…/api_jsonrpc.php)?", r.status_code) from None
        if "error" in j:
            err = j["error"] or {}
            data = str(err.get("data") or "")
            msg = f"{err.get('message', 'Fehler')}: {data}".strip(": ")
            if "Not authorized" in data or "not authorized" in msg.lower() or "session terminated" in msg.lower():
                msg = f"Anmeldung fehlgeschlagen ({data or msg}) – API-Token prüfen (Benutzer → API-Token)"
            raise ZabbixError(f"Zabbix {method}: {msg}", int(err.get("code") or 0))
        return j.get("result")

    def version(self) -> str:
        if self._version is None:
            self._version = str(self.call("apiinfo.version", {}, auth=False))
        return self._version

    @property
    def v(self) -> tuple[int, int]:
        return version_tuple(self.version())

    # ------------------------------------------------------------------ reads
    def hostgroups(self) -> list[dict]:
        return self.call("hostgroup.get", {"output": ["groupid", "name"]}) or []

    def hosts(self, **flt) -> list[dict]:
        params = {"output": ["hostid", "host", "name", "status", "tls_connect"],
                  "selectInterfaces": ["interfaceid", "ip", "dns", "port", "type", "available"],
                  "selectHostGroups" if self.v >= (6, 2) else "selectGroups": ["groupid", "name"],
                  "selectParentTemplates": ["templateid", "name"]}
        params.update(flt)
        hosts = self.call("host.get", params) or []
        for h in hosts:
            h.setdefault("hostgroups", h.pop("groups", []))
            avail = [int(i.get("available") or 0) for i in h.get("interfaces", [])]
            h["available"] = 1 if 1 in avail else (2 if 2 in avail else 0)
        return hosts

    def templates(self, names: list[str]) -> dict[str, str]:
        rows = self.call("template.get", {"output": ["templateid", "host", "name"],
                                          "filter": {"name": names}}) or []
        return {r["name"]: r["templateid"] for r in rows}

    def problems(self, min_severity: int = 0) -> list[dict]:
        probs = self.call("problem.get", {"output": ["eventid", "objectid", "name", "severity", "clock",
                                                     "acknowledged", "opdata", "r_eventid"],
                                          "source": 0, "object": 0, "recent": False,
                                          "severities": list(range(max(0, min_severity), 6)),
                                          "sortfield": ["eventid"], "sortorder": "DESC"}) or []
        trig_ids = sorted({p["objectid"] for p in probs})
        hosts: dict[str, dict] = {}
        if trig_ids:
            for t in self.call("trigger.get", {"triggerids": trig_ids, "output": ["triggerid", "manual_close"],
                                               "selectHosts": ["hostid", "host", "name"]}) or []:
                h = (t.get("hosts") or [{}])[0]
                hosts[t["triggerid"]] = {"hostid": h.get("hostid", ""), "host": h.get("host", ""),
                                         "host_name": h.get("name", ""),
                                         "manual_close": str(t.get("manual_close", "0")) == "1"}
        for p in probs:
            p.update(hosts.get(p["objectid"], {"host": "", "host_name": "", "hostid": "", "manual_close": False}))
            p["severity"] = int(p.get("severity") or 0)
        return probs

    def acknowledge(self, eventid: str, action: int, message: str = "") -> Any:
        params: dict = {"eventids": [str(eventid)], "action": action}
        if message:
            params["message"] = message[:2048]
            params["action"] = action | ACK_MESSAGE
        return self.call("event.acknowledge", params)

    # ------------------------------------------------------------------ hosts
    def ensure_hostgroup(self, name: str) -> str:
        found = self.call("hostgroup.get", {"output": ["groupid"], "filter": {"name": [name]}}) or []
        if found:
            return found[0]["groupid"]
        return self.call("hostgroup.create", {"name": name})["groupids"][0]

    def upsert_host(self, host: str, visible: str, ip: str, groupid: str, template_ids: list[str],
                    psk_identity: str, psk: str, port: int = 10050) -> tuple[str, bool]:
        """Create or update an agent host with PSK encryption; returns (hostid, created)."""
        base = {"name": visible, "tls_connect": 2, "tls_accept": 2, "tls_psk_identity": psk_identity,
                "tls_psk": psk}
        existing = self.hosts(filter={"host": [host]})
        if existing:
            h = existing[0]
            groups = {g["groupid"] for g in h.get("hostgroups", [])} | {groupid}
            templates = {t["templateid"] for t in h.get("parentTemplates", [])} | set(template_ids)
            params = dict(base, hostid=h["hostid"], groups=[{"groupid": g} for g in sorted(groups)],
                          templates=[{"templateid": t} for t in sorted(templates)])
            self.call("host.update", params)
            agent_if = next((i for i in h.get("interfaces", []) if str(i.get("type")) == "1"), None)
            if agent_if and (agent_if.get("ip") != ip or str(agent_if.get("port")) != str(port)):
                self.call("hostinterface.update", {"interfaceid": agent_if["interfaceid"], "ip": ip, "useip": 1,
                                                   "port": str(port)})
            elif not agent_if:
                self.call("hostinterface.create", {"hostid": h["hostid"], "type": 1, "main": 1, "useip": 1,
                                                   "ip": ip, "dns": "", "port": str(port)})
            return h["hostid"], False
        params = dict(base, host=host, groups=[{"groupid": groupid}],
                      templates=[{"templateid": t} for t in template_ids],
                      interfaces=[{"type": 1, "main": 1, "useip": 1, "ip": ip, "dns": "", "port": str(port)}])
        return self.call("host.create", params)["hostids"][0], True

    # ------------------------------------------------------------------ ticket webhook
    def setup_webhook(self, url: str, token: str, min_severity: int) -> dict:
        """Media type (webhook), user group with read access, notification user and trigger action.
        Idempotent: existing objects (by name) are updated."""
        params = [{"name": "URL", "value": url}, {"name": "Token", "value": token}] + \
            [{"name": k, "value": v} for k, v in WEBHOOK_PARAMS]
        media = {"type": 4, "name": MEDIA_NAME, "script": WEBHOOK_SCRIPT, "parameters": params, "timeout": "10s",
                 "process_tags": 0, "show_event_menu": 0, "status": 0,
                 "description": "Übergibt Probleme als Tickets an den Servermanager (angelegt vom Servermanager)."}
        found = self.call("mediatype.get", {"output": ["mediatypeid"], "filter": {"name": [MEDIA_NAME]}}) or []
        if found:
            mediatypeid = found[0]["mediatypeid"]
            self.call("mediatype.update", {k: v for k, v in media.items() if k != "type"} | {"mediatypeid": mediatypeid})
        else:
            mediatypeid = self.call("mediatype.create", media)["mediatypeids"][0]

        rights_key = "hostgroup_rights" if self.v >= (6, 2) else "rights"
        rights = [{"id": g["groupid"], "permission": 2} for g in self.hostgroups()]
        found = self.call("usergroup.get", {"output": ["usrgrpid"], "filter": {"name": [GROUP_NAME]}}) or []
        if found:
            usrgrpid = found[0]["usrgrpid"]
            self.call("usergroup.update", {"usrgrpid": usrgrpid, rights_key: rights, "gui_access": 3})
        else:
            usrgrpid = self.call("usergroup.create", {"name": GROUP_NAME, "gui_access": 3,
                                                      rights_key: rights})["usrgrpids"][0]

        roles = self.call("role.get", {"output": ["roleid", "name", "type"]}) or []
        role = next((r for r in roles if r.get("name") == "User role"), None) or \
            next((r for r in roles if str(r.get("type")) == "1"), None)
        if role is None:
            raise ZabbixError("Keine Benutzerrolle vom Typ „User“ gefunden")
        name_key = "username"
        media_entry = {"mediatypeid": mediatypeid, "sendto": "servermanager", "active": 0, "severity": 63,
                       "period": "1-7,00:00-24:00"}
        found = self.call("user.get", {"output": ["userid"], "filter": {name_key: [USER_NAME]}}) or []
        if found:
            userid = found[0]["userid"]
            self.call("user.update", {"userid": userid, "usrgrps": [{"usrgrpid": usrgrpid}],
                                      "roleid": role["roleid"], "medias": [media_entry]})
        else:
            userid = self.call("user.create", {name_key: USER_NAME, "name": "Servermanager", "surname": "Tickets",
                                               "passwd": _random_password(), "roleid": role["roleid"],
                                               "usrgrps": [{"usrgrpid": usrgrpid}],
                                               "medias": [media_entry]})["userids"][0]

        op = {"operationtype": 0, "opmessage": {"default_msg": 0, "subject": "{EVENT.NAME}",
                                                "message": "{EVENT.NAME}", "mediatypeid": mediatypeid},
              "opmessage_usr": [{"userid": userid}]}
        rec = {"operationtype": 0, "opmessage": op["opmessage"], "opmessage_usr": op["opmessage_usr"]}
        action = {"name": ACTION_NAME, "eventsource": 0, "status": 0, "esc_period": "1h",
                  "filter": {"evaltype": 0, "conditions": [{"conditiontype": 4, "operator": 5,
                                                             "value": str(int(min_severity))}]},
                  "operations": [op], "recovery_operations": [rec], "update_operations": [dict(rec)]}
        found = self.call("action.get", {"output": ["actionid"], "filter": {"name": [ACTION_NAME]}}) or []
        if found:
            actionid = found[0]["actionid"]
            self.call("action.update", {k: v for k, v in action.items() if k != "eventsource"} | {"actionid": actionid})
        else:
            actionid = self.call("action.create", action)["actionids"][0]
        return {"mediatypeid": mediatypeid, "usrgrpid": usrgrpid, "userid": userid, "actionid": actionid}


def _random_password(n: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    core = "".join(secrets.choice(alphabet) for _ in range(n))
    return core + "!aA1"  # satisfies every password complexity policy


def psk() -> str:
    return secrets.token_hex(32)
