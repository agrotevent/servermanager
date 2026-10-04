"""Hetzner Cloud API (https://api.hetzner.cloud/v1): servers, power actions, reverse DNS, traffic, metrics.

One API token per Cloud project (Console → Projekt → Sicherheit → API-Tokens, Lesen oder Lesen & Schreiben).
JSON in both directions, Bearer authentication, paginated lists (``meta.pagination.next_page``), errors as
``{"error": {"code", "message"}}``. Traffic values are bytes of the current billing period.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Optional

import requests

from .hetzner import validate_ptr

API_URL = "https://api.hetzner.cloud/v1"
# action -> label; all of them are "Neustarten" rights (power state of the server)
POWER_ACTIONS = {"reboot": "Neustart (sauber, ACPI)", "shutdown": "Herunterfahren (sauber, ACPI)",
                 "poweron": "Einschalten", "reset": "Reset (hart)", "poweroff": "Ausschalten (hart)"}
STATUS_LABELS = {"running": "läuft", "off": "aus", "initializing": "wird angelegt", "starting": "startet",
                 "stopping": "stoppt", "rebuilding": "wird neu aufgesetzt", "migrating": "wird migriert",
                 "deleting": "wird gelöscht", "unknown": "unbekannt"}
METRIC_STEPS = {"24h": (86400, 300), "7d": (7 * 86400, 1800), "30d": (30 * 86400, 7200)}


class CloudError(Exception):
    def __init__(self, message: str, status: int = 0, code: str = ""):
        super().__init__(message)
        self.status = status
        self.code = code


class Cloud:
    def __init__(self, token: str, base: str = API_URL, fingerprint: str = "", timeout: int = 25):
        token = (token or "").strip()
        if not token:
            raise CloudError("Kein API-Token hinterlegt")
        self.base = base.rstrip("/")
        if not self.base.startswith("https://"):
            raise CloudError("Die Cloud-API ist nur über https erreichbar")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers.update({"Authorization": f"Bearer {token}", "Accept": "application/json"})
        if fingerprint:  # only for tests/mirrors – the real API has a publicly trusted certificate
            from . import tlspin
            self.session.verify = False
            self.session.mount(self.base + "/", tlspin.PinnedAdapter(fingerprint))

    # ------------------------------------------------------------------ raw
    def request(self, method: str, path: str, body: Optional[dict] = None, params: Optional[dict] = None) -> Any:
        url = f"{self.base}/{path.lstrip('/')}"
        try:
            r = self.session.request(method, url, json=body, params=params, timeout=self.timeout,
                                     allow_redirects=False)
        except requests.exceptions.SSLError as exc:
            raise CloudError(f"Hetzner Cloud: TLS-Fehler ({exc})") from exc
        except requests.RequestException as exc:
            raise CloudError(f"Hetzner Cloud nicht erreichbar: {exc}") from exc
        try:
            j = r.json() if r.content else {}
        except ValueError:
            j = {}
        if r.status_code >= 400:
            err = j.get("error", {}) if isinstance(j, dict) else {}
            code, msg = str(err.get("code") or ""), str(err.get("message") or r.reason or "")
            if r.status_code == 401 or code == "unauthorized":
                msg = "API-Token ungültig oder gelöscht (Cloud Console → Projekt → Sicherheit → API-Tokens)"
            elif code == "forbidden":
                msg = (f"keine Berechtigung ({msg}) – für Neustarts und Änderungen braucht das Token "
                       "„Lesen & Schreiben“")
            elif code == "rate_limit_exceeded":
                msg = "Hetzner begrenzt die Anfragen (Projekt-Limit) – bitte später erneut versuchen"
            elif code == "locked":
                msg = "der Server ist gerade gesperrt (eine andere Aktion läuft) – kurz warten"
            elif code == "invalid_input":
                fields = ", ".join(str(x.get("name", "")) for x in (err.get("details") or {}).get("fields") or []
                                   if isinstance(x, dict))
                msg = f"ungültige Eingabe{f' ({fields})' if fields else ''}: {msg}"
            raise CloudError(f"Hetzner Cloud: {msg}", r.status_code, code)
        return j

    def _all(self, path: str, key: str, params: Optional[dict] = None) -> list[dict]:
        out, page = [], 1
        while page:
            j = self.request("GET", path, params={**(params or {}), "page": page, "per_page": 50}) or {}
            out.extend(j.get(key) or [])
            page = ((j.get("meta") or {}).get("pagination") or {}).get("next_page")
            if len(out) > 5000:
                break
        return out

    # ------------------------------------------------------------------ reads
    def servers(self) -> list[dict]:
        return self._all("servers", "servers")

    def floating_ips(self) -> list[dict]:
        return self._all("floating_ips", "floating_ips")

    def metrics(self, server_id: int, types: str, start: str, end: str, step: int) -> dict:
        j = self.request("GET", f"servers/{int(server_id)}/metrics",
                         params={"type": types, "start": start, "end": end, "step": int(step)}) or {}
        return (j.get("metrics") or {}).get("time_series") or {}

    # ------------------------------------------------------------------ writes
    def power(self, server_id: int, action: str) -> dict:
        if action not in POWER_ACTIONS:
            raise CloudError("Unbekannte Aktion")
        return (self.request("POST", f"servers/{int(server_id)}/actions/{action}") or {}).get("action", {})

    def rename(self, server_id: int, name: str) -> dict:
        import re
        if not re.match(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,61}[A-Za-z0-9])?$", name or ""):
            raise CloudError("Ungültiger Servername (Buchstaben, Ziffern, Punkt und Bindestrich, max. 63 Zeichen)")
        return (self.request("PUT", f"servers/{int(server_id)}", {"name": name}) or {}).get("server", {})

    def set_ptr(self, ip: str, ptr: str, server_id: int = 0, floating_id: int = 0) -> dict:
        ip = str(ipaddress.ip_address(ip))
        body = {"ip": ip, "dns_ptr": validate_ptr(ptr) if ptr else None}
        path = (f"floating_ips/{int(floating_id)}/actions/change_dns_ptr" if floating_id
                else f"servers/{int(server_id)}/actions/change_dns_ptr")
        return (self.request("POST", path, body) or {}).get("action", {})


# ----------------------------------------------------------------------------- helpers
def addresses(server: dict, floating: list[dict]) -> list[dict]:
    """IPs of a server with PTR and where the PTR is changed (server itself or its floating IP)."""
    pub = server.get("public_net") or {}
    rows: list[dict] = []
    v4 = pub.get("ipv4") or {}
    if v4.get("ip"):
        rows.append({"ip": v4["ip"], "ptr": v4.get("dns_ptr") or "", "kind": "primary", "net": "",
                     "blocked": bool(v4.get("blocked"))})
    v6 = pub.get("ipv6") or {}
    for e in v6.get("dns_ptr") or []:
        rows.append({"ip": e.get("ip"), "ptr": e.get("dns_ptr") or "", "kind": "primary", "net": v6.get("ip", ""),
                     "blocked": bool(v6.get("blocked"))})
    for f in floating:
        if f.get("server") != server.get("id"):
            continue
        entries = f.get("dns_ptr") or []
        if f.get("type") == "ipv4" or not entries:
            entries = entries or [{"ip": f.get("ip"), "dns_ptr": ""}]
        for e in entries:
            rows.append({"ip": e.get("ip"), "ptr": e.get("dns_ptr") or "", "kind": "floating",
                         "floating_id": f.get("id"), "net": f.get("ip") if f.get("type") == "ipv6" else "",
                         "name": f.get("name") or "", "blocked": bool(f.get("blocked"))})
    return [r for r in rows if r.get("ip")]


def nets(server: dict, floating: list[dict]) -> list[tuple[str, int]]:
    """(network, floating id or 0) a PTR may be set in: the server's IPv6 /64, floating IPs."""
    out: list[tuple[str, int]] = []
    pub = server.get("public_net") or {}
    if (pub.get("ipv4") or {}).get("ip"):
        out.append((f"{pub['ipv4']['ip']}/32", 0))
    if (pub.get("ipv6") or {}).get("ip"):
        out.append((pub["ipv6"]["ip"], 0))
    for f in floating:
        if f.get("server") == server.get("id") and f.get("ip"):
            out.append((f["ip"] if "/" in f["ip"] else f"{f['ip']}/{128 if ':' in f['ip'] else 32}", int(f["id"])))
    return out


def owner_of(ip: str, server: dict, floating: list[dict]) -> Optional[int]:
    """None if ``ip`` does not belong to the server, else 0 (server) or the floating IP id."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for net, fid in nets(server, floating):
        try:
            if addr in ipaddress.ip_network(net, strict=False):
                return fid
        except ValueError:
            continue
    return None


def series(ts: dict, name: str) -> list[tuple[float, float]]:
    out = []
    for t, v in ((ts.get(name) or {}).get("values") or []):
        try:
            out.append((float(t), float(v)))
        except (TypeError, ValueError):
            continue
    return out
