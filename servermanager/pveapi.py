"""Minimal Proxmox VE REST API client (API token authentication).

Proxmox VE uses a self-signed certificate by default. Instead of disabling
certificate checks, the SHA-256 fingerprint of the server certificate is
pinned (trust on first use, confirmed by an administrator) - or the
certificate is verified against the system CAs.
"""
from __future__ import annotations

import re
from typing import Any, Optional
from urllib.parse import quote, urlsplit

import requests

from . import tlspin

TOKEN_ID_RE = re.compile(r"^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+![A-Za-z][A-Za-z0-9._-]*$")
NODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$")
UPID_RE = re.compile(r"^UPID:[A-Za-z0-9.-]+:[0-9A-Fa-f]{8}:[0-9A-Fa-f]{8}:[0-9A-Fa-f]{8}:[A-Za-z0-9_-]+:[^:]*:[^:]+:$")
GUEST_TYPES = ("lxc", "qemu")


class PveError(Exception):
    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status


def normalize_url(url: str) -> str:
    """https://host[:port] without path; port 8006 is added when missing."""
    url = (url or "").strip().rstrip("/")
    if not url:
        raise PveError("Keine API-Adresse angegeben")
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise PveError("Die Proxmox-API ist nur per https erreichbar")
    if not parts.hostname:
        raise PveError("Ungültige API-Adresse")
    if parts.username or parts.password:
        raise PveError("Zugangsdaten gehören nicht in die Adresse")
    host = parts.hostname
    if ":" in host:
        host = f"[{host}]"
    return f"https://{host}:{parts.port or 8006}"


def fetch_fingerprint(url: str, timeout: int = 10) -> str:
    parts = urlsplit(normalize_url(url))
    try:
        return tlspin.fetch_fingerprint(parts.hostname, parts.port, timeout)
    except tlspin.PinError as exc:
        raise PveError(str(exc)) from exc


def _enc(value: Any) -> Any:
    if isinstance(value, bool):
        return 1 if value else 0
    return value


def seg(value: Any) -> str:
    """Quote a single URL path segment."""
    return quote(str(value), safe="")


class PveClient:
    def __init__(self, url: str, token_id: str, token_secret: str, fingerprint: str = "",
                 verify_ca: bool = False, timeout: int = 20):
        self.base = normalize_url(url)
        if not TOKEN_ID_RE.match(token_id or ""):
            raise PveError("Ungültige Token-ID (Format benutzer@realm!tokenname)")
        if not token_secret:
            raise PveError("Kein Token-Secret hinterlegt")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"PVEAPIToken={token_id}={token_secret}"
        self.session.trust_env = False  # never send the token through a proxy from the environment
        if fingerprint:
            try:
                adapter = tlspin.PinnedAdapter(fingerprint)
            except tlspin.PinError as exc:
                raise PveError(str(exc)) from exc
            self.session.verify = False
            self.session.mount(self.base, adapter)
        elif verify_ca:
            self.session.verify = True
        else:
            raise PveError("Kein Zertifikats-Fingerabdruck hinterlegt und CA-Prüfung deaktiviert")

    # ------------------------------------------------------------------ raw
    def request(self, method: str, path: str, params: Optional[dict] = None, timeout: Optional[int] = None) -> Any:
        url = f"{self.base}/api2/json/{path.lstrip('/')}"
        clean = {k: _enc(v) for k, v in (params or {}).items() if v is not None}
        kw: dict = {"timeout": timeout or self.timeout}
        if method in ("POST", "PUT"):
            kw["data"] = clean
        else:
            kw["params"] = clean
        try:
            r = self.session.request(method, url, **kw)
        except requests.exceptions.SSLError as exc:
            raise PveError(f"TLS-Fehler bei {self.base} – stimmt der Zertifikats-Fingerabdruck noch? ({exc})") from exc
        except requests.RequestException as exc:
            raise PveError(f"Proxmox-API nicht erreichbar ({self.base}): {exc}") from exc
        if r.status_code >= 400:
            detail = ""
            try:
                j = r.json()
                errs = j.get("errors") or {}
                if isinstance(errs, dict) and errs:
                    detail = "; ".join(f"{k}: {str(v).strip()}" for k, v in errs.items())
                elif j.get("message"):
                    detail = str(j["message"]).strip()
            except ValueError:
                pass
            reason = (r.reason or "").strip()
            if r.status_code == 401:
                raise PveError("Anmeldung an der Proxmox-API fehlgeschlagen (Token-ID/Secret prüfen)", 401)
            if r.status_code == 403:
                raise PveError(f"Keine Berechtigung: {reason or detail} (Rechte des API-Tokens prüfen)", 403)
            msg = " – ".join(x for x in (reason, detail) if x) or r.text[:300]
            raise PveError(f"Proxmox-Fehler {r.status_code} bei {method} /{path.lstrip('/')}: {msg}", r.status_code)
        try:
            return r.json().get("data")
        except ValueError as exc:
            raise PveError("Ungültige Antwort der Proxmox-API") from exc

    def get(self, path: str, **params) -> Any:
        return self.request("GET", path, params)

    def post(self, path: str, **params) -> Any:
        return self.request("POST", path, params)

    def put(self, path: str, **params) -> Any:
        return self.request("PUT", path, params)

    def delete(self, path: str, **params) -> Any:
        return self.request("DELETE", path, params)

    # ------------------------------------------------------------------ cluster
    def version(self) -> dict:
        return self.get("version") or {}

    def resources(self) -> list[dict]:
        return self.get("cluster/resources") or []

    def cluster_status(self) -> list[dict]:
        try:
            return self.get("cluster/status") or []
        except PveError as exc:
            if exc.status == 403:
                return []
            raise

    def nextid(self) -> int:
        return int(self.get("cluster/nextid"))

    def pools(self) -> list[dict]:
        try:
            return self.get("pools") or []
        except PveError:
            return []

    # ------------------------------------------------------------------ node
    def node_status(self, node: str) -> dict:
        return self.get(f"nodes/{seg(node)}/status") or {}

    def storages(self, node: str, content: str = "") -> list[dict]:
        params = {"content": content} if content else {}
        return [s for s in (self.get(f"nodes/{seg(node)}/storage", enabled=1, **params) or []) if s.get("active", 1)]

    def storage_content(self, node: str, storage: str, content: str) -> list[dict]:
        return self.get(f"nodes/{seg(node)}/storage/{seg(storage)}/content", content=content) or []

    def appliances(self, node: str) -> list[dict]:
        return self.get(f"nodes/{seg(node)}/aptinfo") or []

    def bridges(self, node: str) -> list[dict]:
        items = self.get(f"nodes/{seg(node)}/network") or []
        return [i for i in items if i.get("type") in ("bridge", "OVSBridge")]

    def node_rrd(self, node: str, timeframe: str) -> list[dict]:
        return self.get(f"nodes/{seg(node)}/rrddata", timeframe=timeframe, cf="AVERAGE") or []

    # ------------------------------------------------------------------ guests
    def guest_path(self, node: str, gtype: str, vmid: int) -> str:
        if gtype not in GUEST_TYPES:
            raise PveError("Ungültiger Gast-Typ")
        return f"nodes/{seg(node)}/{gtype}/{int(vmid)}"

    def guest_status(self, node: str, gtype: str, vmid: int) -> dict:
        return self.get(self.guest_path(node, gtype, vmid) + "/status/current") or {}

    def guest_config(self, node: str, gtype: str, vmid: int) -> dict:
        return self.get(self.guest_path(node, gtype, vmid) + "/config") or {}

    def guest_rrd(self, node: str, gtype: str, vmid: int, timeframe: str) -> list[dict]:
        return self.get(self.guest_path(node, gtype, vmid) + "/rrddata", timeframe=timeframe, cf="AVERAGE") or []

    def snapshots(self, node: str, gtype: str, vmid: int) -> list[dict]:
        return [s for s in (self.get(self.guest_path(node, gtype, vmid) + "/snapshot") or [])
                if s.get("name") != "current"]

    def lxc_interfaces(self, node: str, vmid: int) -> list[dict]:
        return self.get(f"nodes/{seg(node)}/lxc/{int(vmid)}/interfaces") or []

    # ------------------------------------------------------------------ tasks
    def task_status(self, node: str, upid: str) -> dict:
        return self.get(f"nodes/{seg(node)}/tasks/{seg(upid)}/status") or {}

    def task_log(self, node: str, upid: str, start: int = 0, limit: int = 500) -> list[dict]:
        return self.get(f"nodes/{seg(node)}/tasks/{seg(upid)}/log", start=start, limit=limit) or []

    def task_stop(self, node: str, upid: str) -> None:
        self.delete(f"nodes/{seg(node)}/tasks/{seg(upid)}")


def upid_node(upid: str) -> str:
    """The node a task runs on is the second field of the UPID."""
    parts = (upid or "").split(":")
    return parts[1] if len(parts) > 2 and parts[0] == "UPID" else ""
