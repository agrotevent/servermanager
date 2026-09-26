"""Client for the Pangolin Integration API (v1).

Pangolin (https://github.com/fosrl/pangolin) publishes services from private
networks through a Newt tunnel ("site"). A *resource* is a public domain
(subdomain + base domain) - or a raw TCP/UDP port - with one or more
*targets* (IP:port inside the site's network).

The Integration API must be enabled on the Pangolin server
(``flags.enable_integration_api: true``); an organisation API key with the
resource/target/site/domain permissions is used as Bearer token.

The routes changed slightly between Pangolin versions (resources used to belong
to a site, newer versions attach the site to the target); both variants are
supported.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Optional
from urllib.parse import quote, urlsplit

import requests

from . import tlspin

ORG_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
SUBDOMAIN_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$")
METHODS = {"http": "http", "https": "https (Ziel mit TLS)"}
PROTOCOLS = {"http": "HTTP(S) über Domain", "tcp": "TCP-Port", "udp": "UDP-Port"}


class PangolinError(Exception):
    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status


def normalize_url(url: str) -> str:
    url = (url or "").strip().rstrip("/")
    if not url:
        raise PangolinError("Keine API-Adresse angegeben")
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise PangolinError("Ungültige API-Adresse")
    if parts.username or parts.password:
        raise PangolinError("Zugangsdaten gehören nicht in die Adresse")
    path = parts.path.rstrip("/") or "/v1"
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://{parts.hostname}{port}{path}"


def validate_target(ip: str, port: Any) -> tuple[str, int]:
    ip = (ip or "").strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        if not re.match(r"^(?!-)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})*$", ip):
            raise PangolinError("Ungültige Ziel-Adresse (IP oder Hostname)") from None
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise PangolinError("Ungültiger Ziel-Port") from None
    if not 1 <= port <= 65535:
        raise PangolinError("Ungültiger Ziel-Port")
    return ip, port


def connect_hint(base: str, exc: Exception) -> str:
    """Readable cause for a failed connection to the integration API."""
    text = str(exc)
    parts = urlsplit(base)
    if "Connection refused" in text or "Errno 111" in text:
        if parts.port == 3003:
            return ("Port 3003 ist der interne Port der Integration-API im Docker-Netz von Pangolin und nach "
                    "außen nicht geöffnet. Die API über Traefik unter einer eigenen Subdomain freigeben und "
                    "hier ohne Port eintragen, z. B. https://api.<domain>/v1 (siehe Hilfe → Pangolin).")
        return ("Auf diesem Port lauscht nichts – Adresse/Port prüfen und ob die Integration-API "
                "(flags.enable_integration_api) aktiviert und über Traefik veröffentlicht ist.")
    if "Name or service not known" in text or "getaddrinfo failed" in text or "Errno -2" in text \
            or "Errno -3" in text:
        return f"Der Name {parts.hostname} lässt sich nicht auflösen (DNS-Eintrag anlegen)."
    if "timed out" in text.lower():
        return "Zeitüberschreitung – Firewall zwischen Servermanager und Pangolin prüfen."
    return ""


def _seg(v: Any) -> str:
    return quote(str(v), safe="")


class Pangolin:
    def __init__(self, url: str, api_key: str, org_id: str, fingerprint: str = "", timeout: int = 20):
        self.base = normalize_url(url)
        if not api_key:
            raise PangolinError("Kein API-Schlüssel hinterlegt")
        if not ORG_RE.match(org_id or ""):
            raise PangolinError("Ungültige Organisations-ID")
        self.org = org_id
        self.timeout = timeout
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers["Authorization"] = f"Bearer {api_key}"
        self.session.headers["Accept"] = "application/json"
        if fingerprint and self.base.startswith("https://"):
            try:
                adapter = tlspin.PinnedAdapter(fingerprint)
            except tlspin.PinError as exc:
                raise PangolinError(str(exc)) from exc
            self.session.verify = False
            parts = urlsplit(self.base)
            self.session.mount(f"https://{parts.netloc}/", adapter)

    # ------------------------------------------------------------------ raw
    def request(self, method: str, path: str, body: Optional[dict] = None, params: Optional[dict] = None) -> Any:
        url = f"{self.base}/{path.lstrip('/')}"
        try:
            r = self.session.request(method, url, json=body, params=params, timeout=self.timeout)
        except requests.exceptions.SSLError as exc:
            raise PangolinError(f"TLS-Fehler bei {self.base}: {exc}") from exc
        except requests.RequestException as exc:
            hint = connect_hint(self.base, exc)
            raise PangolinError(f"Pangolin-API nicht erreichbar ({self.base}): {exc}"
                                + (f" – {hint}" if hint else "")) from exc
        try:
            j = r.json()
        except ValueError:
            j = {}
        if r.status_code >= 400 or (isinstance(j, dict) and j.get("error") is True):
            msg = (j.get("message") if isinstance(j, dict) else "") or r.reason or r.text[:200]
            if r.status_code == 401:
                msg = "Anmeldung fehlgeschlagen (API-Schlüssel prüfen)"
            elif r.status_code == 403:
                msg = f"Keine Berechtigung ({msg}) – Rechte des API-Schlüssels prüfen"
            raise PangolinError(f"Pangolin: {msg}", r.status_code)
        return j.get("data") if isinstance(j, dict) else None

    def _list(self, path: str, key: str) -> list[dict]:
        items: list[dict] = []
        offset = 0
        while True:
            data = self.request("GET", path, params={"limit": 1000, "offset": offset}) or {}
            batch = data.get(key, []) if isinstance(data, dict) else (data or [])
            items.extend(batch)
            total = ((data.get("pagination") or {}).get("total") if isinstance(data, dict) else None) or 0
            offset += len(batch)
            if not batch or offset >= total:
                return items

    # ------------------------------------------------------------------ read
    def sites(self) -> list[dict]:
        return self._list(f"org/{_seg(self.org)}/sites", "sites")

    def domains(self) -> list[dict]:
        return self._list(f"org/{_seg(self.org)}/domains", "domains")

    def resources(self) -> list[dict]:
        return self._list(f"org/{_seg(self.org)}/resources", "resources")

    def resource(self, resource_id: int) -> dict:
        return self.request("GET", f"resource/{int(resource_id)}") or {}

    def targets(self, resource_id: int) -> list[dict]:
        data = self.request("GET", f"resource/{int(resource_id)}/targets") or {}
        return data.get("targets", []) if isinstance(data, dict) else data

    # ------------------------------------------------------------------ write
    def create_resource(self, name: str, protocol: str, site_id: int, subdomain: str = "",
                        domain_id: str = "", proxy_port: Optional[int] = None) -> dict:
        body: dict[str, Any] = {"name": name}
        if protocol == "http":
            if not domain_id:
                raise PangolinError("Keine Domain ausgewählt")
            body.update({"http": True, "protocol": "tcp", "domainId": domain_id})
            if subdomain:
                body["subdomain"] = subdomain
            else:
                body["isBaseDomain"] = True
        elif protocol in ("tcp", "udp"):
            if not proxy_port or not 1 <= int(proxy_port) <= 65535:
                raise PangolinError("Ungültiger öffentlicher Port")
            body.update({"http": False, "protocol": protocol, "proxyPort": int(proxy_port)})
        else:
            raise PangolinError("Ungültiges Protokoll")
        try:
            # newer Pangolin versions: resources belong to the organisation
            return self.request("PUT", f"org/{_seg(self.org)}/resource", body) or {}
        except PangolinError as exc:
            if exc.status not in (404, 405):
                raise
        return self.request("PUT", f"org/{_seg(self.org)}/site/{int(site_id)}/resource",
                            {**body, "siteId": int(site_id)}) or {}

    def add_target(self, resource_id: int, ip: str, port: int, method: Optional[str], site_id: int) -> dict:
        ip, port = validate_target(ip, port)
        body: dict[str, Any] = {"ip": ip, "port": port, "enabled": True, "method": method}
        try:
            return self.request("PUT", f"resource/{int(resource_id)}/target", {**body, "siteId": int(site_id)}) or {}
        except PangolinError as exc:
            if exc.status != 400:
                raise
        # older versions reject the unknown field siteId
        return self.request("PUT", f"resource/{int(resource_id)}/target", body) or {}

    def update_resource(self, resource_id: int, **fields) -> dict:
        return self.request("POST", f"resource/{int(resource_id)}", fields) or {}

    def delete_resource(self, resource_id: int) -> None:
        self.request("DELETE", f"resource/{int(resource_id)}")

    def delete_target(self, target_id: int) -> None:
        self.request("DELETE", f"target/{int(target_id)}")

    def publish(self, name: str, protocol: str, site_id: int, target_ip: str, target_port: int,
                method: str = "http", subdomain: str = "", domain_id: str = "", proxy_port: Optional[int] = None,
                sso: bool = False) -> dict:
        """Create a resource with one target; the resource is removed again if the target fails."""
        target_ip, target_port = validate_target(target_ip, target_port)
        if protocol == "http" and subdomain and not SUBDOMAIN_RE.match(subdomain):
            raise PangolinError("Ungültige Subdomain (a-z, 0-9, -, Punkte)")
        res = self.create_resource(name, protocol, site_id, subdomain, domain_id, proxy_port)
        rid = res.get("resourceId")
        if not rid:
            raise PangolinError("Pangolin hat keine Resource-ID zurückgegeben")
        try:
            self.add_target(rid, target_ip, target_port, method if protocol == "http" else None, site_id)
            if protocol == "http":
                self.update_resource(rid, sso=bool(sso))
        except PangolinError:
            try:
                self.delete_resource(rid)
            except PangolinError:
                pass
            raise
        return res


# --------------------------------------------------------------------------
# primary -> backup domain mapping
# --------------------------------------------------------------------------
DEFAULT_TEMPLATE = "{sub}"
TEMPLATE_RE = re.compile(r"^[a-z0-9{}.-]{1,100}$")


def validate_template(template: str) -> str:
    t = (template or DEFAULT_TEMPLATE).strip().lower()
    if not TEMPLATE_RE.match(t) or re.search(r"\{(?!sub\}|domain\}|base\})[^}]*\}", t):
        raise PangolinError("Vorlage: Buchstaben, Ziffern, '-', '.' und die Platzhalter {sub}, {domain}, {base}")
    return t


def render_subdomain(template: str, sub: str, primary_base: str) -> str:
    """Backup subdomain for a primary resource; '' means the backup base domain itself."""
    label = (primary_base or "").split(".")[0]
    t = validate_template(template)
    out = t.replace("{sub}", sub or "").replace("{domain}", label).replace("{base}", (primary_base or "").replace(".", "-"))
    out = re.sub(r"\.{2,}", ".", re.sub(r"-{2,}", "-", out)).strip(".-")
    out = re.sub(r"(^|\.)-+|-+(\.|$)", lambda m: m.group(1) or m.group(2), out)
    if out and not SUBDOMAIN_RE.match(out):
        raise PangolinError(f"Ungültige Subdomain „{out}“ aus Vorlage {template}")
    return out


def backup_address(backup, primary_base: str, sub: str, backup_domains: dict[str, str]) -> dict:
    """Where a primary service (sub + base domain) is published on the backup Pangolin.

    Returns {"domain_id", "base", "subdomain", "full", "mapped"}. Without an explicit mapping the
    backup's default domain is used with the plain subdomain.
    """
    entry = (backup.domain_map or {}).get((primary_base or "").lower())
    mapped = bool(entry and entry.get("domain_id") in backup_domains)
    domain_id = entry["domain_id"] if mapped else backup.default_domain_id
    template = (entry or {}).get("template") or DEFAULT_TEMPLATE if mapped else DEFAULT_TEMPLATE
    if not domain_id or domain_id not in backup_domains:
        raise PangolinError(f"Für {backup.name} ist keine Backup-Domain für {primary_base or '?'} festgelegt")
    subdomain = render_subdomain(template, sub, primary_base)
    base = backup_domains[domain_id]
    return {"domain_id": domain_id, "base": base, "subdomain": subdomain,
            "full": f"{subdomain}.{base}" if subdomain else base, "mapped": mapped}
