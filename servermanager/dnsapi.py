"""DNS and domains at the registrar: hosting.de platform (also FRESH Internet, http.net) and INWX.

Both providers are reduced to the same small interface (zones, records, domains) with normalized records:
``{"id", "name" (FQDN, lower case, no trailing dot), "type", "content", "ttl", "prio"}``. TXT content is the
plain text (hosting.de stores it quoted, INWX not), MX/SRV keep their priority in ``prio`` and SRV content is
"weight port target".

hosting.de: JSON over POST to ``{base}/api/{service}/v1/json/{method}``, the API key as ``authToken`` in the
body, answers ``{"status": "success|pending|error", "errors": [...], "response": {...}}``.
INWX: JSON-RPC ``{"method", "params"}`` to ``{base}/jsonrpc/`` with a session cookie after ``account.login``
(two-factor: ``account.unlock`` with the TOTP code), answers ``{"code": 1000, "msg", "resData"}``.
"""
from __future__ import annotations

import ipaddress
import re
import threading
import time
from datetime import date
from typing import Any, Optional
from urllib.parse import urlsplit

import requests

from . import tlspin

PROVIDERS = {"hostingde": "hosting.de-Plattform (FRESH Internet, hosting.de, http.net)", "inwx": "INWX"}
DEFAULT_URLS = {"hostingde": "https://secure.fresh-internet.de", "inwx": "https://api.domrobot.com"}
RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA", "NS", "PTR")
HOST_RE = re.compile(r"^(\*\.)?([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
HOST_ONLY_RE = re.compile(r"^([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class DnsError(Exception):
    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status


# ----------------------------------------------------------------------------- helpers
def fqdn(name: str) -> str:
    return (name or "").strip().rstrip(".").lower()


def in_zone(host: str, zone: str) -> bool:
    host, zone = fqdn(host), fqdn(zone)
    return host == zone or host.endswith("." + zone)


def zone_of(host: str, zones: list[str]) -> Optional[str]:
    """The most specific zone ``host`` belongs to."""
    hits = [z for z in zones if in_zone(host, z)]
    return max(hits, key=len) if hits else None


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address((value or "").strip())
        return True
    except ValueError:
        return False


def txt_plain(content: str) -> str:
    """'"v=spf1 " "mx -all"' -> 'v=spf1 mx -all' (presentation format to text)."""
    content = (content or "").strip()
    if not content.startswith('"'):
        return content
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', content)
    return "".join(re.sub(r"\\(.)", r"\1", p) for p in parts)


def txt_quoted(text: str) -> str:
    """Text -> presentation format, split into strings of at most 255 characters."""
    text = text or ""
    chunks = [text[i:i + 255] for i in range(0, len(text), 255)] or [""]
    return " ".join('"' + c.replace("\\", "\\\\").replace('"', '\\"') + '"' for c in chunks)


def validate_record(zone: str, rec: dict) -> dict:
    """Checks and normalizes a record entered by a user (name relative to the zone or absolute)."""
    zone = fqdn(zone)
    rtype = (rec.get("type") or "").upper()
    if rtype not in RECORD_TYPES:
        raise DnsError("Ungültiger Typ")
    name = fqdn(rec.get("name") or "")
    if name in ("", "@"):
        name = zone
    elif not in_zone(name, zone):
        name = f"{name}.{zone}"
    if not HOST_RE.match(name):
        raise DnsError("Ungültiger Name")
    content = (rec.get("content") or "").strip()
    if not content or "\n" in content or len(content) > 4000:
        raise DnsError("Inhalt angeben")
    if rtype == "A" and not (is_ip(content) and ":" not in content):
        raise DnsError("A-Eintrag: IPv4-Adresse angeben")
    if rtype == "AAAA" and not (is_ip(content) and ":" in content):
        raise DnsError("AAAA-Eintrag: IPv6-Adresse angeben")
    if rtype in ("CNAME", "MX", "NS", "PTR"):
        content = fqdn(content)
        if not HOST_ONLY_RE.match(content):
            raise DnsError(f"{rtype}: Hostnamen angeben (z. B. mail.example.com)")
    if rtype == "CNAME" and name == zone:
        raise DnsError("Für die Zone selbst ist kein CNAME möglich")
    if rtype == "TXT":
        content = txt_plain(content)
    try:
        ttl = int(rec.get("ttl") or 3600)
        prio = int(rec.get("prio") or (10 if rtype == "MX" else 0))
    except ValueError:
        raise DnsError("TTL und Priorität als Zahl angeben") from None
    if not 60 <= ttl <= 604800:
        raise DnsError("TTL zwischen 60 und 604800 Sekunden")
    if not 0 <= prio <= 65535:
        raise DnsError("Ungültige Priorität")
    return {"id": str(rec.get("id") or ""), "name": name, "type": rtype, "content": content, "ttl": ttl,
            "prio": prio if rtype in ("MX", "SRV") else 0}


def same_record(a: dict, b: dict) -> bool:
    return (fqdn(a["name"]) == fqdn(b["name"]) and a["type"] == b["type"]
            and _cmp(a["type"], a["content"]) == _cmp(b["type"], b["content"])
            and (a["type"] not in ("MX", "SRV") or int(a.get("prio") or 0) == int(b.get("prio") or 0)))


def _cmp(rtype: str, content: str) -> str:
    if rtype in ("CNAME", "MX", "NS", "PTR"):
        return fqdn(content)
    if rtype == "TXT":
        return txt_plain(content)
    return (content or "").strip()


def _date(value: Any) -> str:
    """ISO date (YYYY-MM-DD) from the various date formats of the APIs, '' if none."""
    text = str(value or "").strip()
    m = re.match(r"^(\d{4}-\d{2}-\d{2})", text)
    if m:
        return m.group(1)
    m = re.match(r"^(\d{4})(\d{2})(\d{2})T", text)  # XML-RPC style 20261231T00:00:00
    return f"{m.group(1)}-{m.group(2)}-{m.group(3)}" if m else ""


def days_left(iso: str) -> Optional[int]:
    try:
        return (date.fromisoformat(iso) - date.today()).days
    except (TypeError, ValueError):
        return None


# ----------------------------------------------------------------------------- base
class Provider:
    kind = ""

    def __init__(self, base: str, fingerprint: str = "", verify_ca: bool = True, timeout: int = 25):
        self.base = normalize_url(base, self.kind)
        self.timeout = timeout
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.verify = verify_ca
        if fingerprint and self.base.startswith("https://"):
            try:
                adapter = tlspin.PinnedAdapter(fingerprint)
            except tlspin.PinError as exc:
                raise DnsError(str(exc)) from exc
            self.session.verify = False
            self.session.mount(f"https://{urlsplit(self.base).netloc}/", adapter)

    def _post(self, url: str, body: dict) -> dict:
        try:
            r = self.session.post(url, json=body, timeout=self.timeout, allow_redirects=False)
        except requests.exceptions.SSLError as exc:
            raise DnsError(tlspin.tls_message(self.base, exc)) from exc
        except requests.RequestException as exc:
            raise DnsError(f"{PROVIDERS[self.kind].split(' (')[0]} nicht erreichbar ({self.base}): {exc}") from exc
        if r.status_code in (301, 302, 303, 307, 308):
            raise DnsError(f"Die Adresse leitet um (HTTP {r.status_code}) – Adresse der Schnittstelle prüfen",
                           r.status_code)
        try:
            j = r.json()
        except ValueError:
            raise DnsError(f"Keine gültige Antwort (HTTP {r.status_code}) – Adresse der Schnittstelle prüfen",
                           r.status_code) from None
        if not isinstance(j, dict):
            raise DnsError("Unerwartete Antwort der Schnittstelle")
        return j

    # interface
    def zones(self) -> list[dict]:
        raise NotImplementedError

    def records(self, zone: str) -> list[dict]:
        raise NotImplementedError

    def add(self, zone: str, rec: dict) -> None:
        raise NotImplementedError

    def update(self, zone: str, old: dict, new: dict) -> None:
        raise NotImplementedError

    def delete(self, zone: str, rec: dict) -> None:
        raise NotImplementedError

    def domains(self) -> list[dict]:
        raise NotImplementedError

    def close(self) -> None:
        self.session.close()


def normalize_url(url: str, kind: str) -> str:
    url = (url or DEFAULT_URLS.get(kind, "")).strip().rstrip("/")
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise DnsError("Ungültige Adresse der Schnittstelle")
    if parts.username or parts.password:
        raise DnsError("Zugangsdaten gehören nicht in die Adresse")
    path = re.sub(r"/(api(/.*)?|jsonrpc/?|xmlrpc/?)$", "", parts.path.rstrip("/"))
    return f"{parts.scheme}://{parts.netloc}{path}"


# ----------------------------------------------------------------------------- hosting.de
class HostingDe(Provider):
    """hosting.de API (also white label partners like FRESH Internet under their own address)."""

    kind = "hostingde"
    PAGE = 500

    def __init__(self, base: str, api_key: str, **kw):
        super().__init__(base, **kw)
        self.api_key = (api_key or "").strip()
        if not self.api_key:
            raise DnsError("Kein API-Schlüssel hinterlegt")
        self._zone_cfg: dict[str, dict] = {}

    def call(self, service: str, method: str, body: Optional[dict] = None, retries: int = 3) -> Any:
        j = self._post(f"{self.base}/api/{service}/v1/json/{method}", {"authToken": self.api_key, **(body or {})})
        if j.get("status") in ("success", "pending"):
            return j.get("response")
        errors = [e for e in j.get("errors") or [] if isinstance(e, dict)]
        code = int(errors[0].get("code") or 0) if errors else 0
        if code == 10205 and retries > 0:  # object is blocked by another change: try again shortly
            time.sleep(2)
            return self.call(service, method, body, retries - 1)
        texts = "; ".join(f"{e.get('text') or e.get('code')}{(' (' + str(e['value']) + ')') if e.get('value') else ''}"
                          for e in errors) or str(j.get("status") or "unbekannter Fehler")
        if "auth" in texts.lower() or "permission" in texts.lower() or "access" in texts.lower():
            texts += " – API-Schlüssel und seine Rechte prüfen"
        raise DnsError(f"{method}: {texts}", code)

    def _find(self, service: str, method: str, flt: Optional[dict] = None) -> list[dict]:
        out, page = [], 1
        while True:
            body: dict = {"limit": self.PAGE, "page": page}
            if flt:
                body["filter"] = flt
            res = self.call(service, method, body) or {}
            out.extend(x for x in res.get("data") or [] if isinstance(x, dict))
            if page >= int(res.get("totalPages") or 1) or page > 100:
                return out
            page += 1

    def zones(self) -> list[dict]:
        rows = self._find("dns", "zoneConfigsFind")
        for z in rows:
            self._zone_cfg[fqdn(z.get("name") or "")] = z
        return sorted(({"id": str(z.get("id") or ""), "name": fqdn(z.get("name") or ""),
                        "status": str(z.get("status") or ""), "type": str(z.get("type") or "")}
                       for z in rows if z.get("name")), key=lambda z: z["name"])

    def _zone(self, zone: str) -> dict:
        zones = self._find("dns", "zonesFind", {"field": "ZoneName", "value": fqdn(zone)})
        if not zones:
            raise DnsError(f"Zone {zone} nicht gefunden", 404)
        self._zone_cfg[fqdn(zone)] = zones[0].get("zoneConfig") or {}
        return zones[0]

    def records(self, zone: str) -> list[dict]:
        out = []
        for r in self._zone(zone).get("records") or []:
            rtype = str(r.get("type") or "").upper()
            content = str(r.get("content") or "")
            if rtype == "TXT":
                content = txt_plain(content)
            elif rtype in ("CNAME", "MX", "NS", "PTR"):
                content = fqdn(content)
            out.append({"id": str(r.get("id") or ""), "name": fqdn(r.get("name") or ""), "type": rtype,
                        "content": content, "ttl": int(r.get("ttl") or 0), "prio": int(r.get("priority") or 0)})
        return sorted(out, key=_sort_key)

    @staticmethod
    def _native(rec: dict) -> dict:
        content = txt_quoted(rec["content"]) if rec["type"] == "TXT" else rec["content"]
        out = {"name": fqdn(rec["name"]), "type": rec["type"], "content": content, "ttl": int(rec["ttl"])}
        if rec["type"] in ("MX", "SRV"):
            out["priority"] = int(rec.get("prio") or 0)
        if rec.get("id"):
            out["id"] = rec["id"]
        return out

    def _update(self, zone: str, add=(), modify=(), delete=()) -> None:
        cfg = self._zone_cfg.get(fqdn(zone)) or self._zone(zone).get("zoneConfig") or {}
        self.call("dns", "zoneUpdate", {"zoneConfig": cfg,
                                        "recordsToAdd": [self._native(r) for r in add],
                                        "recordsToModify": [self._native(r) for r in modify],
                                        "recordsToDelete": [self._native(r) for r in delete]})

    def add(self, zone: str, rec: dict) -> None:
        self._update(zone, add=[{**rec, "id": ""}])

    def update(self, zone: str, old: dict, new: dict) -> None:
        if not old.get("id"):
            raise DnsError("Eintrag ohne Kennung")
        self._update(zone, modify=[{**new, "id": old["id"]}])

    def delete(self, zone: str, rec: dict) -> None:
        self._update(zone, delete=[rec])

    def domains(self) -> list[dict]:
        out = []
        for d in self._find("domain", "domainsFind"):
            name = fqdn(d.get("nameUnicode") or d.get("name") or "")
            if not name:
                continue
            end = _date(d.get("currentContractPeriodEnd") or d.get("expirationDate") or d.get("paidUntil"))
            out.append({"name": name, "status": str(d.get("status") or ""),
                        "expires": end, "renew": "" if d.get("deletionDate") else "automatisch",
                        "deletion": _date(d.get("deletionDate")),
                        "nameservers": [fqdn(n.get("name") if isinstance(n, dict) else n)
                                        for n in d.get("nameservers") or []],
                        "transfer_lock": bool(d.get("transferLockEnabled"))})
        return sorted(out, key=lambda x: x["name"])


# ----------------------------------------------------------------------------- INWX
_INWX_SESSIONS: dict[str, tuple[Any, float]] = {}   # base|user -> (cookie jar, login time)
_INWX_LOCK = threading.Lock()
_INWX_LAST_TAN: dict[str, int] = {}


class Inwx(Provider):
    """INWX DomRobot JSON-RPC API (login per session, optional two-factor with the shared secret)."""

    kind = "inwx"
    SESSION_TTL = 600

    def __init__(self, base: str, username: str, password: str, totp_secret: str = "", **kw):
        super().__init__(base, **kw)
        if not username or not password:
            raise DnsError("Benutzername und Passwort fehlen")
        self.username, self.password, self.totp_secret = username, password, (totp_secret or "").replace(" ", "")
        self._key = f"{self.base}|{username}"
        cached = _INWX_SESSIONS.get(self._key)
        if cached and time.time() - cached[1] < self.SESSION_TTL:
            self.session.cookies.update(cached[0])
            self.logged_in = True
        else:
            self.logged_in = False

    def _rpc(self, method: str, params: Optional[dict] = None) -> dict:
        j = self._post(f"{self.base}/jsonrpc/", {"method": method, "params": {"lang": "de", **(params or {})}})
        return j

    def _login(self) -> None:
        j = self._rpc("account.login", {"user": self.username, "pass": self.password})
        code = int(j.get("code") or 0)
        if code != 1000:
            raise DnsError(f"INWX-Anmeldung fehlgeschlagen ({code} {j.get('msg') or ''}) – Benutzername und "
                           "Passwort prüfen", code)
        tfa = str((j.get("resData") or {}).get("tfa") or "0")
        if tfa not in ("0", "", "False", "false"):
            if not self.totp_secret:
                raise DnsError("Das INWX-Konto verlangt eine Zwei-Faktor-Anmeldung – den geheimen Schlüssel (aus dem "
                               "QR-Code) in der Verbindung hinterlegen")
            import pyotp
            totp = pyotp.TOTP(self.totp_secret)
            step = int(time.time() // 30)
            with _INWX_LOCK:
                if _INWX_LAST_TAN.get(self._key) == step:  # INWX refuses a TAN used before: wait for the next
                    time.sleep(30 - time.time() % 30 + 0.5)
                    step = int(time.time() // 30)
                _INWX_LAST_TAN[self._key] = step
            u = self._rpc("account.unlock", {"tan": totp.now()})
            if int(u.get("code") or 0) != 1000:
                raise DnsError(f"INWX: Zwei-Faktor-Code abgelehnt ({u.get('code')} {u.get('msg') or ''}) – geheimen "
                               "Schlüssel und Uhrzeit des Servers prüfen")
        self.logged_in = True
        with _INWX_LOCK:
            _INWX_SESSIONS[self._key] = (self.session.cookies.copy(), time.time())

    def call(self, method: str, params: Optional[dict] = None, _retry: bool = True) -> dict:
        if not self.logged_in:
            self._login()
        j = self._rpc(method, params)
        code = int(j.get("code") or 0)
        if 1000 <= code < 1500:
            return j.get("resData") or {}
        if _retry and code in (2002, 2200, 2201, 2202):  # session expired / not logged in
            self.logged_in = False
            with _INWX_LOCK:
                _INWX_SESSIONS.pop(self._key, None)
            return self.call(method, params, _retry=False)
        reason = f" – {j.get('reason')}" if j.get("reason") else ""
        raise DnsError(f"INWX {method}: {code} {j.get('msg') or ''}{reason}", code)

    def zones(self) -> list[dict]:
        out, page = [], 1
        while True:
            res = self.call("nameserver.list", {"page": page, "pagelimit": 500})
            rows = [x for x in res.get("domains") or [] if isinstance(x, dict)]
            out.extend({"id": str(x.get("roId") or ""), "name": fqdn(x.get("domain") or ""),
                        "status": "active", "type": str(x.get("type") or "")} for x in rows if x.get("domain"))
            if len(rows) < 500 or page > 100 or len(out) >= int(res.get("count") or 0):
                return sorted(out, key=lambda z: z["name"])
            page += 1

    def records(self, zone: str) -> list[dict]:
        res = self.call("nameserver.info", {"domain": fqdn(zone)})
        out = []
        for r in res.get("record") or []:
            rtype = str(r.get("type") or "").upper()
            if rtype == "SOA":
                continue
            content = str(r.get("content") or "")
            if rtype in ("CNAME", "MX", "NS", "PTR"):
                content = fqdn(content)
            elif rtype == "TXT":
                content = txt_plain(content)
            out.append({"id": str(r.get("id") or ""), "name": fqdn(r.get("name") or zone), "type": rtype,
                        "content": content, "ttl": int(r.get("TTL") or r.get("ttl") or 0),
                        "prio": int(r.get("prio") or 0)})
        return sorted(out, key=_sort_key)

    @staticmethod
    def _params(rec: dict) -> dict:
        p = {"name": fqdn(rec["name"]), "type": rec["type"], "content": rec["content"], "ttl": max(300, int(rec["ttl"]))}
        if rec["type"] in ("MX", "SRV"):
            p["prio"] = int(rec.get("prio") or 0)
        return p

    def add(self, zone: str, rec: dict) -> None:
        self.call("nameserver.createRecord", {"domain": fqdn(zone), **self._params(rec)})

    def update(self, zone: str, old: dict, new: dict) -> None:
        if not old.get("id"):
            raise DnsError("Eintrag ohne Kennung")
        self.call("nameserver.updateRecord", {"id": int(old["id"]) if str(old["id"]).isdigit() else old["id"],
                                              **self._params(new)})

    def delete(self, zone: str, rec: dict) -> None:
        if not rec.get("id"):
            raise DnsError("Eintrag ohne Kennung")
        self.call("nameserver.deleteRecord", {"id": int(rec["id"]) if str(rec["id"]).isdigit() else rec["id"]})

    def domains(self) -> list[dict]:
        out, page = [], 1
        while True:
            res = self.call("domain.list", {"page": page, "pagelimit": 500})
            rows = [x for x in res.get("domain") or [] if isinstance(x, dict)]
            for d in rows:
                mode = str(d.get("renewalMode") or "")
                out.append({"name": fqdn(d.get("domain") or ""), "status": str(d.get("status") or ""),
                            "expires": _date(d.get("exDate") or d.get("reDate")),
                            "renew": {"AUTORENEW": "automatisch", "AUTODELETE": "wird gelöscht",
                                      "AUTOEXPIRE": "läuft aus"}.get(mode.upper(), mode.lower()),
                            "deletion": _date(d.get("exDate")) if mode.upper() in ("AUTODELETE", "AUTOEXPIRE") else "",
                            "nameservers": [fqdn(n) for n in d.get("ns") or []],
                            "transfer_lock": str(d.get("transferLock")) in ("1", "True", "true")})
            if len(rows) < 500 or page > 100 or len(out) >= int(res.get("count") or 0):
                return sorted((x for x in out if x["name"]), key=lambda x: x["name"])
            page += 1


def _sort_key(r: dict) -> tuple:
    order = {t: i for i, t in enumerate(("NS", "A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA", "PTR"))}
    return (r["name"].count("."), r["name"], order.get(r["type"], 99), r["content"])
