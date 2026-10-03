"""Hetzner Robot webservice (dedicated root servers): servers, IPs, reverse DNS, resets, traffic.

API: https://robot-ws.your-server.de, HTTP basic auth with the *webservice user* (Robot → Einstellungen →
Webservice- und App-Einstellungen), form-encoded request bodies, JSON answers. Lists answer
``[{"server": {...}}, ...]``; an empty list is a 404 with a ``*_NOT_FOUND`` code. Traffic values are GB,
traffic warning thresholds MB (hourly/daily) and GB (monthly).
"""
from __future__ import annotations

import ipaddress
import re
from datetime import date
from typing import Any, Optional

import requests

API_URL = "https://robot-ws.your-server.de"
RESET_TYPES = {"sw": "Software-Reset (Strg+Alt+Entf)", "hw": "Hardware-Reset", "power": "Ein-/Ausschalter drücken",
               "power_long": "Ausschalter lang drücken (hart aus)", "man": "Manueller Reset durch Techniker"}
PTR_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\.?$")
NAME_RE = re.compile(r"^[^\x00-\x1f]{0,100}$")


class RobotError(Exception):
    def __init__(self, message: str, status: int = 0, code: str = ""):
        super().__init__(message)
        self.status = status
        self.code = code


def parse_limit_gb(traffic: Any) -> Optional[float]:
    """'20 TB' / '5000 GB' / 'unlimited' -> GB (None = unlimited/unknown)."""
    m = re.match(r"^\s*([\d.,]+)\s*([KMGT]i?B)\s*$", str(traffic or ""), re.I)
    if not m:
        return None
    value = float(m.group(1).replace(",", "."))
    factor = {"K": 1 / 1024 / 1024, "M": 1 / 1024, "G": 1, "T": 1024}[m.group(2)[0].upper()]
    return value * factor


def validate_ptr(ptr: str) -> str:
    ptr = (ptr or "").strip().rstrip(".").lower()
    if not PTR_RE.match(ptr):
        raise RobotError("Ungültiger Hostname für den PTR-Eintrag (z. B. mail.example.com)")
    return ptr


def belongs_to(ip: str, server: dict) -> bool:
    """Is ``ip`` one of the server's addresses or inside one of its subnets (e.g. the IPv6 /64)?"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if str(addr) in {str(x) for x in server.get("ip") or []} or str(addr) == server.get("server_ip"):
        return True
    nets = [f"{s.get('ip')}/{s.get('mask')}" for s in server.get("subnet") or []]
    if server.get("server_ipv6_net"):
        nets.append(f"{server['server_ipv6_net']}/64" if "/" not in server["server_ipv6_net"]
                    else server["server_ipv6_net"])
    for n in nets:
        try:
            if addr in ipaddress.ip_network(n, strict=False):
                return True
        except ValueError:
            continue
    return False


class Robot:
    def __init__(self, username: str, password: str, base: str = API_URL, fingerprint: str = "", timeout: int = 25):
        if not username or not password:
            raise RobotError("Webservice-Benutzer und Passwort fehlen")
        self.base = base.rstrip("/")
        if not self.base.startswith("https://"):
            raise RobotError("Die Robot-API ist nur über https erreichbar")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.trust_env = False
        if fingerprint:  # only for tests/mirrors – the real API has a publicly trusted certificate
            from . import tlspin
            self.session.verify = False
            self.session.mount(self.base + "/", tlspin.PinnedAdapter(fingerprint))
        self.session.auth = (username, password)
        self.session.headers["Accept"] = "application/json"

    # ------------------------------------------------------------------ raw
    def request(self, method: str, path: str, data: Any = None, params: Optional[dict] = None) -> Any:
        url = f"{self.base}/{path.lstrip('/')}"
        try:
            r = self.session.request(method, url, data=data, params=params, timeout=self.timeout,
                                     allow_redirects=False)
        except requests.exceptions.SSLError as exc:
            raise RobotError(f"Hetzner Robot: TLS-Fehler ({exc})") from exc
        except requests.RequestException as exc:
            raise RobotError(f"Hetzner Robot nicht erreichbar: {exc}") from exc
        try:
            j = r.json() if r.content else None
        except ValueError:
            j = None
        if r.status_code >= 400:
            err = (j or {}).get("error", {}) if isinstance(j, dict) else {}
            code, msg = str(err.get("code") or ""), str(err.get("message") or r.reason or "")
            if r.status_code == 401:
                msg = ("Anmeldung fehlgeschlagen – Webservice-Benutzer prüfen (Robot → Einstellungen → Webservice- "
                       "und App-Einstellungen; nicht die Robot-Kundennummer)")
            elif code == "RATE_LIMIT_EXCEEDED":
                n = err.get("max_request") or err.get("max_requests")
                limit = f" (höchstens {n} Anfragen je Zeitfenster)" if n else ""
                msg = f"Hetzner begrenzt die Anfragen{limit} – bitte später erneut versuchen"
            elif code == "INVALID_INPUT":
                bad = ", ".join(err.get("invalid") or []) or ", ".join(err.get("missing") or [])
                msg = f"Ungültige Eingabe{f' ({bad})' if bad else ''}"
            raise RobotError(f"Hetzner Robot: {msg}", r.status_code, code)
        return j

    def _list(self, path: str, key: str) -> list[dict]:
        try:
            rows = self.request("GET", path) or []
        except RobotError as exc:
            if exc.code.endswith("NOT_FOUND"):
                return []
            raise
        return [r[key] for r in rows if isinstance(r, dict) and key in r]

    # ------------------------------------------------------------------ servers
    def servers(self) -> list[dict]:
        return self._list("server", "server")

    def server(self, number: int) -> dict:
        return (self.request("GET", f"server/{int(number)}") or {}).get("server", {})

    def rename(self, number: int, name: str) -> dict:
        if not NAME_RE.match(name or ""):
            raise RobotError("Ungültiger Servername")
        return (self.request("POST", f"server/{int(number)}", {"server_name": name}) or {}).get("server", {})

    def reset_options(self) -> dict[int, list[str]]:
        return {int(r["server_number"]): list(r.get("type") or []) for r in self._list("reset", "reset")}

    def reset(self, number: int, kind: str) -> dict:
        if kind not in RESET_TYPES:
            raise RobotError("Unbekannte Reset-Art")
        return (self.request("POST", f"reset/{int(number)}", {"type": kind}) or {}).get("reset", {})

    def wol(self, number: int) -> dict:
        return (self.request("POST", f"wol/{int(number)}", {}) or {}).get("wol", {})

    # ------------------------------------------------------------------ addresses
    def ips(self) -> list[dict]:
        return self._list("ip", "ip")

    def subnets(self) -> list[dict]:
        return self._list("subnet", "subnet")

    def set_traffic_warnings(self, ip: str, enabled: bool, hourly_mb: int = 0, daily_mb: int = 0,
                             monthly_gb: int = 0) -> dict:
        ipaddress.ip_address(ip)
        data: dict = {"traffic_warnings": "true" if enabled else "false"}
        if enabled:
            for k, v in (("traffic_hourly", hourly_mb), ("traffic_daily", daily_mb), ("traffic_monthly", monthly_gb)):
                if int(v) < 1:
                    raise RobotError("Grenzwerte für Traffic-Warnungen müssen größer als 0 sein")
                data[k] = str(int(v))
        return (self.request("POST", f"ip/{ip}", data) or {}).get("ip", {})

    # ------------------------------------------------------------------ reverse DNS
    def rdns(self) -> dict[str, str]:
        return {r["ip"]: r.get("ptr") or "" for r in self._list("rdns", "rdns")}

    def set_rdns(self, ip: str, ptr: str) -> dict:
        ipaddress.ip_address(ip)
        return (self.request("POST", f"rdns/{ip}", {"ptr": validate_ptr(ptr)}) or {}).get("rdns", {})

    def delete_rdns(self, ip: str) -> None:
        ipaddress.ip_address(ip)
        try:
            self.request("DELETE", f"rdns/{ip}")
        except RobotError as exc:
            if not exc.code.endswith("NOT_FOUND"):
                raise

    # ------------------------------------------------------------------ traffic
    def traffic(self, kind: str, start: str, end: str, ips: list[str], subnets: list[str]) -> dict:
        """kind day (from/to 'YYYY-MM-DDTHH'), month ('YYYY-MM-DD'), year ('YYYY-MM'); single values.

        Returns {address: {"01": {"in", "out", "sum"}, ...}} in GB."""
        if kind not in ("day", "month", "year"):
            raise RobotError("Ungültiger Zeitraum")
        if not ips and not subnets:
            return {}
        body: list[tuple[str, str]] = [("type", kind), ("from", start), ("to", end), ("single_values", "true")]
        body += [("ip[]", i) for i in ips] + [("subnet[]", s) for s in subnets]
        res = (self.request("POST", "traffic", body) or {}).get("traffic", {})
        return res.get("data") or {}


# ----------------------------------------------------------------------------- helpers
def month_range(year: int, month: int, today: Optional[date] = None) -> tuple[str, str]:
    import calendar
    today = today or date.today()
    last = calendar.monthrange(year, month)[1]
    if (year, month) == (today.year, today.month):
        last = today.day
    return f"{year:04d}-{month:02d}-01", f"{year:04d}-{month:02d}-{last:02d}"


def addresses_of(server: dict) -> tuple[list[str], list[str]]:
    """Single IPs and subnets ('ip/mask') of a server for the traffic query."""
    ips = sorted({str(x) for x in server.get("ip") or [] if x})
    nets = sorted({f"{s.get('ip')}/{s.get('mask')}" for s in server.get("subnet") or [] if s.get("ip")})
    return ips, nets


def sum_series(data: dict, keys: list[str]) -> tuple[dict, dict]:
    """Adds the single values of several addresses: ({"01": {...}}, total)."""
    series: dict[str, dict] = {}
    for k in keys:
        candidates = [k, k.split("/")[0]]
        values = next((data[c] for c in candidates if c in data), {}) or {}
        for slot, v in values.items():
            if not isinstance(v, dict):
                continue
            s = series.setdefault(str(slot), {"in": 0.0, "out": 0.0, "sum": 0.0})
            for f in ("in", "out", "sum"):
                try:
                    s[f] += float(v.get(f) or 0)
                except (TypeError, ValueError):
                    pass
    total = {f: round(sum(s[f] for s in series.values()), 3) for f in ("in", "out", "sum")}
    return dict(sorted(series.items())), total
