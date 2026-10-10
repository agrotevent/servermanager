"""Expected DNS records – Pangolin publications and mail (Mailcow) – compared with the zones at the registrar.

Rows of a check: ``{"key", "host", "type", "expected", "found", "state", "zone", "account_id", "note"}`` with
state ok | missing | wrong | wildcard | info | unmanaged. A fix is never taken from the browser: the row is
computed again by its key and its expected record is written (wrong records of the same kind are replaced).
"""
from __future__ import annotations

import socket
from typing import Callable, Optional
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from .dnsapi import DnsError, fqdn, in_zone, is_ip, same_record, zone_of
from .models import DnsAccount, MailcowServer, PangolinServer

Log = Callable[[str], None]
STATES = {"ok": "in Ordnung", "missing": "fehlt", "wrong": "abweichend", "wildcard": "über Platzhalter",
          "info": "Hinweis", "unmanaged": "Zone nicht verwaltet"}


# ----------------------------------------------------------------------------- zones and records
class Zones:
    """Which account manages which zone; records are fetched once per zone and check."""

    def __init__(self, db: Session, accounts: Optional[list[DnsAccount]] = None):
        self.accounts = accounts if accounts is not None else list(db.execute(select(DnsAccount)).scalars())
        self.by_zone: dict[str, DnsAccount] = {}
        for a in self.accounts:
            for z in (a.cache or {}).get("zones") or []:
                self.by_zone.setdefault(fqdn(z), a)
        self._clients: dict[int, object] = {}
        self._records: dict[str, list[dict]] = {}

    def zone(self, host: str) -> Optional[str]:
        return zone_of(host, list(self.by_zone))

    def client(self, account: DnsAccount):
        if account.id not in self._clients:
            from .integrations import dns_client
            self._clients[account.id] = dns_client(account)
        return self._clients[account.id]

    def records(self, zone: str) -> list[dict]:
        if zone not in self._records:
            self._records[zone] = self.client(self.by_zone[zone]).records(zone)
        return self._records[zone]

    def at(self, host: str, *types: str) -> list[dict]:
        zone = self.zone(host)
        if zone is None:
            return []
        return [r for r in self.records(zone) if r["name"] == fqdn(host) and (not types or r["type"] in types)]

    def write(self, zone: str, add: Optional[dict] = None, delete: tuple = ()) -> None:
        client = self.client(self.by_zone[zone])
        for r in delete:
            client.delete(zone, r)
        if add:
            client.add(zone, add)
        self._records.pop(zone, None)

    def close(self) -> None:
        for c in self._clients.values():
            c.close()


def _row(key: str, host: str, rtype: str, expected: str, found: list[str], state: str, zone: Optional[str],
         account: Optional[DnsAccount], note: str = "") -> dict:
    return {"key": key, "host": fqdn(host), "type": rtype, "expected": expected, "found": found, "state": state,
            "state_label": STATES[state], "zone": zone or "", "account_id": account.id if account else None,
            "account": account.name if account else "", "note": note}


# ----------------------------------------------------------------------------- Pangolin
def pangolin_target(pg: PangolinServer) -> str:
    """Where published host names point to: the configured target or the dashboard host of Pangolin."""
    if (pg.dns_target or "").strip():
        return fqdn(pg.dns_target)
    from .pangolin import dashboard_guess
    return fqdn(urlsplit(dashboard_guess(pg.api_url or "")).hostname or "")


def expected_host_record(host: str, target: str, zone: str, ttl: int) -> dict:
    """A/AAAA for an IP target, CNAME otherwise (A with the resolved address for the zone apex)."""
    host, target = fqdn(host), fqdn(target)
    if is_ip(target):
        return {"name": host, "type": "AAAA" if ":" in target else "A", "content": target, "ttl": ttl, "prio": 0}
    if host == fqdn(zone):
        try:
            ip = socket.getaddrinfo(target, 443, socket.AF_INET)[0][4][0]
        except OSError:
            raise DnsError(f"{target} lässt sich nicht auflösen – als DNS-Ziel eine IP-Adresse eintragen") from None
        return {"name": host, "type": "A", "content": ip, "ttl": ttl, "prio": 0}
    return {"name": host, "type": "CNAME", "content": target, "ttl": ttl, "prio": 0}


def check_host(zones: Zones, key: str, host: str, target: str) -> dict:
    zone = zones.zone(host)
    if zone is None:
        return _row(key, host, "A/CNAME", target, [], "unmanaged", None, None)
    account = zones.by_zone[zone]
    if not target:
        return _row(key, host, "A/CNAME", "", [], "info", zone, account,
                    "Kein DNS-Ziel – in der Pangolin-Verbindung eintragen")
    found = zones.at(host, "A", "AAAA", "CNAME")
    shown = [f"{r['type']} {r['content']}" for r in found]
    target_ips = {target} if is_ip(target) else set()
    if any((r["type"] == "CNAME" and r["content"] == target) or r["content"] in target_ips for r in found):
        return _row(key, host, "A/CNAME", target, shown, "ok", zone, account)
    if found:
        if not target_ips and all(r["type"] in ("A", "AAAA") for r in found):
            try:
                resolved = {i[4][0] for i in socket.getaddrinfo(target, 443)}
            except OSError:
                resolved = set()
            if resolved and all(r["content"] in resolved for r in found):
                return _row(key, host, "A/CNAME", target, shown, "ok", zone, account, "zeigt auf die Adresse des Ziels")
        return _row(key, host, "A/CNAME", target, shown, "wrong", zone, account)
    wild = [r for r in zones.records(zone) if r["type"] in ("A", "AAAA", "CNAME") and r["name"].startswith("*.")
            and in_zone(host, r["name"][2:]) and fqdn(host).count(".") == r["name"].count(".")]
    if wild:
        return _row(key, host, "A/CNAME", target, [f"{w['name']} {w['type']} {w['content']}" for w in wild],
                    "wildcard", zone, account)
    return _row(key, host, "A/CNAME", target, [], "missing", zone, account)


def pangolin_rows(db: Session, zones: Zones, pangolins: Optional[list[PangolinServer]] = None) -> list[dict]:
    rows = []
    for pg in pangolins if pangolins is not None else db.execute(select(PangolinServer)).scalars():
        target = pangolin_target(pg)
        for host in sorted(set((pg.cache or {}).get("published") or [])):
            if zones.zone(host):
                rows.append({**check_host(zones, f"pg:{pg.id}:{host}", host, target), "pangolin": pg.name})
    return rows


def ensure_published(db: Session, host: str, pg: PangolinServer, log: Log = lambda _m: None) -> str:
    """After publishing through Pangolin: create the missing record in a managed zone (accounts with
    "auto_pangolin"). Never raises – the publication itself has succeeded."""
    host = fqdn(host)
    if not host:
        return ""
    zones = Zones(db, [a for a in db.execute(select(DnsAccount)).scalars() if a.auto_pangolin])
    try:
        row = check_host(zones, f"pg:{pg.id}:{host}", host, pangolin_target(pg))
        if row["state"] == "missing":
            account = zones.by_zone[row["zone"]]
            rec = expected_host_record(host, pangolin_target(pg), row["zone"], account.default_ttl or 3600)
            zones.write(row["zone"], add=rec)
            msg = f"DNS: {rec['type']} {host} → {rec['content']} bei {account.name} angelegt"
        elif row["state"] == "wrong":
            msg = f"DNS: {host} zeigt auf {', '.join(row['found'])} statt auf {row['expected']} – bitte prüfen"
        elif row["state"] in ("ok", "wildcard"):
            msg = f"DNS: {host} ist eingerichtet ({row['state_label']})"
        else:
            msg = ""
    except (DnsError, ValueError) as exc:
        msg = f"DNS für {host} nicht angelegt: {exc}"
    finally:
        zones.close()
    if msg:
        log(msg)
    return msg


# ----------------------------------------------------------------------------- mail (Mailcow)
def spf_expected(ip: str) -> str:
    return f"v=spf1 mx ip4:{ip} -all" if ip and is_ip(ip) and ":" not in ip else "v=spf1 mx -all"


def _host_row(zones: Zones, key: str, host: str, ip: str) -> Optional[dict]:
    zone = zones.zone(host)
    if not zone or not ip:
        return None
    found = zones.at(host, "A", "AAAA", "CNAME")
    state = "ok" if any(r["type"] == "A" and r["content"] == ip for r in found) else ("wrong" if found else "missing")
    return _row(key, host, "A", ip, [f"{r['type']} {r['content']}" for r in found], state, zone, zones.by_zone[zone],
                "Mail-Hostname → eigene Mail-IP")


def mail_rows(zones: Zones, mc: MailcowServer, domains: list[str], dkim: dict[str, dict]) -> list[dict]:
    """Expected records of every mail domain. The mail host name is fixed (mail.example.com) or follows the
    domain ("post.[domain]" -> post.<domain> for each domain, with its own A record)."""
    from .mailcow import is_host_template, mail_host_for
    rows: list[dict] = []
    template = mc.mail_hostname or ""
    per_domain = is_host_template(template)
    ip = (mc.mail_public_ip or "").strip()
    if not template:
        return [_row(f"mc:{mc.id}:host", "", "MX", "", [], "info", None, None,
                     "Kein Mail-Hostname in der Mailcow-Verbindung eingetragen")]
    if not per_domain:
        row = _host_row(zones, f"mc:{mc.id}:host", fqdn(template), ip)
        if row:
            rows.append(row)
    for d in sorted({fqdn(x) for x in domains if x}):
        mx_host = fqdn(mail_host_for(template, d))
        dz = zones.zone(d)
        if dz is None:
            rows.append(_row(f"mc:{mc.id}:{d}:zone", d, "", "", [], "unmanaged", None, None))
            continue
        acc = zones.by_zone[dz]
        if per_domain:
            row = _host_row(zones, f"mc:{mc.id}:{d}:host", mx_host, ip)
            if row:
                rows.append(row)
        # MX
        mx = zones.at(d, "MX")
        st = "ok" if any(r["content"] == mx_host for r in mx) else ("wrong" if mx else "missing")
        rows.append(_row(f"mc:{mc.id}:{d}:mx", d, "MX", f"10 {mx_host}", [f"{r['prio']} {r['content']}" for r in mx],
                         st, dz, acc))
        # SPF
        spf = [r for r in zones.at(d, "TXT") if r["content"].lower().startswith("v=spf1")]
        good = [r for r in spf if " mx" in f" {r['content'].lower()}" or (ip and f"ip4:{ip}" in r["content"])
                or f"a:{mx_host}" in r["content"].lower() or "include:" in r["content"].lower()]
        st = "ok" if good and len(spf) == 1 else ("wrong" if spf else "missing")
        note = "mehrere SPF-Einträge – es darf nur einen geben" if len(spf) > 1 else ""
        rows.append(_row(f"mc:{mc.id}:{d}:spf", d, "TXT (SPF)", spf_expected(ip), [r["content"] for r in spf], st, dz,
                         acc, note))
        # DKIM
        key = dkim.get(d) or {}
        if key.get("dkim_txt"):
            name = f"{key.get('dkim_selector') or 'dkim'}._domainkey.{d}"
            have = zones.at(name, "TXT")
            want = "".join(key["dkim_txt"].split())
            st = "ok" if any("".join(r["content"].split()) == want for r in have) else ("wrong" if have else "missing")
            rows.append(_row(f"mc:{mc.id}:{d}:dkim", name, "TXT (DKIM)", key["dkim_txt"],
                             [r["content"][:60] + ("…" if len(r["content"]) > 60 else "") for r in have], st, dz, acc))
        else:
            rows.append(_row(f"mc:{mc.id}:{d}:dkim", f"dkim._domainkey.{d}", "TXT (DKIM)", "", [], "info", dz, acc,
                             "In Mailcow ist für diese Domain noch kein DKIM-Schlüssel angelegt"))
        # DMARC
        dmarc = [r for r in zones.at(f"_dmarc.{d}", "TXT") if r["content"].lower().startswith("v=dmarc1")]
        rows.append(_row(f"mc:{mc.id}:{d}:dmarc", f"_dmarc.{d}", "TXT (DMARC)", "v=DMARC1; p=quarantine",
                         [r["content"] for r in dmarc], "ok" if dmarc else "missing", dz, acc))
        # autodiscover / autoconfig
        for sub in ("autodiscover", "autoconfig"):
            host = f"{sub}.{d}"
            found = zones.at(host, "A", "AAAA", "CNAME")
            ok = any((r["type"] == "CNAME" and r["content"] == mx_host) or (ip and r["content"] == ip) for r in found)
            rows.append(_row(f"mc:{mc.id}:{d}:{sub}", host, "CNAME", mx_host,
                             [f"{r['type']} {r['content']}" for r in found],
                             "ok" if ok else ("wrong" if found else "missing"), dz, acc))
        srv = zones.at(f"_autodiscover._tcp.{d}", "SRV")
        ok = any(r["content"].split()[-1:] == [mx_host] for r in srv)
        rows.append(_row(f"mc:{mc.id}:{d}:srv", f"_autodiscover._tcp.{d}", "SRV", f"0 1 443 {mx_host}",
                         [f"{r['prio']} {r['content']}" for r in srv], "ok" if ok else ("wrong" if srv else "missing"),
                         dz, acc))
    return rows


def mail_fix_record(row: dict, ttl: int) -> tuple[dict, list[str]]:
    """(record to write, types of records at the same name that it replaces)."""
    kind = row["key"].rsplit(":", 1)[-1]
    host = row["host"]
    if kind == "host":
        return {"name": host, "type": "A", "content": row["expected"], "ttl": ttl, "prio": 0}, ["A", "AAAA", "CNAME"]
    if kind == "mx":
        return {"name": host, "type": "MX", "content": row["expected"].split()[-1], "ttl": ttl, "prio": 10}, ["MX"]
    if kind in ("spf", "dkim", "dmarc"):
        return {"name": host, "type": "TXT", "content": row["expected"], "ttl": ttl, "prio": 0}, ["TXT"]
    if kind in ("autodiscover", "autoconfig"):
        return {"name": host, "type": "CNAME", "content": row["expected"], "ttl": ttl, "prio": 0}, ["A", "AAAA", "CNAME"]
    if kind == "srv":
        return {"name": host, "type": "SRV", "content": "1 443 " + row["expected"].split()[-1], "ttl": ttl,
                "prio": 0}, ["SRV"]
    raise DnsError("Für diesen Eintrag gibt es keine Korrektur")


def fix(zones: Zones, row: dict, rec: dict, replaces: list[str]) -> str:
    """Write the expected record; records of the same name it replaces are removed first (for TXT only those
    of the same kind: SPF, DKIM or DMARC)."""
    if row["state"] not in ("missing", "wrong") or not row["zone"]:
        raise DnsError("Nichts zu tun")
    zone = row["zone"]
    old = [r for r in zones.at(rec["name"], *replaces)]
    if rec["type"] == "TXT":
        prefix = rec["content"].split(";")[0].split()[0].lower()   # v=spf1 / v=DKIM1 / v=DMARC1
        old = [r for r in old if r["content"].lower().startswith(prefix)]
    if any(same_record(r, rec) for r in old) and len(old) == 1:
        return f"{rec['name']} ist bereits richtig"
    zones.write(zone, add=rec, delete=tuple(old))
    return (f"{rec['type']} {rec['name']} → {rec['content'][:80]} angelegt"
            + (f" ({len(old)} alte(r) Eintrag/Einträge ersetzt)" if old else ""))
