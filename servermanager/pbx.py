"""Asterisk / FreePBX over SSH: status (trunks, endpoints, extensions), extension management."""
from __future__ import annotations

import re
from typing import Optional

from .models import System

EXT_RE = re.compile(r"^[0-9]{2,8}$")
SECRET_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
NAME_RE = re.compile(r"^[^\x00-\x1f\"\\]{1,80}$")
EMAIL_RE = re.compile(r"^[^@\s,\"]+@[^@\s,\"]+\.[^@\s,\"]+$")
REG_OK = ("registered",)


class PbxError(Exception):
    pass


def _section(text: str, name: str) -> list[str]:
    marker = f"__{name}__"
    if marker not in text:
        return []
    part = text.split(marker, 1)[1]
    part = re.split(r"^__[A-Z]+__\s*$", part, maxsplit=1, flags=re.M)[0]
    return [ln.rstrip() for ln in part.splitlines() if ln.strip()]


def _table_rows(lines: list[str]) -> list[str]:
    """Data lines of an Asterisk CLI table (no headers, rulers or 'Objects found')."""
    out = []
    for ln in lines:
        s = ln.strip()
        if not s or s.startswith(("<", "=", "Objects found", "No objects found", "No such command")) \
                or re.match(r"^[A-Z][a-z]+:\s+<", s) or s.lower().startswith("host "):
            continue
        out.append(s)
    return out


def parse_registrations(lines: list[str]) -> list[dict]:
    """pjsip show registrations: '<name>/<uri>  <auth>  <status>  (exp. …)'."""
    regs = []
    for s in _table_rows(lines):
        parts = [x for x in re.split(r"\s{2,}", s) if not x.startswith("(exp")]
        if len(parts) < 2 or "/" not in parts[0]:
            continue
        name, _, uri = parts[0].partition("/")
        status = re.sub(r"\s*\(exp\..*\)$", "", parts[-1]).strip()
        regs.append({"name": name, "uri": uri, "auth": parts[1] if len(parts) > 2 else "", "status": status,
                     "ok": status.lower() in REG_OK, "tech": "pjsip"})
    return regs


def parse_sip_registry(lines: list[str]) -> list[dict]:
    """chan_sip: sip show registry."""
    regs = []
    states = ("Registered", "Unregistered", "Request Sent", "Auth. Sent", "Rejected", "Failed", "Timeout",
              "No Authentication")
    for s in _table_rows(lines):
        if s.endswith("SIP registrations.") or s.startswith("Host"):
            continue
        state = next((st for st in states if f" {st}" in f" {s}"), "")
        if not state:
            continue
        host = s.split()[0]
        user = s.split()[2] if len(s.split()) > 2 else ""
        regs.append({"name": host, "uri": host, "auth": user, "status": state, "ok": state == "Registered",
                     "tech": "sip"})
    return regs


def parse_contacts(lines: list[str]) -> dict[str, dict]:
    """pjsip show contacts -> {aor: {"status", "rtt", "uri"}} (best contact per AOR)."""
    out: dict[str, dict] = {}
    for s in _table_rows(lines):
        if not s.startswith("Contact:"):
            continue
        tok = s.split()
        if len(tok) < 4 or "/" not in tok[1]:
            continue
        aor, _, uri = tok[1].partition("/")
        status = tok[3] if len(tok) > 3 else ""
        rtt = tok[4] if len(tok) > 4 and re.match(r"^\d+(\.\d+)?$", tok[4]) else ""
        ok = status.lower() in ("avail", "reachable", "nonqual")
        prev = out.get(aor)
        if prev is None or (ok and not prev["ok"]):
            ip = re.search(r"@([^:;>]+)", uri)
            out[aor] = {"status": status, "rtt": rtt, "uri": uri, "ok": ok, "ip": ip.group(1) if ip else ""}
    return out


def parse_endpoints(lines: list[str]) -> list[dict]:
    """pjsip list endpoints: 'Endpoint:  <name>[/<cid>]  <state>  <n> of <max>'."""
    eps = []
    for s in _table_rows(lines):
        m = re.match(r"^Endpoint:\s+(\S+)\s+(.+?)\s+(\d+)\s+of\s+(\S+)\s*$", s)
        if not m:
            continue
        name = m.group(1).split("/", 1)[0]
        eps.append({"name": name, "state": m.group(2).strip(), "channels": int(m.group(3)),
                    "ok": m.group(2).strip().lower() not in ("unavailable", "invalid")})
    return eps


def parse_transports(lines: list[str]) -> list[dict]:
    out = []
    for s in _table_rows(lines):
        m = re.match(r"^Transport:\s+(\S+)\s+(udp|tcp|tls|ws|wss)\s+\d+\s+\d+\s+(\S+):(\d+)", s, re.I)
        if m:
            out.append({"name": m.group(1), "proto": m.group(2).lower(), "bind": m.group(3),
                        "port": int(m.group(4))})
    return out


def parse_extensions(lines: list[str]) -> list[dict]:
    out = []
    for ln in lines:
        parts = ln.split("\t")
        if not parts or not EXT_RE.match(parts[0].strip()):
            continue
        out.append({"ext": parts[0].strip(), "name": parts[1].strip() if len(parts) > 1 else "",
                    "tech": parts[2].strip() if len(parts) > 2 else "",
                    "voicemail": (parts[3].strip() if len(parts) > 3 else "") not in ("", "novm")})
    return out


def parse_status(text: str) -> dict:
    kv: dict[str, str] = {}
    head = text.split("__TRANSPORTS__", 1)[0]
    for ln in head.splitlines():
        k, sep, v = ln.partition("=")
        if sep and re.match(r"^[a-z_]+$", k.strip()):
            kv.setdefault(k.strip(), v.strip())
    ver = re.search(r"Asterisk\s+([0-9][\w.~-]*)", kv.get("version", ""))
    contacts = parse_contacts(_section(text, "CONTACTS"))
    regs = parse_registrations(_section(text, "REGS")) + parse_sip_registry(_section(text, "SIPREG"))
    endpoints = parse_endpoints(_section(text, "ENDPOINTS"))
    exts = parse_extensions(_section(text, "EXT"))
    ext_names = {e["ext"] for e in exts}
    for e in exts:
        c = contacts.get(e["ext"])
        e["online"] = bool(c and c["ok"])
        e["contact"] = c or {}
    # endpoints that are no extension are trunks (or other devices)
    trunks = [ep for ep in endpoints if ep["name"] not in ext_names and not EXT_RE.match(ep["name"])]
    for t in trunks:
        c = contacts.get(t["name"])
        t["contact"] = c or {}
        t["registration"] = next((r for r in regs if r["name"] == t["name"]), None)

    def num(key: str) -> int:
        try:
            return int(kv.get(key) or 0)
        except ValueError:
            return 0
    return {
        "version": ver.group(1) if ver else "", "freepbx": kv.get("freepbx", ""),
        "is_freepbx": kv.get("freepbx_installed") == "yes", "active": kv.get("active") == "yes",
        "uptime": num("uptime"), "calls": num("calls"), "channels": num("channels"), "processed": num("processed"),
        "nat": {k[4:]: v for k, v in kv.items() if k.startswith("nat_")},
        "rtp": {"start": num("rtpstart"), "end": num("rtpend")},
        "transports": parse_transports(_section(text, "TRANSPORTS")),
        "registrations": regs, "trunks": trunks, "extensions": exts,
        "endpoints_total": len(endpoints), "endpoints_unavailable": sum(1 for e in endpoints if not e["ok"]),
        "extensions_online": sum(1 for e in exts if e["online"]),
    }


def parse_upgrades(text: str) -> list[dict]:
    """fwconsole ma showupgrades: table rows '| module | local | online |'."""
    rows = []
    for ln in _section(text, "UPGRADES"):
        cells = [c.strip() for c in ln.strip().strip("|").split("|")]
        if len(cells) >= 3 and cells[0] and cells[0].lower() not in ("module", "rawname") \
                and re.match(r"^[a-z0-9_-]+$", cells[0]) and re.match(r"^\d", cells[1]):
            rows.append({"module": cells[0], "local": cells[1], "online": cells[2]})
    return rows


def alerts(data: dict) -> list[dict]:
    out = []
    if not data.get("active"):
        out.append({"key": "down", "severity": "crit", "text": "Asterisk läuft nicht"})
        return out
    for r in data.get("registrations", []):
        if not r["ok"]:
            out.append({"key": f"reg:{r['name']}", "severity": "crit",
                        "text": f"Trunk {r['name']} nicht registriert ({r['status']})"})
    for t in data.get("trunks", []):
        if not t["ok"] and not t.get("registration"):
            out.append({"key": f"trunk:{t['name']}", "severity": "warn",
                        "text": f"Trunk {t['name']} nicht erreichbar ({t['state']})"})
    return out


# --------------------------------------------------------------------------
# remote calls
# --------------------------------------------------------------------------
def run(conn, task: str, extra: Optional[dict] = None, timeout: int = 120) -> str:
    from .modules import get_module
    from .modules.base import run_module_script
    return run_module_script(conn, get_module("asterisk"), "asterisk.sh", dict(SM_TASK=task, **(extra or {})),
                             timeout=timeout)


def status(system: System) -> dict:
    from . import inventory
    with inventory.connect(system, timeout=15) as conn:
        return parse_status(run(conn, "status", timeout=90))


def validate_extension(ext: str, name: str = "", secret: str = "", email: str = "", pin: str = "") -> dict:
    if not EXT_RE.match(ext or ""):
        raise PbxError("Nebenstelle: 2–8 Ziffern")
    if name and not NAME_RE.match(name):
        raise PbxError("Ungültiger Name")
    if secret and not SECRET_RE.match(secret):
        raise PbxError("SIP-Passwort: 8–64 Zeichen aus Buchstaben, Ziffern, . _ -")
    if email and not EMAIL_RE.match(email):
        raise PbxError("Ungültige E-Mail-Adresse")
    if pin and not re.match(r"^[0-9]{4,10}$", pin):
        raise PbxError("Voicemail-PIN: 4–10 Ziffern")
    return {"SM_EXT": ext, "SM_NAME": name, "SM_SECRET": secret, "SM_VM_EMAIL": email, "SM_VM_PIN": pin}


def extension_task(system: System, task: str, env: dict) -> str:
    from . import inventory
    with inventory.connect(system, timeout=15) as conn:
        out = run(conn, task, env, timeout=300)
    if "SM_OK" not in out:
        raise PbxError(out.strip()[-300:] or "FreePBX meldet keinen Erfolg")
    return out


def sip_secret() -> str:
    import secrets
    import string
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(24))
