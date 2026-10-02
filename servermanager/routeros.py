"""RouterOS 7 (e.g. CHR): configuration import, analysis against the target setup and fixes.

Target setup ("Soll")::

    Internet ── WAN (public IP) ── RouterOS ── LAN bridge (DHCP) ── LXC with Newt ─→ Pangolin
                                                             └── further services

* the internal network gets its addresses from the RouterOS DHCP server,
* the services reach the internet through source NAT (masquerade) on the WAN
  interface - optionally with policy routing (mangle marks + own routing table),
  so that e.g. a management WireGuard tunnel with wide AllowedIPs does not
  swallow the internet traffic and replies to connections that came in via WAN
  leave via WAN again,
* published services are reached through the Pangolin tunnel (Newt only needs
  outgoing connections - no port forwarding).

The running configuration is imported (REST API or a pasted ``/export``) and
compared with that target. Every finding says whether the current state can
stay, has to be changed or is missing. Additive and uncritical changes can be
applied through the API; everything that could lock the administrator out
(firewall input chain, IP services, users) is only emitted as a script.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any, Callable, Iterable, Optional

from .mikrotik import MikroTik, MikroTikError

TAG = "servermanager"

# menus read for the analysis (REST paths)
SNAPSHOT_MENUS = [
    "system/resource", "system/identity", "system/routerboard", "system/ntp/client",
    "interface", "interface/bridge", "interface/bridge/port", "interface/list", "interface/list/member",
    "interface/wireguard", "interface/wireguard/peers", "interface/vlan",
    "ip/address", "ip/route", "ip/pool", "ip/dhcp-client",
    "ip/dhcp-server", "ip/dhcp-server/network", "ip/dhcp-server/lease",
    "ip/dns", "ip/dns/static",
    "ip/dhcp-server/option", "ip/ipsec/policy",
    "ip/firewall/filter", "ip/firewall/nat", "ip/firewall/mangle", "ip/firewall/raw", "ip/firewall/address-list",
    "ip/firewall/service-port", "routing/table", "routing/rule",
    "ip/service", "ip/neighbor/discovery-settings", "tool/mac-server", "tool/mac-server/mac-winbox",
    "user", "user/group",
]
SINGLETONS = {"system/resource", "system/identity", "system/routerboard", "system/ntp/client", "ip/dns",
              "ip/neighbor/discovery-settings", "tool/mac-server", "tool/mac-server/mac-winbox"}

DEFAULT_SERVICES = [  # RouterOS 7 defaults (a plain export only lists changes)
    {"name": "telnet", "port": "23", "disabled": "false", "address": ""},
    {"name": "ftp", "port": "21", "disabled": "false", "address": ""},
    {"name": "www", "port": "80", "disabled": "false", "address": ""},
    {"name": "ssh", "port": "22", "disabled": "false", "address": ""},
    {"name": "www-ssl", "port": "443", "disabled": "true", "address": ""},
    {"name": "api", "port": "8728", "disabled": "false", "address": ""},
    {"name": "winbox", "port": "8291", "disabled": "false", "address": ""},
    {"name": "api-ssl", "port": "8729", "disabled": "false", "address": ""},
]

PRIVATE_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"]


class RouterOSError(Exception):
    pass


# ==========================================================================
# helpers
# ==========================================================================
def yes(value: Any, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    return str(value).lower() in ("true", "yes")


def items(snap: dict, menu: str) -> list[dict]:
    return list((snap.get("menus") or {}).get(menu) or [])


def have_menu(snap: dict, menu: str) -> bool:
    """The menu was read: an API snapshot lists it (also when empty), an export leaves empty menus out."""
    return menu in (snap.get("menus") or {}) or \
        (snap.get("source") == "export" and menu not in (snap.get("errors") or {}))


def single(snap: dict, menu: str) -> dict:
    lst = items(snap, menu)
    return lst[0] if lst else {}


def enabled(item: dict) -> bool:
    return not yes(item.get("disabled")) and not yes(item.get("invalid"))


def ours(item: dict) -> bool:
    return str(item.get("comment", "")).startswith(TAG)


def net_of(value: str) -> Optional[ipaddress.IPv4Network]:
    try:
        return ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return None


def iface_of(value: str) -> Optional[ipaddress.IPv4Interface]:
    try:
        return ipaddress.ip_interface(str(value).strip())
    except ValueError:
        return None


def is_public(ip: Any) -> bool:
    try:
        a = ipaddress.ip_address(str(ip).split("/")[0])
    except ValueError:
        return False
    return a.is_global


def split_list(value: str) -> list[str]:
    return [v.strip() for v in re.split(r"[,\s]+", value or "") if v.strip()]


def version_tuple(version: str) -> tuple[int, ...]:
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", version or "")
    return tuple(int(x or 0) for x in m.groups()) if m else (0,)


def quote_cli(value: Any) -> str:
    s = str(value)
    if s and re.match(r"^[A-Za-z0-9_./:,!*+@-]+$", s):
        return s
    s = s.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")
    # line breaks would start a new command when the script is pasted: RouterOS escapes instead
    s = s.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    s = re.sub(r"[\x00-\x1f\x7f]", "", s)
    return '"' + s + '"'


def in_iface_list(snap: dict, iface: str, name: str, _seen: frozenset = frozenset()) -> Optional[bool]:
    """Is iface in the interface list `name`? Direct members, include/exclude of other lists and the predefined
    lists all/none/static/dynamic. None: cannot be decided (include cycle, interface unknown)."""
    if name in ("all", "none"):
        return name == "all"
    if name in ("static", "dynamic"):
        it = next((i for i in items(snap, "interface") if i.get("name") == iface), None)
        if it is None:
            return None
        return yes(it.get("dynamic")) == (name == "dynamic")   # an export only contains static interfaces
    if name in _seen:
        return None
    seen = _seen | {name}
    lst = next((x for x in items(snap, "interface/list") if x.get("name") == name and enabled(x)), {})

    def any_of(names: str) -> Optional[bool]:
        res = [in_iface_list(snap, iface, n, seen) for n in split_list(names)]
        return True if True in res else (None if None in res else False)

    inc = True if any(m.get("interface") == iface and m.get("list") == name and enabled(m)
                      for m in items(snap, "interface/list/member")) else any_of(lst.get("include", ""))
    exc = any_of(lst.get("exclude", ""))
    if exc is True or inc is False:
        return False
    return True if inc is True and exc is False else None


def rule_matches_iface(rule: dict, key: str, iface: str, snap: dict) -> bool:
    """rule's in-/out-interface(-list) matches iface (positive match only)."""
    direct = rule.get(f"{key}-interface", "")
    if direct:
        return direct == iface
    lst = rule.get(f"{key}-interface-list", "")
    if lst:
        return not lst.startswith("!") and in_iface_list(snap, iface, lst) is True
    return False


# ==========================================================================
# firewall rule evaluation (which rule decides about a probe packet?)
# ==========================================================================
ORPHAN_RE = re.compile(r"^\*[0-9A-Fa-f]+$")   # reference to a deleted interface (internal id)
BUILTIN_CHAINS = {"input", "forward", "output", "prerouting", "postrouting", "srcnat", "dstnat"}
DROP_ACTIONS = {"drop", "reject", "tarpit"}
NONTERMINAL_ACTIONS = {"log", "passthrough", "add-src-to-address-list", "add-dst-to-address-list",
                       "fasttrack-connection"}
# properties that do not restrict which packets a rule matches
RULE_META = {".id", ".nextid", "chain", "action", "comment", "log", "log-prefix", "disabled", "invalid", "dynamic",
             "bytes", "packets", "jump-target", "reject-with", "address-list", "address-list-timeout", "hw-offload",
             "passthrough", "to-addresses", "to-ports", "place-before"}
PROTO_NAMES = {"1": "icmp", "6": "tcp", "17": "udp"}


def _is_meta(key: str) -> bool:
    return key in RULE_META or key.startswith("new-")


def unconditional(rule: dict) -> bool:
    """The rule has no matcher at all - it applies to every packet of its chain."""
    return not any(v not in ("", None) for k, v in rule.items() if not _is_meta(k))


def _neg(value: Any) -> tuple[bool, str]:
    v = str(value)
    return (True, v[1:]) if v.startswith("!") else (False, v)


def _addr_match(spec: str, ip: str) -> Optional[bool]:
    """a.b.c.d, a.b.c.d/nn or a.b.c.d-e.f.g.h; None if not evaluable (e.g. a DNS name)."""
    try:
        addr = ipaddress.ip_address(ip)
        if "-" in spec:
            lo, hi = spec.split("-", 1)
            return ipaddress.ip_address(lo.strip()) <= addr <= ipaddress.ip_address(hi.strip())
    except ValueError:
        return None
    n = net_of(spec)
    return None if n is None else addr in n


def _list_match(snap: dict, name: str, ip: str) -> Optional[bool]:
    unknown = False
    for e in items(snap, "ip/firewall/address-list"):
        if e.get("list") != name or not enabled(e):
            continue
        r = _addr_match(str(e.get("address", "")), ip)
        if r:
            return True
        unknown = unknown or r is None
    return None if unknown else False


def _port_match(spec: str, port: int) -> Optional[bool]:
    for part in (p.strip() for p in spec.split(",") if p.strip()):
        lo, _, hi = part.partition("-")
        if not lo.isdigit() or (hi and not hi.isdigit()):
            return None
        if int(lo) <= port <= int(hi or lo):
            return True
    return False


def _proto(value: Any) -> str:
    v = str(value or "")
    return PROTO_NAMES.get(v, v)


def _matcher(key: str, val: str, pkt: dict, snap: dict) -> Optional[bool]:
    """Does one (not negated) matcher apply to the probe packet? None: cannot be decided statically."""
    if key in ("in-interface", "out-interface"):
        ifc = pkt.get("in" if key == "in-interface" else "out")
        return ifc == val if ifc else False
    if key in ("in-interface-list", "out-interface-list"):
        ifc = pkt.get("in" if key == "in-interface-list" else "out")
        return in_iface_list(snap, ifc, val) if ifc else False
    if key in ("src-address", "dst-address"):
        return _addr_match(val, pkt["src" if key == "src-address" else "dst"])
    if key in ("src-address-list", "dst-address-list"):
        return _list_match(snap, val, pkt["src" if key == "src-address-list" else "dst"])
    if key == "protocol":
        return _proto(val) == pkt["proto"]
    if key in ("dst-port", "src-port", "port"):
        if pkt["proto"] not in ("tcp", "udp"):
            return False
        ports = {"dst-port": [pkt["dport"]], "src-port": [pkt["sport"]], "port": [pkt["dport"], pkt["sport"]]}[key]
        res = [_port_match(val, p) for p in ports]
        return True if True in res else (None if None in res else False)
    if key == "connection-state":
        return pkt["state"] in split_list(val)
    if key == "connection-nat-state":
        return any(x in pkt.get("nat", ()) for x in split_list(val))
    if key in ("dst-address-type", "src-address-type"):
        return any(x in pkt["dst_type" if key == "dst-address-type" else "src_type"] for x in split_list(val))
    if key == "tcp-flags":
        if pkt["proto"] != "tcp":
            return False
        for flag in split_list(val):
            neg, name = _neg(flag)
            if (name in pkt.get("flags", ())) == neg:
                return False
        return True
    if key == "icmp-options":
        return None if pkt["proto"] == "icmp" else False
    if key == "ipsec-policy":
        direction, _, policy = val.partition(",")
        if direction == "in":
            return policy == "none"   # a probe packet never comes out of an IPsec tunnel
        if not have_menu(snap, "ip/ipsec/policy"):
            return None
        res = [rule_matches({k: p[k] for k in ("src-address", "dst-address") if p.get(k)}, pkt, snap)
               for p in items(snap, "ip/ipsec/policy") if enabled(p) and not yes(p.get("template"))]
        hit = True if True in res else (None if None in res else False)
        return hit if hit is None or policy == "ipsec" else not hit
    return None  # limit, dst-limit, psd, time, marks, layer7, ... - depends on traffic


def rule_matches(rule: dict, pkt: dict, snap: dict) -> Optional[bool]:
    """True/False, or None when a matcher cannot be decided statically (rate limits, marks, ...)."""
    unknown = False
    for key, raw in rule.items():
        if _is_meta(key) or raw in ("", None):
            continue
        # tcp-flags: "!" negates the single flag ("!fin,!syn" = neither set), not the whole matcher
        neg, val = (False, str(raw)) if key == "tcp-flags" else _neg(raw)
        res = _matcher(key, val, pkt, snap)
        if res is None:
            unknown = True
        elif res == neg:
            return False
    return None if unknown else True


Verdict = tuple[str, Optional[dict], Optional[dict]]


def _eval_chain(rules: list[dict], chain: str, pkt: dict, snap: dict, depth: int = 0, start: int = 0,
                forks: int = 0) -> Verdict:
    """-> (verdict, deciding rule, rule of this chain that led there) - verdict accept | drop | uncertain |
    return | "" (end of a user chain)."""

    def hit(r: dict) -> Optional[Verdict]:
        """result when r matches; None: evaluation goes on behind r"""
        action = r.get("action") or "accept"
        if action == "accept":
            return "accept", r, r
        if action in DROP_ACTIONS:
            return "drop", r, r
        if action == "return":   # in a built-in chain: end of the chain = its policy (accept)
            return ("accept", None, None) if chain in BUILTIN_CHAINS else ("return", r, r)
        if action == "jump" and depth < 16:
            verdict, rule, _top = _eval_chain(rules, r.get("jump-target", ""), pkt, snap, depth + 1, 0, forks)
            return (verdict, rule, r) if verdict in ("accept", "drop", "uncertain") else None
        return "uncertain", r, r

    for i in range(start, len(rules)):
        r = rules[i]
        if r.get("chain") != chain or not enabled(r) or (r.get("action") or "accept") in NONTERMINAL_ACTIONS:
            continue
        m = rule_matches(r, pkt, snap)
        if m is False:
            continue
        res = hit(r)
        if m is True:
            if res is None:
                continue
            return res
        # undecidable rule (rate limit, mark, ...): it only matters if matching it ends elsewhere than skipping it
        rest = _eval_chain(rules, chain, pkt, snap, depth, i + 1, forks + 1) if forks < 64 else ("uncertain", r, r)
        res = res or rest
        same = {res[0], rest[0]} <= {"return", ""} or res[0] == rest[0] != "uncertain"
        return rest if same else ("uncertain", r, r)
    return ("accept", None, None) if chain in BUILTIN_CHAINS else ("", None, None)


def probe(snap: dict, chain: str, pkt: dict) -> Verdict:
    """Run a new connection's first packet through raw prerouting and the filter chain (input or forward)."""
    for menu, ch in (("ip/firewall/raw", "prerouting"), ("ip/firewall/filter", chain)):
        verdict, rule, top = _eval_chain(items(snap, menu), ch, pkt, snap)
        if verdict != "accept":
            return verdict, rule, top
    return "accept", None, None


def _q(value: Any) -> str:
    """value for a [ find where ... ] expression"""
    s = str(value)
    if re.match(r"^[A-Za-z0-9_./:-]+$", s):
        return s
    return '"' + _cli_escape(s).replace('"', '\\"').replace("$", "\\$") + '"'


def _cli_escape(text: str) -> str:
    """backslashes and control characters escaped - a raw line break would start a new command in a script"""
    s = str(text).replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return re.sub(r"[\x00-\x1f\x7f]", "", s)


FIND_KEYS = ("chain", "action", "protocol", "in-interface", "in-interface-list", "out-interface", "out-interface-list",
             "src-address", "dst-address", "src-address-list", "dst-address-list", "dst-port", "connection-state",
             "connection-nat-state", "jump-target", "log-prefix")


def find_expr(rule: dict, rules: list[dict]) -> str:
    """Conditions for [ find where ... ] that select this rule - via its comment when that is unique."""
    c = rule.get("comment")
    if c and sum(1 for r in rules if r.get("comment") == c) == 1:
        return f"comment={_q(c)}"
    return " ".join(f"{k}={_q(rule[k])}" for k in FIND_KEYS if rule.get(k))


def _find_unique(rule: dict, rules: list[dict]) -> bool:
    c = rule.get("comment")
    if c and sum(1 for r in rules if r.get("comment") == c) == 1:
        return True
    keys = [k for k in FIND_KEYS if rule.get(k)]
    return sum(1 for r in rules if all(r.get(k) == rule.get(k) for k in keys)) == 1


def cli_menu(menu: str) -> str:
    return "/" + menu.replace("/", " ")


# ==========================================================================
# import
# ==========================================================================
def snapshot_from_api(mt: MikroTik, progress: Optional[Callable[[str], None]] = None) -> dict:
    menus: dict[str, list[dict]] = {}
    errors: dict[str, str] = {}
    for menu in SNAPSHOT_MENUS:
        try:
            res = mt._req("GET", menu)
            menus[menu] = [res] if isinstance(res, dict) else list(res or [])
        except MikroTikError as exc:
            if "401" in str(exc) or "Anmeldung" in str(exc) or "nicht erreichbar" in str(exc):
                raise
            errors[menu] = str(exc)
        if progress:
            progress(menu)
    return {"source": "api", "menus": menus, "errors": errors,
            "version": (menus.get("system/resource") or [{}])[0].get("version", ""),
            "taken_at": datetime.now().isoformat(timespec="seconds")}


_CMD_WORDS = {"add", "set", "remove", "enable", "disable", "print", "export"}
_SECTION_RE = re.compile(r"^/([a-z0-9-]+(?: [a-z0-9-]+)*)(?:\s+(.*))?$")


def _tokens(line: str) -> list[str]:
    """Split a RouterOS CLI line into tokens (quotes, escapes and [ find ... ] kept together)."""
    out: list[str] = []
    buf = ""
    i, n = 0, len(line)
    in_q = False
    depth = 0
    while i < n:
        c = line[i]
        if in_q:
            if c == "\\" and i + 1 < n:
                nxt = line[i + 1]
                buf += {"n": "\n", "t": "\t", "r": "\r"}.get(nxt, nxt)
                i += 2
                continue
            if c == '"':
                in_q = False
            else:
                buf += c
        elif c == '"':
            in_q = True
        elif c == "[":
            depth += 1
            buf += c
        elif c == "]":
            depth -= 1
            buf += c
        elif c.isspace() and depth == 0:
            if buf:
                out.append(buf)
                buf = ""
        else:
            buf += c
        i += 1
    if buf:
        out.append(buf)
    return out


def _kv(tokens: Iterable[str]) -> tuple[dict, list[str]]:
    data: dict[str, str] = {}
    rest: list[str] = []
    for t in tokens:
        if "=" in t and not t.startswith("["):
            k, v = t.split("=", 1)
            data[k] = v
        else:
            rest.append(t)
    return data, rest


def _find_filter(expr: str) -> dict:
    """[ find default-name=ether1 ] -> {"default-name": "ether1"}"""
    inner = expr.strip()[1:-1].strip()
    if inner.startswith("find"):
        inner = inner[4:]
    data, _ = _kv(_tokens(inner))
    return data


def parse_export(text: str) -> dict:
    """Parse the output of ``/export`` (compact or terse) into the snapshot format."""
    menus: dict[str, list[dict]] = {}
    version = ""
    lines: list[str] = []
    cur = ""
    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if line.startswith("#"):
            m = re.search(r"RouterOS (\d+\.\d+(?:\.\d+)?)", line)
            if m and not version:
                version = m.group(1)
            continue
        if cur:
            line = cur + line.lstrip()
            cur = ""
        if line.endswith("\\"):
            cur = line[:-1]
            continue
        if line.strip():
            lines.append(line.strip())
    if cur.strip():
        lines.append(cur.strip())

    section = ""
    for line in lines:
        if line.startswith("/"):
            m = _SECTION_RE.match(line)
            if not m:
                continue
            words = m.group(1).split(" ")
            path: list[str] = []
            cmd_rest = m.group(2) or ""
            for idx, w in enumerate(words):
                if w in _CMD_WORDS:
                    cmd_rest = " ".join(words[idx:]) + (" " + cmd_rest if cmd_rest else "")
                    break
                path.append(w)
            section = "/".join(path)
            line = cmd_rest.strip()
            if not line:
                continue
        toks = _tokens(line)
        if not toks or not section:
            continue
        cmd, args = toks[0], toks[1:]
        lst = menus.setdefault(section, [])
        if cmd == "add":
            data, _ = _kv(args)
            lst.append(data)
        elif cmd == "set":
            data, rest = _kv(args)
            target: Optional[dict] = None
            if rest and rest[0].startswith("["):
                flt = _find_filter(rest[0])
                for it in lst:
                    if all(it.get(k) == v for k, v in flt.items()):
                        target = it
                        break
                if target is None:
                    target = dict(flt)
                    lst.append(target)
            elif rest:
                name = rest[0]
                for it in lst:
                    if it.get("name") == name or it.get("numbers") == name:
                        target = it
                        break
                if target is None:
                    target = {"name": name}
                    lst.append(target)
            else:
                if not lst:
                    lst.append({})
                target = lst[0]
            target.update(data)

    # RouterOS only exports changes from the defaults - fill in the relevant defaults
    services = {s["name"]: dict(s) for s in DEFAULT_SERVICES}
    for s in menus.get("ip/service", []):
        if s.get("name") in services:
            services[s["name"]].update(s)
    menus["ip/service"] = list(services.values())
    for it in menus.get("ip/firewall/filter", []) + menus.get("ip/firewall/nat", []) + \
            menus.get("ip/firewall/mangle", []) + menus.get("ip/firewall/raw", []):
        it.setdefault("disabled", "no")
    # synthesized interface list: all typed interface menus + interfaces referenced elsewhere
    ifaces: dict[str, dict] = {}
    for menu, lst in menus.items():
        if menu.startswith("interface/") and menu.count("/") == 1 and menu not in ("interface/list",):
            itype = {"ethernet": "ether", "wireguard": "wg"}.get(menu.split("/")[1], menu.split("/")[1])
            for it in lst:
                name = it.get("name") or it.get("default-name")
                if name:
                    ifaces[name] = {"name": name, "type": itype, "disabled": it.get("disabled", "no"),
                                    "mtu": it.get("mtu", "")}
    for menu in ("ip/address", "ip/dhcp-client", "ip/dhcp-server", "interface/bridge/port",
                 "interface/list/member"):
        for it in menus.get(menu, []):
            name = it.get("interface")
            if name and name not in ifaces:
                ifaces[name] = {"name": name, "type": "ether" if name.startswith("ether") else "",
                                "disabled": "no"}
    port_mtus: dict[str, list[int]] = {}
    for p in menus.get("interface/bridge/port", []):
        mtu = str(ifaces.get(p.get("interface"), {}).get("mtu", ""))
        if mtu.isdigit() and not yes(p.get("disabled")):
            port_mtus.setdefault(p.get("bridge", ""), []).append(int(mtu))
    for name, mtus in port_mtus.items():
        br = ifaces.get(name)
        if br and br.get("type") == "bridge" and not str(br.get("mtu", "")).isdigit():
            br["actual-mtu"] = str(min(mtus))   # what the API reports for an auto-MTU bridge
    menus["interface"] = list(ifaces.values())
    if version:
        menus.setdefault("system/resource", [{}])[0].setdefault("version", version)
    return {"source": "export", "menus": menus, "errors": {}, "version": version,
            "taken_at": datetime.now().isoformat(timespec="seconds")}


# ==========================================================================
# target detection
# ==========================================================================
def default_route(snap: dict) -> Optional[dict]:
    for r in items(snap, "ip/route"):
        if r.get("dst-address") == "0.0.0.0/0" and r.get("routing-table", "main") in ("main", "") \
                and enabled(r) and not yes(r.get("blackhole")):
            return r
    return None


def wan_gateway(snap: dict) -> str:
    r = default_route(snap)
    if r:
        gw = str(r.get("gateway", "")).split("%")[0]
        if gw and re.match(r"^\d+\.\d+\.\d+\.\d+$", gw):
            return gw
    for c in items(snap, "ip/dhcp-client"):
        if c.get("gateway"):
            return c["gateway"]
    return ""


def detect_target(snap: dict, mgmt_default: str = "") -> dict:
    addrs = [a for a in items(snap, "ip/address") if enabled(a)]
    wan = ""
    r = default_route(snap)
    if r:
        imm = str(r.get("immediate-gw", "") or r.get("gateway", ""))
        if "%" in imm:
            wan = imm.split("%", 1)[1]
        else:
            gw = imm.split(",")[0]
            for a in addrs:
                i = iface_of(a.get("address", ""))
                if i and gw and _in_net(gw, i.network):
                    wan = a.get("interface", "")
                    break
    if not wan:
        for c in items(snap, "ip/dhcp-client"):
            if enabled(c):
                wan = c.get("interface", "")
                break
    if not wan:
        for a in addrs:
            if is_public(a.get("address", "")):
                wan = a.get("interface", "")
                break
    bridges = {b.get("name") for b in items(snap, "interface/bridge")}
    # interfaces that serve clients: DHCP server or member of the interface list LAN
    serving = {s.get("interface") for s in items(snap, "ip/dhcp-server") if enabled(s)} | \
        {a.get("interface") for a in addrs if in_iface_list(snap, a.get("interface", ""), "LAN") is True}
    lan, lan_addr = "", ""
    for prefer in (bridges & serving, serving, bridges, None):
        for a in addrs:
            ifc = a.get("interface", "")
            i = iface_of(a.get("address", ""))
            if not i or ifc == wan or is_public(i.ip) or yes(a.get("dynamic")) or ORPHAN_RE.match(ifc) \
                    or i.network.prefixlen >= 31:
                continue
            if prefer is not None and ifc not in prefer:
                continue
            if any(w.get("name") == ifc for w in items(snap, "interface/wireguard")):
                continue
            lan, lan_addr = ifc, str(i)
            break
        if lan:
            break
    if not lan:
        lan, lan_addr = "bridge-lan", "10.20.0.1/24"
    lan_if = iface_of(lan_addr)
    net = lan_if.network if lan_if else ipaddress.ip_network("10.20.0.0/24")
    hosts = list(net.hosts())
    rng = f"{hosts[min(99, len(hosts) - 1)]}-{hosts[min(198, len(hosts) - 1)]}" if len(hosts) > 2 else ""
    for srv in items(snap, "ip/dhcp-server"):
        if srv.get("interface") == lan:
            for p in items(snap, "ip/pool"):
                if p.get("name") == srv.get("address-pool") and p.get("ranges"):
                    rng = p["ranges"]
    dns = single(snap, "ip/dns").get("servers", "") or "1.1.1.1,9.9.9.9"
    wg = [w.get("name") for w in items(snap, "interface/wireguard")]
    tables = [t for t in items(snap, "routing/table") if t.get("name") not in ("main", "")]
    return {
        "wan_interface": wan or "ether1",
        "lan_interface": lan,
        "lan_address": lan_addr,
        "dhcp_range": rng,
        "dns_servers": dns,
        "policy_routing": bool(wg or tables),
        "routing_table": "sm-inet",
        "mss_clamp": bool(wg),
        "mgmt_addresses": mgmt_default,
        "ntp_servers": "pool.ntp.org",
    }


def _in_net(ip: str, net) -> bool:
    try:
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


def internal_networks(snap: dict, wan: str) -> list[dict]:
    """Internal IPv4 networks of the router: a private address on an interface that serves clients (DHCP server,
    member of the interface list LAN or a bridge). WAN, WireGuard tunnels and transfer nets (/31, /32) are left out."""
    wg = {w.get("name") for w in items(snap, "interface/wireguard")}
    ifaces = {i.get("name"): i for i in items(snap, "interface")}
    dhcp = {s.get("interface") for s in items(snap, "ip/dhcp-server") if enabled(s)}
    bridges = {b.get("name") for b in items(snap, "interface/bridge")}
    out: list[dict] = []
    seen: set = set()
    for a in items(snap, "ip/address"):
        ifc = a.get("interface", "")
        i = iface_of(a.get("address", ""))
        if not enabled(a) or yes(a.get("dynamic")) or not i or i.version != 4 or i.network.prefixlen >= 31:
            continue
        if ifc == wan or ifc in wg or ORPHAN_RE.match(ifc) or is_public(i.ip) or (ifc, i.network) in seen:
            continue
        info = ifaces.get(ifc, {})
        if yes(info.get("disabled")) or str(info.get("type", "")).startswith(L3_TUNNEL_TYPES + PPP_TYPES):
            continue
        if not (ifc in dhcp or ifc in bridges or in_iface_list(snap, ifc, "LAN") is True):
            continue
        seen.add((ifc, i.network))
        out.append({"iface": ifc, "ip": str(i.ip), "net": i.network, "address": str(i), "dhcp": ifc in dhcp})
    return keyed(out)


def keyed(nets: list[dict]) -> list[dict]:
    """Stable id part per network: the interface name, plus the network when the interface carries several."""
    count: dict[str, int] = {}
    for n in nets:
        count[n["iface"]] = count.get(n["iface"], 0) + 1
    for n in nets:
        n["key"] = n["iface"] if count[n["iface"]] == 1 else f"{n['iface']}.{n['net'].network_address}"
    return nets


def iface_mtu(item: dict) -> int:
    for key in ("actual-mtu", "mtu"):
        v = str(item.get(key) or "")
        if v.isdigit():
            return int(v)
    return 0


def validate_target(t: dict) -> tuple[dict, list[str]]:
    errors: list[str] = []
    out = dict(t)
    for key in ("wan_interface", "lan_interface"):
        if not re.match(r"^[A-Za-z0-9._<>-]{1,64}$", out.get(key, "")):
            errors.append(f"Ungültiger Interface-Name: {key}")
    i = iface_of(out.get("lan_address", ""))
    if not i or i.version != 4 or i.network.prefixlen > 30 or i.ip == i.network.network_address:
        errors.append("LAN-Adresse muss eine IPv4-Adresse mit Präfix sein, z. B. 10.20.0.1/24")
    rng = out.get("dhcp_range", "")
    m = re.match(r"^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$", rng)
    if not m or (i and not all(_in_net(x, i.network) for x in m.groups())):
        errors.append("DHCP-Bereich muss im LAN liegen, z. B. 10.20.0.100-10.20.0.199")
    for d in split_list(out.get("dns_servers", "")):
        if not _valid_ip(d):
            errors.append(f"Ungültiger DNS-Server {d}")
    for a in split_list(out.get("mgmt_addresses", "")):
        if not net_of(a):
            errors.append(f"Ungültige Management-Adresse {a}")
    if not re.match(r"^[A-Za-z0-9_-]{1,32}$", out.get("routing_table", "") or ""):
        errors.append("Ungültiger Name der Routing-Tabelle")
    out["policy_routing"] = yes(out.get("policy_routing"))
    out["mss_clamp"] = yes(out.get("mss_clamp"))
    return out, errors


def _valid_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


# ==========================================================================
# analysis
# ==========================================================================
OK, CHANGE, MISSING, CHECK = "ok", "change", "missing", "check"
STATUS_LABELS = {OK: "Bleibt so", CHANGE: "Anpassen", MISSING: "Fehlt", CHECK: "Prüfen / Hinweis"}
AREAS = {
    "system": "System", "wan": "WAN & Routing", "lan": "LAN & DHCP", "dns": "DNS",
    "nat": "Internetzugang (NAT)", "policy": "Policy-Routing (Mangle)", "firewall": "Firewall",
    "services": "Dienste & Zugang", "tunnel": "Tunnel (WireGuard / Newt)",
}


def finding(fid: str, area: str, status: str, title: str, detail: str = "", severity: str = "",
            current: str = "", ops: Optional[list] = None, script: Optional[list] = None) -> dict:
    sev = severity or {OK: "ok", CHANGE: "warn", MISSING: "warn", CHECK: "info"}[status]
    ops = ops or []
    script = list(script or []) or [op_to_cli(o) for o in ops]
    return {"id": fid, "area": area, "status": status, "severity": sev, "title": title, "detail": detail,
            "current": current, "ops": ops, "script": script, "applicable": bool(ops)}


def op_add(path: str, data: dict) -> dict:
    return {"m": "add", "path": path, "data": data}


def op_set(path: str, data: dict, item_id: str = "", find: str = "") -> dict:
    """item_id empty: singleton menu (POST <path>/set)."""
    return {"m": "set", "path": path, "id": item_id, "find": find, "data": data}


def direct_op_allowed(op: dict) -> bool:
    """Operations a confirmed optimization may send without a full analysis: additions of addresses, NAT rules
    and address-list entries, and switching off the SIP helper."""
    if op.get("m") == "add":
        return op.get("path") in ("ip/address", "ip/firewall/nat", "ip/firewall/address-list")
    return (op.get("m") == "set" and op.get("path") == "ip/firewall/service-port" and bool(op.get("id"))
            and op.get("data") == {"disabled": "yes"})


def op_to_cli(op: dict) -> str:
    path = "/" + op["path"].replace("/", " ")
    args = " ".join(f"{k}={quote_cli(v)}" for k, v in op["data"].items())
    if op["m"] == "add":
        return f"{path} add {args}"
    if op.get("id") or op.get("find"):
        return f"{path} set [ find {op.get('find') or ''} ] {args}"
    return f"{path} set {args}"


def analyze(snap: dict, target: dict) -> list[dict]:
    t = target
    out: list[dict] = []
    add = out.append
    wan, lan = t["wan_interface"], t["lan_interface"]
    lan_if = iface_of(t["lan_address"])
    lan_net = str(lan_if.network) if lan_if else ""
    router_ip = str(lan_if.ip) if lan_if else ""
    iface_names = {i.get("name") for i in items(snap, "interface")}
    tag = f"{TAG}: "
    # all internal networks; the target LAN first (also when it does not exist yet)
    nets = internal_networks(snap, wan)
    primary = next((n for n in nets if lan_if and n["iface"] == lan and n["net"] == lan_if.network), None)
    if primary is None and lan_if:
        primary = {"iface": lan, "ip": router_ip, "net": lan_if.network, "address": str(lan_if), "dhcp": False}
        nets = keyed([primary] + nets)
    extra = [n for n in nets if n is not primary]

    # ---------------------------------------------------------------- system
    ver = single(snap, "system/resource").get("version", "") or snap.get("version", "")
    vt = version_tuple(ver)
    if vt[0] >= 7:
        add(finding("sys.version", "system", OK, f"RouterOS {ver}", "RouterOS 7 – REST-API verfügbar."))
    elif ver:
        add(finding("sys.version", "system", CHANGE, f"RouterOS {ver} ist zu alt",
                    "Für die REST-API wird RouterOS 7.1 oder neuer benötigt. Update über "
                    "/system package update.", severity="crit"))
    if snap.get("source") == "api":
        stale = [m for m in SNAPSHOT_MENUS if m not in (snap.get("menus") or {}) and m not in (snap.get("errors") or {})]
        if stale:
            add(finding("sys.snapshot", "system", CHECK, "Gespeicherter Stand ist älter als die Analyse",
                        "Einige Menüs wurden damals noch nicht eingelesen – Ergebnisse dazu fehlen oder sind "
                        "unvollständig. Konfiguration neu vom Router einlesen.", current=", ".join(stale)))
    ident = single(snap, "system/identity").get("name", "")
    if ident and ident != "MikroTik":
        add(finding("sys.identity", "system", OK, f"Identität „{ident}“"))
    elif ident:
        add(finding("sys.identity", "system", CHECK, "Identität ist noch „MikroTik“",
                    "Eindeutigen Namen vergeben (erleichtert Protokolle und Überwachung).",
                    script=['/system identity set name="chr-…"']))
    ntp = single(snap, "system/ntp/client")
    if ntp and yes(ntp.get("enabled")):
        add(finding("sys.ntp", "system", OK, "NTP-Client aktiv", current=ntp.get("servers", "")))
    elif "system/ntp/client" in (snap.get("menus") or {}) or snap.get("source") == "export":
        add(finding("sys.ntp", "system", CHANGE, "NTP-Client nicht aktiv",
                    "Korrekte Zeit ist Voraussetzung für TLS, Protokolle und Leases.",
                    ops=[op_set("system/ntp/client", {"enabled": "yes", "servers": t.get("ntp_servers") or
                                                      "pool.ntp.org"})]))

    # ---------------------------------------------------------------- WAN
    wan_addrs = [a for a in items(snap, "ip/address") if a.get("interface") == wan and enabled(a)]
    wan_dhcp = [c for c in items(snap, "ip/dhcp-client") if c.get("interface") == wan and enabled(c)]
    if wan not in iface_names and wan_addrs == [] and not wan_dhcp:
        add(finding("wan.iface", "wan", MISSING, f"WAN-Interface {wan} nicht gefunden",
                    "Bitte in den Sollwerten das Interface mit der öffentlichen IP angeben.", severity="crit"))
    else:
        pub = [a.get("address") for a in wan_addrs if is_public(a.get("address"))]
        cur = ", ".join(a.get("address", "") for a in wan_addrs) or ("DHCP-Client" if wan_dhcp else "")
        if pub or wan_dhcp:
            add(finding("wan.iface", "wan", OK, f"WAN-Interface {wan}", current=cur))
        else:
            add(finding("wan.iface", "wan", CHECK, f"WAN-Interface {wan} ohne öffentliche Adresse",
                        "Liegt der Router hinter einem weiteren NAT, sind eingehende Verbindungen (z. B. "
                        "WireGuard) nur über dessen Portweiterleitung möglich.", current=cur))
    dr = default_route(snap)
    dhcp_default = any(yes(c.get("add-default-route"), True) for c in wan_dhcp)
    if dr:
        add(finding("wan.default", "wan", OK, "Default-Route vorhanden",
                    current=f"0.0.0.0/0 via {dr.get('gateway', '')}"))
    elif dhcp_default:
        add(finding("wan.default", "wan", OK, "Default-Route über DHCP-Client", current=wan))
    else:
        add(finding("wan.default", "wan", MISSING, "Keine Default-Route",
                    "Ohne Default-Route haben weder Router noch Dienste Internetzugang.", severity="crit",
                    script=["/ip route add dst-address=0.0.0.0/0 gateway=<GATEWAY-IP> comment=\"servermanager: "
                            "default\""]))

    # ---------------------------------------------------------------- LAN
    bridges = {b.get("name") for b in items(snap, "interface/bridge")}
    if lan in iface_names or lan in bridges:
        ports = [p.get("interface") for p in items(snap, "interface/bridge/port") if p.get("bridge") == lan]
        add(finding("lan.iface", "lan", OK, f"LAN-Interface {lan}",
                    current=("Ports: " + ", ".join(ports)) if ports else ""))
    else:
        add(finding("lan.iface", "lan", MISSING, f"LAN-Bridge {lan} fehlt",
                    "Die Bridge wird angelegt; die internen Ports (z. B. das Interface zum Proxmox-Host) "
                    "müssen anschließend zugeordnet werden.",
                    ops=[op_add("interface/bridge", {"name": lan, "comment": tag + "LAN"})],
                    script=[f"/interface bridge add name={lan} comment=\"{tag}LAN\"",
                            f"/interface bridge port add bridge={lan} interface=<PORT>"]))
    lan_addrs = [a for a in items(snap, "ip/address") if a.get("interface") == lan and enabled(a)]
    have = [a for a in lan_addrs if iface_of(a.get("address", "")) == lan_if]
    if have:
        add(finding("lan.address", "lan", OK, f"LAN-Adresse {t['lan_address']}"))
    elif lan_addrs:
        add(finding("lan.address", "lan", CHECK, "LAN hat eine andere Adresse",
                    "Die vorhandene Adresse bleibt – bitte die Sollwerte an das bestehende Netz anpassen oder "
                    "bewusst umstellen.", current=", ".join(a.get("address", "") for a in lan_addrs)))
    else:
        add(finding("lan.address", "lan", MISSING, f"LAN-Adresse {t['lan_address']} fehlt",
                    ops=[op_add("ip/address", {"address": t["lan_address"], "interface": lan,
                                               "comment": tag + "LAN"})]))

    # DHCP pool + server + network
    rng = t["dhcp_range"]
    pool = next((p for p in items(snap, "ip/pool") if p.get("ranges") == rng), None)
    srv = next((s for s in items(snap, "ip/dhcp-server") if s.get("interface") == lan), None)
    if srv:
        srv_pool = next((p for p in items(snap, "ip/pool") if p.get("name") == srv.get("address-pool")), None)
        pool = pool or srv_pool
    pool_name = pool.get("name") if pool else "sm-lan-pool"
    if pool:
        add(finding("lan.pool", "lan", OK, f"Adress-Pool {pool_name}", current=pool.get("ranges", "")))
    else:
        add(finding("lan.pool", "lan", MISSING, f"Adress-Pool für {rng} fehlt",
                    ops=[op_add("ip/pool", {"name": pool_name, "ranges": rng, "comment": tag + "LAN"})]))
    if srv and enabled(srv):
        add(finding("lan.dhcp", "lan", OK, f"DHCP-Server {srv.get('name')} auf {lan}",
                    current=f"Pool {srv.get('address-pool', '')}, Lease-Zeit {srv.get('lease-time', '')}"))
    elif srv:
        add(finding("lan.dhcp", "lan", CHANGE, f"DHCP-Server {srv.get('name')} ist deaktiviert",
                    ops=[op_set("ip/dhcp-server", {"disabled": "no"}, srv.get(".id", ""),
                                f"name={quote_cli(srv.get('name'))}")]))
    else:
        add(finding("lan.dhcp", "lan", MISSING, f"Kein DHCP-Server auf {lan}",
                    "Die Dienste (z. B. der Newt-LXC) erhalten ihre Adresse per DHCP.",
                    ops=[op_add("ip/dhcp-server", {"name": "sm-dhcp-lan", "interface": lan,
                                                    "address-pool": pool_name, "lease-time": "1d",
                                                    "comment": tag + "LAN"})]))
    f, dns_for_clients = _dhcp_network_finding("lan.network", snap, lan_if, "", tag + "LAN")
    add(f)
    leases = [le for le in items(snap, "ip/dhcp-server/lease") if yes(le.get("dynamic")) and
              lan_if and _in_net(le.get("address", ""), lan_if.network)]
    if leases:
        add(finding("lan.leases", "lan", CHECK, f"{len(leases)} dynamische DHCP-Lease(s)",
                    "Für Server und veröffentlichte Dienste (Newt-LXC, Pangolin-Ziele) die Lease statisch "
                    "machen – sonst kann sich die IP ändern und das Pangolin-Ziel zeigt ins Leere. "
                    "(Reiter DHCP → „Statisch machen“)",
                    current=", ".join(f"{le.get('address')} {le.get('host-name', '')}".strip()
                                      for le in leases[:8])))
    for n in extra:
        if n["dhcp"]:
            add(_dhcp_network_finding(f"lan.network.{n['key']}", snap, iface_of(n["address"]),
                                      f" ({n['iface']})", tag + n["iface"])[0])
    _dhcp_mtu_findings(snap, add, nets)

    # ---------------------------------------------------------------- DNS
    dns = single(snap, "ip/dns")
    servers = dns.get("servers", "")
    if servers or dns.get("dynamic-servers"):
        add(finding("dns.servers", "dns", OK, "Upstream-DNS gesetzt", current=servers or dns.get("dynamic-servers")))
    else:
        add(finding("dns.servers", "dns", MISSING, "Kein Upstream-DNS-Server",
                    ops=[op_set("ip/dns", {"servers": ",".join(split_list(t["dns_servers"]))})]))
    if dns_for_clients == router_ip:
        if yes(dns.get("allow-remote-requests")):
            add(finding("dns.remote", "dns", OK, "Router beantwortet DNS-Anfragen aus dem LAN"))
        else:
            add(finding("dns.remote", "dns", CHANGE, "DNS-Anfragen der Clients werden nicht beantwortet",
                        "Das DHCP-Netz verteilt den Router als DNS-Server – dafür muss allow-remote-requests "
                        "aktiv sein. Die Firewall muss DNS (Port 53) von außen blockieren (siehe Firewall).",
                        ops=[op_set("ip/dns", {"allow-remote-requests": "yes"})]))

    # ---------------------------------------------------------------- NAT
    covering, broad, unsure = nat_coverage(snap, lan_if.network if lan_if else None, wan)
    if covering:
        add(finding("nat.masq", "nat", OK, "NAT (masquerade) für das LAN über WAN",
                    current=_rule_text(covering[0])))
    elif broad:
        add(finding("nat.masq", "nat", CHANGE, "Masquerade ohne Ausgangs-Interface",
                    "Die Regel maskiert auch Verkehr in Tunnel und interne Netze (Quell-IPs gehen verloren, "
                    "WireGuard-Management und Protokolle zeigen nur noch die Router-IP). Empfohlen: auf das "
                    "WAN-Interface beschränken.", current=_rule_text(broad[0]),
                    script=[f"/ip firewall nat set [ find where chain=srcnat action={broad[0].get('action')} "
                            f"!out-interface !out-interface-list ] out-interface={wan}"]))
    elif unsure:
        add(finding("nat.masq", "nat", CHECK, "NAT für das LAN nicht eindeutig",
                    "Die Regel hängt von einer Adressliste oder Interface-Liste ab, die sich nicht vollständig "
                    "auswerten lässt – bitte prüfen, ob das LAN darüber ins Internet kommt.",
                    current=_rule_text(unsure[0])))
    else:
        add(finding("nat.masq", "nat", MISSING, "Kein NAT für das LAN – Dienste kommen nicht ins Internet",
                    severity="crit",
                    ops=[op_add("ip/firewall/nat", {"chain": "srcnat", "action": "masquerade",
                                                     "src-address": lan_net, "out-interface": wan,
                                                     "comment": tag + "LAN -> Internet"})]))
    dstnat = [r for r in items(snap, "ip/firewall/nat") if r.get("chain") == "dstnat" and enabled(r)]
    if dstnat:
        add(finding("nat.dstnat", "nat", CHECK, f"{len(dstnat)} Portweiterleitung(en) vorhanden",
                    "Können bleiben, wenn sie gebraucht werden. Über Pangolin veröffentlichte Dienste "
                    "benötigen keine Portweiterleitung – nicht mehr benötigte Weiterleitungen entfernen.",
                    current="; ".join(_rule_text(r) for r in dstnat[:5])))
    _extra_nat_findings(snap, add, extra, wan, tag)
    _lan_masq_findings(snap, add, nets)

    # ---------------------------------------------------------------- policy routing
    mangle = [r for r in items(snap, "ip/firewall/mangle") if enabled(r)]
    fasttrack = [r for r in items(snap, "ip/firewall/filter") if r.get("action") == "fasttrack-connection"
                 and enabled(r)]
    table = t["routing_table"]
    if t.get("policy_routing"):
        _policy_findings(snap, t, add, mangle, fasttrack, table, wan, lan_net, tag)
    else:
        foreign = [r for r in mangle if r.get("action") in ("mark-routing", "mark-connection") and not ours(r)]
        if foreign:
            add(finding("pol.foreign", "policy", CHECK, f"{len(foreign)} vorhandene Mangle-Markierung(en)",
                        "Bleiben unverändert. Prüfen, ob sie den LAN-Verkehr in eine andere Routing-Tabelle "
                        "lenken.", current="; ".join(_rule_text(r) for r in foreign[:5])))
        add(finding("pol.off", "policy", OK, "Policy-Routing nicht vorgesehen",
                    "Einfaches Routing über die Default-Route genügt, solange kein Tunnel eine "
                    "Default-Route (0.0.0.0/0) übernimmt."))
    if t.get("mss_clamp"):
        tunnels = [w.get("name") for w in items(snap, "interface/wireguard")]
        for tun in tunnels:
            have_mss = any(r.get("action") == "change-mss" and (r.get("out-interface") == tun or not
                           r.get("out-interface")) for r in mangle)
            if have_mss:
                add(finding(f"pol.mss.{tun}", "policy", OK, f"MSS-Clamping für {tun}"))
            else:
                add(finding(f"pol.mss.{tun}", "policy", MISSING, f"MSS-Clamping für {tun} fehlt",
                            "Verhindert hängende TCP-Verbindungen durch die kleinere MTU im Tunnel.",
                            ops=[op_add("ip/firewall/mangle", {
                                "chain": "forward", "action": "change-mss", "protocol": "tcp",
                                "tcp-flags": "syn", "out-interface": tun, "new-mss": "clamp-to-pmtu",
                                "passthrough": "yes", "comment": tag + f"MSS {tun}"})]))
    _mtu_findings(snap, add, wan, tag)

    # ---------------------------------------------------------------- firewall (script only)
    _firewall_findings(snap, t, add, wan, lan, lan_net)
    _network_firewall_findings(snap, add, nets, primary, wan)
    _icmp_findings(snap, add, wan, nets)
    _dead_rule_findings(snap, add)
    _log_findings(snap, add)
    _orphan_findings(snap, add)

    # ---------------------------------------------------------------- services (script only)
    _service_findings(snap, t, add, wan)

    # ---------------------------------------------------------------- tunnels
    for w in items(snap, "interface/wireguard"):
        peers = [p for p in items(snap, "interface/wireguard/peers") if p.get("interface") == w.get("name")]
        wide = [p for p in peers if "0.0.0.0/0" in str(p.get("allowed-address", ""))]
        add(finding(f"tun.wg.{w.get('name')}", "tunnel", CHECK if wide else OK,
                    f"WireGuard {w.get('name')} ({len(peers)} Peer(s), Port {w.get('listen-port', '')})",
                    "Ein Peer mit AllowedIPs 0.0.0.0/0 kann Verkehr ins Internet an sich ziehen – dann "
                    "Policy-Routing aktivieren." if wide else ""))
    add(finding("tun.newt", "tunnel", CHECK, "Newt/Pangolin braucht nur ausgehende Verbindungen",
                "Der Newt-Client im LXC baut den Tunnel zum Pangolin-Server selbst auf (HTTPS/WebSocket und "
                "UDP 51820 ausgehend). Voraussetzung: NAT (siehe oben) und keine Forward-Regel, die "
                "ausgehenden Verkehr aus dem LAN blockiert. Die Newt-IP sollte eine statische Lease haben."))
    return out


def _rule_text(r: dict) -> str:
    keys = ["chain", "action", "src-address", "dst-address", "protocol", "dst-port", "in-interface",
            "in-interface-list", "out-interface", "out-interface-list", "connection-mark", "new-connection-mark",
            "new-routing-mark", "to-addresses", "to-ports", "comment"]
    return " ".join(f"{k}={_cli_escape(r[k])}" for k in keys if r.get(k))


def _covers_net(spec: str, net) -> Optional[bool]:
    """True: spec (address, CIDR or range) contains all of net, False: no overlap, None: partly or unknown."""
    try:
        if "-" in spec:
            lo, hi = (ipaddress.ip_address(x.strip()) for x in spec.split("-", 1))
            if lo.version != net.version:
                return False
            if lo <= net.network_address and net.broadcast_address <= hi:
                return True
            return None if not (hi < net.network_address or lo > net.broadcast_address) else False
    except ValueError:
        return None
    other = net_of(spec)
    if other is None:
        return None
    if other.version != net.version:
        return False
    return True if net.subnet_of(other) else (None if net.overlaps(other) else False)


def _src_covers(snap: dict, r: dict, net) -> Optional[bool]:
    """Do src-address and src-address-list (both must hold) select every host of net?"""
    if net is None:
        return not r.get("src-address") and not r.get("src-address-list")
    res: list[Optional[bool]] = []
    if r.get("src-address"):
        neg, spec = _neg(r["src-address"])
        c = _covers_net(spec, net)
        res.append(c if not neg or c is None else not c)
    if r.get("src-address-list"):
        neg, name = _neg(r["src-address-list"])
        parts = [_covers_net(str(e.get("address", "")), net) for e in items(snap, "ip/firewall/address-list")
                 if e.get("list") == name and enabled(e)]
        c = True if True in parts else (None if None in parts else False)
        res.append(c if not neg or c is None else not c)
    return False if False in res else (None if None in res else True)


def nat_coverage(snap: dict, net, wan: str) -> tuple[list[dict], list[dict], list[dict]]:
    """srcnat rules that take `net` to the internet: via the WAN interface (covering), as a masquerade without any
    out-interface (broad), or depending on lists that cannot be fully evaluated (unsure)."""
    covering, broad, unsure = [], [], []
    for r in items(snap, "ip/firewall/nat"):
        if r.get("chain") != "srcnat" or not enabled(r) or r.get("action") not in ("masquerade", "src-nat"):
            continue
        src = _src_covers(snap, r, net)
        if src is False:
            continue
        out_keys = {k: r[k] for k in ("out-interface", "out-interface-list") if r.get(k)}
        out = rule_matches(out_keys, {"out": wan}, snap) if out_keys else True
        if out is False:
            continue
        if src is None or out is None:
            unsure.append(r)
        elif out_keys:
            covering.append(r)
        else:
            broad.append(r)
    return covering, broad, unsure


def _dhcp_net_of(snap: dict, net) -> Optional[dict]:
    return next((n for n in items(snap, "ip/dhcp-server/network") if net is not None
                 and net_of(n.get("address", "")) == net), None)


def _dhcp_network_finding(fid: str, snap: dict, lan_if, label: str, comment: str) -> tuple[dict, str]:
    """DHCP network of an internal net: gateway and DNS for the clients. -> (finding, DNS the clients get)"""
    router_ip = str(lan_if.ip) if lan_if else ""
    lan_net = str(lan_if.network) if lan_if else ""
    dnet = _dhcp_net_of(snap, lan_if.network if lan_if else None)
    dns_for_clients = router_ip
    if not dnet:
        return finding(fid, "lan", MISSING, f"DHCP-Netz {lan_net}{label} fehlt",
                       ops=[op_add("ip/dhcp-server/network", {"address": lan_net, "gateway": router_ip,
                                                               "dns-server": router_ip, "comment": comment})]), \
            dns_for_clients
    problems = {}
    if dnet.get("gateway") != router_ip:
        problems["gateway"] = router_ip
    if not dnet.get("dns-server"):
        problems["dns-server"] = dns_for_clients
    else:
        dns_for_clients = dnet.get("dns-server")
    if problems:
        return finding(fid, "lan", CHANGE, f"DHCP-Netz unvollständig{label}",
                       "Ohne Gateway/DNS in der DHCP-Antwort kommen die Dienste nicht ins Internet.",
                       current=f"Gateway {dnet.get('gateway') or '–'}, DNS {dnet.get('dns-server') or '–'}",
                       ops=[op_set("ip/dhcp-server/network", problems, dnet.get(".id", ""),
                                   f"address={quote_cli(dnet.get('address'))}")]), dns_for_clients
    return finding(fid, "lan", OK, f"DHCP-Netz {dnet.get('address')}{label}",
                   current=f"Gateway {dnet.get('gateway')}, DNS {dnet.get('dns-server')}"), dns_for_clients


def _router_is_gateway(snap: dict, n: dict) -> bool:
    """The router hands itself out as default gateway for the network (its DHCP network says so)."""
    dnet = _dhcp_net_of(snap, n["net"]) if n["dhcp"] else None
    return bool(dnet) and dnet.get("gateway") == n["ip"]


def _masq_into(snap: dict, iface: str) -> list[dict]:
    """masquerade/src-nat of everything that leaves into iface (no source/destination restriction)"""
    return [r for r in items(snap, "ip/firewall/nat") if r.get("chain") == "srcnat" and enabled(r)
            and r.get("action") in ("masquerade", "src-nat") and r.get("out-interface") == iface
            and not any(r.get(k) for k in ("src-address", "dst-address", "src-address-list", "dst-address-list"))]


def _extra_nat_findings(snap, add, extra, wan, tag) -> None:
    """Every further internal network needs its own way to the internet."""
    for n in extra:
        fid, name = f"nat.masq.{n['key']}", f"{n['net']} ({n['iface']})"
        covering, broad, unsure = nat_coverage(snap, n["net"], wan)
        op = op_add("ip/firewall/nat", {"chain": "srcnat", "action": "masquerade", "src-address": str(n["net"]),
                                        "out-interface": wan, "comment": tag + f"{n['iface']} -> Internet"})
        if covering:
            add(finding(fid, "nat", OK, f"NAT für {name} über WAN", current=_rule_text(covering[0])))
        elif broad:
            add(finding(fid, "nat", CHECK, f"NAT für {name} nur ohne Ausgangs-Interface",
                        "Funktioniert, maskiert aber auch Verkehr in Tunnel und interne Netze – siehe den Hinweis "
                        "zur Masquerade-Regel des LAN.", current=_rule_text(broad[0])))
        elif unsure:
            add(finding(fid, "nat", CHECK, f"NAT für {name} nicht eindeutig",
                        "Die Regel hängt von einer Adressliste oder Interface-Liste ab, die sich nicht vollständig "
                        "auswerten lässt.", current=_rule_text(unsure[0])))
        elif _router_is_gateway(snap, n) and not _masq_into(snap, n["iface"]):
            add(finding(fid, "nat", MISSING, f"Kein NAT für {name} – Geräte dort kommen nicht ins Internet",
                        severity="crit", ops=[op]))
        else:
            add(finding(fid, "nat", CHECK, f"Kein NAT für {name}",
                        "Der Router verteilt in diesem Netz kein Gateway per DHCP – ob die Geräte über ihn ins "
                        "Internet sollen, ist nicht erkennbar (z. B. Backend-Netz, dessen Server einen eigenen "
                        "Uplink haben). Falls ja: Masquerade ergänzen.", script=[op_to_cli(op)]))


def _lan_masq_findings(snap, add, nets) -> None:
    """masquerade/src-nat of everything that leaves into an internal network."""
    by_iface: dict[str, list[dict]] = {}
    for n in nets:
        by_iface.setdefault(n["iface"], []).append(n)
    for out_if, group in by_iface.items():
        rules = _masq_into(snap, out_if)
        if not rules:
            continue
        r, n = rules[0], group[0]
        fid, net = f"nat.lanmasq.{out_if}", str(n["net"])
        effect = ("Alles, was der Router in dieses Netz weiterleitet – auch Portweiterleitungen aus dem Internet – "
                  "kommt dort mit der Router-Adresse an: Server sehen keine echten Client-IPs mehr (Spamfilter, "
                  "fail2ban, Protokolle).")
        if len(group) == 1 and _router_is_gateway(snap, n):
            add(finding(fid, "nat", CHANGE, f"Masquerade in das interne Netz {net} ({out_if})",
                        effect + " Der Router verteilt sich hier selbst als Gateway; die Regel ist dann meist ein "
                        "Notbehelf für Geräte mit falsch eingetragenem Gateway – die kommen so auch nicht ins Internet. "
                        f"Gateway der Geräte auf {n['ip']} prüfen und die Regel auf Hairpin-NAT (Zugriff aus "
                        "demselben Netz auf eine öffentliche IP des Routers) beschränken.",
                        current=_rule_text(r),
                        script=[f"/ip firewall nat set [ find where chain=srcnat action={r.get('action')} "
                                f"out-interface={_q(out_if)} !src-address !dst-address !src-address-list "
                                f"!dst-address-list ] src-address={net} dst-address={net}"]))
        else:
            add(finding(fid, "nat", CHECK, f"Masquerade in das interne Netz ({out_if})",
                        effect + " Nötig ist das, wenn die Geräte dort ein anderes Gateway nutzen (z. B. Server im "
                        "Hetzner vSwitch mit eigenem Uplink, erreicht über WireGuard). Dann die Regel auf die Quellen "
                        "beschränken, die sie brauchen (src-address bzw. src-address-list der VPN-Netze).",
                        severity="info", current=_rule_text(r)))


PPP_TYPES = ("pppoe", "pptp", "l2tp", "sstp", "ovpn", "ppp")
L3_TUNNEL_TYPES = ("gre", "ipip", "6to4")


def _mtu_findings(snap, add, wan, tag) -> None:
    """Interfaces with an MTU below 1500 (Hetzner vSwitch: 1400) need MSS clamping in both directions."""
    wg = {w.get("name") for w in items(snap, "interface/wireguard")}
    with_addr = {a.get("interface") for a in items(snap, "ip/address") if enabled(a)}
    rules = [r for r in items(snap, "ip/firewall/mangle") if enabled(r) and r.get("action") == "change-mss"
             and r.get("chain") in ("forward", "prerouting", "postrouting") and _proto(r.get("protocol")) == "tcp"
             and "syn" in split_list(r.get("tcp-flags", ""))]
    for i in items(snap, "interface"):
        name, mtu = i.get("name", ""), iface_mtu(i)
        if not name or not 0 < mtu < 1500 or name in wg or name not in with_addr or ORPHAN_RE.match(name) \
                or yes(i.get("disabled")) or str(i.get("type", "")).startswith(PPP_TYPES):
            continue
        mss = mtu - 40

        def covers(r: dict, key: str) -> bool:
            other = "out" if key == "in" else "in"
            if r.get(f"{key}-interface") or r.get(f"{key}-interface-list"):
                return rule_matches_iface(r, key, name, snap)
            return not r.get(f"{other}-interface") and not r.get(f"{other}-interface-list")

        def small_enough(r: dict, pmtu_ok: bool) -> bool:
            v = str(r.get("new-mss", ""))
            return (pmtu_ok and v == "clamp-to-pmtu") or (v.isdigit() and int(v) <= mss)

        have = {"in": any(covers(r, "in") and small_enough(r, False) for r in rules),
                "out": any(covers(r, "out") and small_enough(r, True) for r in rules)}
        title = f"MSS-Clamping für {name} (MTU {mtu})"
        if all(have.values()):
            add(finding(f"pol.mtu.{name}", "policy", OK, title))
            continue
        ops = [op_add("ip/firewall/mangle", {
            "chain": "forward", "action": "change-mss", "protocol": "tcp", "tcp-flags": "syn",
            f"{key}-interface": name, "tcp-mss": f"{mss + 1}-65535", "new-mss": str(mss), "passthrough": "yes",
            "comment": tag + f"MSS {name} (MTU {mtu})"}) for key in ("in", "out") if not have[key]]
        missing = " und ".join({"in": "eingehend", "out": "ausgehend"}[k] for k in ("in", "out") if not have[k])
        add(finding(f"pol.mtu.{name}", "policy", MISSING, f"{title} fehlt ({missing})",
                    f"{name} hat eine MTU unter 1500 (z. B. Hetzner vSwitch: 1400). Ohne MSS-Clamping schicken "
                    "Gegenstellen zu große TCP-Segmente: Verbindungen bauen sich auf, hängen dann aber (TLS-Handshake, "
                    f"Downloads). Geklemmt wird in beide Richtungen auf {mss} – eingehend auch für Geräte, deren MTU "
                    "falsch auf 1500 steht.", ops=ops))


def _dhcp_mtu_findings(snap, add, nets) -> None:
    """DHCP option 26 (interface MTU) for networks behind an interface with an MTU below 1500."""
    if not have_menu(snap, "ip/dhcp-server/option"):
        return  # not read (no permission, or a snapshot from before this check)
    ifaces = {i.get("name"): i for i in items(snap, "interface")}
    options = items(snap, "ip/dhcp-server/option")
    mtu_opts = [o for o in options if str(o.get("code")) == "26"]
    for n in nets:
        mtu = iface_mtu(ifaces.get(n["iface"], {}))
        dnet = _dhcp_net_of(snap, n["net"])
        if not n["dhcp"] or not 0 < mtu < 1500 or not dnet:
            continue
        fid, label = f"lan.mtu.{n['key']}", f"{n['net']} ({n['iface']})"
        names = split_list(dnet.get("dhcp-option", ""))
        if any(o.get("name") in names for o in mtu_opts):
            add(finding(fid, "lan", OK, f"DHCP verteilt die MTU für {label}"))
            continue
        sets = [f"dhcp-server {x.get('name')}: dhcp-option-set={x.get('dhcp-option-set')}"
                for x in items(snap, "ip/dhcp-server") if x.get("interface") == n["iface"] and enabled(x)
                and x.get("dhcp-option-set")]
        sets += [f"dhcp-option-set={dnet.get('dhcp-option-set')}"] if dnet.get("dhcp-option-set") else []
        if sets:
            add(finding(fid, "lan", CHECK, f"DHCP-Option 26 (MTU {mtu}) für {label} prüfen",
                        "Der DHCP-Server bzw. das DHCP-Netz nutzt ein Option-Set – darin muss eine Option mit Code 26 "
                        "enthalten sein.", current="; ".join(sets)))
            continue
        value = f"0x{mtu:04x}"
        opt = next((o for o in mtu_opts if str(o.get("value", "")).lower() == value), None)
        name = opt.get("name") if opt else f"sm-mtu-{mtu}"
        ops = [] if opt or any(o.get("name") == name for o in options) else \
            [op_add("ip/dhcp-server/option", {"name": name, "code": "26", "value": value,
                                              "comment": f"{TAG}: MTU {mtu}"})]
        ops.append(op_set("ip/dhcp-server/network", {"dhcp-option": ",".join(names + [name])}, dnet.get(".id", ""),
                          f"address={quote_cli(dnet.get('address'))}"))
        add(finding(fid, "lan", MISSING, f"DHCP verteilt die MTU {mtu} für {label} nicht",
                    f"Die Clients setzen sonst MTU 1500 und schicken Pakete, die {n['iface']} (z. B. ein Hetzner "
                    "vSwitch) verwirft. DHCP-Option 26 teilt ihnen die MTU mit; Geräte mit fester IP-Konfiguration "
                    "von Hand einstellen.", ops=ops))


def _probe_host(n: dict) -> str:
    for h in n["net"].hosts():
        if str(h) != n["ip"]:
            return str(h)
    return ""


def _network_firewall_findings(snap, add, nets, primary, wan) -> None:
    """Probe every internal network: may it reach the internet (forward) and the router's DNS/DHCP (input)?"""
    dns = single(snap, "ip/dns")
    raw = items(snap, "ip/firewall/raw")
    remote_done: set = set()
    for n in nets:
        host = _probe_host(n)
        if not host:
            continue
        sfx = "" if n is primary else f".{n['key']}"
        name = f"{n['net']} ({n['iface']})"
        pkt = {"src": host, "dst": "1.1.1.1", "proto": "tcp", "sport": 40000, "dport": 443, "in": n["iface"],
               "out": wan, "state": "new", "nat": (), "dst_type": ("unicast",), "src_type": ("unicast",),
               "flags": ("syn",)}
        verdict, rule, _top = probe(snap, "forward", pkt)
        if verdict == "drop":
            add(finding("fw.lanout" + sfx, "firewall", CHANGE, f"Firewall blockiert Verkehr aus {name} ins Internet",
                        "Damit erreichen Newt und die Dienste das Internet nicht.", current=_rule_text(rule)))
        elif verdict == "uncertain":
            add(finding("fw.lanout" + sfx, "firewall", CHECK,
                        f"Internetzugang aus {name}: Ergebnis der Firewall nicht eindeutig",
                        "Eine Regel hängt von Ratenbegrenzung, Markierungen o. Ä. ab – bitte von Hand prüfen.",
                        current=_rule_text(rule or {})))
        dnet = _dhcp_net_of(snap, n["net"]) if n["dhcp"] else None
        hands_out = bool(dnet) and n["ip"] in split_list(dnet.get("dns-server", ""))
        if not yes(dns.get("allow-remote-requests")):
            if hands_out and n is not primary and n["iface"] not in remote_done:  # target LAN: dns.remote
                remote_done.add(n["iface"])
                add(finding(f"dns.remote.{n['iface']}", "dns", CHANGE,
                            f"DNS-Anfragen aus {name} werden nicht beantwortet",
                            "Das DHCP-Netz verteilt den Router als DNS-Server – dafür muss allow-remote-requests "
                            "aktiv sein.", ops=[op_set("ip/dns", {"allow-remote-requests": "yes"})]))
            continue
        pkt = dict(pkt, dst=n["ip"], proto="udp", dport=53, out=None, dst_type=("local",), flags=())
        verdict, rule, top = probe(snap, "input", pkt)
        fid = "fw.lanin" + sfx
        if verdict == "accept":
            add(finding(fid, "firewall", OK, f"DNS aus {name} erreicht den Router"))
        elif verdict == "drop":
            in_raw = any(rule is r for r in raw)
            act = (top or rule or {}).get("action") or "drop"
            tagc = f"{TAG}: DNS/DHCP {n['iface']}"
            script = [f"# Raw-Regel verwirft DNS aus {n['net']}: {_rule_text(rule)}"] if in_raw else [
                f"/ip firewall filter add chain=input action=accept in-interface={_q(n['iface'])} protocol=udp "
                f"dst-port=53,67 comment={quote_cli(tagc)} "
                f"place-before=[:pick [find where chain=input action={act} dynamic=no] 0]",
                f"/ip firewall filter add chain=input action=accept in-interface={_q(n['iface'])} protocol=tcp "
                f"dst-port=53 comment={quote_cli(tagc)} "
                f"place-before=[:pick [find where chain=input action={act} dynamic=no] 0]"]
            add(finding(fid, "firewall", CHANGE, f"DNS aus {name} wird vom Router verworfen",
                        "Die Input-Kette verwirft DNS-Anfragen (und DHCP-Verlängerungen) aus diesem Netz. Ein Gerät, "
                        "das den Router als DNS-Server nutzt, löst keine Namen auf und wirkt offline."
                        + (" Das DHCP-Netz verteilt den Router als DNS-Server." if hands_out else ""),
                        severity="crit" if hands_out else "warn", current=_rule_text(rule), script=script))
        else:
            add(finding(fid, "firewall", CHECK, f"DNS aus {name}: Ergebnis der Firewall nicht eindeutig",
                        "Eine Regel hängt von Ratenbegrenzung, Markierungen o. Ä. ab – bitte von Hand prüfen.",
                        current=_rule_text(rule or {})))


def _icmp_errors_pass(before: list[dict], chain: str, never: set[int], wan: str, snap: dict) -> bool:
    """Earlier accepts of the chain already let ICMP errors through: related, all ICMP, or type 3 (code 4) and 11."""
    types: set[str] = set()
    for x in before:
        if x.get("chain") != chain or not enabled(x) or id(x) in never or (x.get("action") or "accept") != "accept":
            continue
        cond = {k: v for k, v in x.items() if not _is_meta(k) and v not in ("", None)}
        scope = {k: cond.pop(k) for k in ("in-interface", "in-interface-list") if k in cond}
        if scope and rule_matches(scope, {"in": wan}, snap) is not True:
            continue
        if set(cond) == {"connection-state"} and rule_matches(cond, {"state": "related"}, snap):
            return True
        if _proto(cond.pop("protocol", "")) != "icmp":
            continue
        opt = str(cond.pop("icmp-options", ""))
        if cond or opt.startswith("!"):
            continue  # further conditions (limits, addresses, ...)
        if not opt:
            return True
        typ, _, code = opt.partition(":")
        if typ == "11" or (typ == "3" and (not code or _port_match(code, 4))):
            types.add(typ)
    return {"3", "11"} <= types


def _icmp_findings(snap, add, wan, nets) -> None:
    """ICMP dropped or rate limited for everyone: ping tests fail and Path MTU Discovery (type 3 code 4) breaks."""
    hits: list[tuple[str, dict, list]] = []
    never = _never_fires(snap)
    inner = [n["iface"] for n in nets]
    for menu in ("ip/firewall/raw", "ip/firewall/filter"):
        rules = items(snap, menu)
        for idx, r in enumerate(rules):
            if not enabled(r) or id(r) in never or (r.get("action") or "accept") not in DROP_ACTIONS or \
                    _proto(r.get("protocol")) != "icmp" or r.get("chain") not in ("prerouting", "input", "forward"):
                continue
            if r.get("src-address") or r.get("src-address-list"):
                continue  # aimed at certain sources
            opt = str(r.get("icmp-options", ""))
            if opt and not opt.startswith("!") and opt.split(":")[0] not in ("3", "11"):
                continue  # only e.g. echo requests - PMTUD is not affected
            dl = str(r.get("dst-limit", "")).split(",")
            if len(dl) >= 3 and "src" in dl[2]:
                continue  # limit per source
            ifc = {k: r[k] for k in ("in-interface", "in-interface-list") if r.get(k)}
            if ifc and rule_matches(ifc, {"in": wan}, snap) is False:
                continue  # never sees traffic from the internet
            outc = {k: r[k] for k in ("out-interface", "out-interface-list") if r.get(k)}
            if outc and inner and all(rule_matches(outc, {"out": i}, snap) is False for i in inner):
                continue  # only ICMP leaving to the internet - errors coming back are not hit
            if r.get("connection-state") and \
                    rule_matches({"connection-state": r["connection-state"]}, {"state": "related"}, snap) is False:
                continue  # ICMP errors are "related" and not hit
            if _icmp_errors_pass(rules[:idx], r.get("chain", ""), never, wan, snap):
                continue
            hits.append((menu, r, rules))
    if not hits:
        return
    script = []
    for menu, r, rules in hits:
        if _find_unique(r, rules):
            script.append(f"{cli_menu(menu)} disable [ find where {find_expr(r, rules)} ]")
        else:
            script.append(f"# {cli_menu(menu)}: {_rule_text(r)} – von Hand deaktivieren")
    add(finding("fw.icmp", "firewall", CHANGE, "ICMP wird pauschal verworfen oder begrenzt",
                "Eine globale ICMP-Sperre oder -Ratenbegrenzung lässt Ping-Tests scheitern und bricht die "
                "Path-MTU-Discovery (ICMP Typ 3 „Fragmentation needed“): Verbindungen über Strecken mit kleinerer MTU "
                "(vSwitch, Tunnel, PPPoE) hängen. Ping-Flut besser pro Quelle begrenzen (dst-limit mit src-address) "
                "und ICMP-Fehlermeldungen (Typ 3 und 11) nie verwerfen.",
                current="; ".join(_rule_text(r) + (f" limit={r['limit']}" if r.get("limit") else "")
                                  for _m, r, _rs in hits[:3]), script=script))


def dead_rules(snap: dict) -> tuple[list[tuple[str, dict, dict]], list[tuple[str, str]]]:
    """-> ([(menu, rule, rule that ends the chain before it)], [(menu, user chain without an active jump)])"""
    dead: list[tuple[str, dict, dict]] = []
    unused: list[tuple[str, str]] = []
    for menu in ("ip/firewall/filter", "ip/firewall/raw"):
        rules = items(snap, menu)
        targets = {r.get("jump-target") for r in rules if enabled(r) and r.get("action") == "jump"}
        for ch in dict.fromkeys(r.get("chain", "") for r in rules if enabled(r)):
            killer = None
            for r in rules:
                if r.get("chain") != ch or not enabled(r) or yes(r.get("dynamic")):
                    continue
                if killer:
                    dead.append((menu, r, killer))
                elif unconditional(r) and (r.get("action") or "accept") in DROP_ACTIONS | {"accept", "return"}:
                    killer = r
            if ch not in BUILTIN_CHAINS and ch not in targets:
                unused.append((menu, ch))
    return dead, unused


def _never_fires(snap: dict) -> set[int]:
    """ids (id()) of firewall rules that can never match: dead, in an unused chain or bound to a deleted interface"""
    dead, unused = dead_rules(snap)
    out = {id(r) for _m, r, _k in dead}
    for menu, ch in unused:
        out |= {id(r) for r in items(snap, menu) if r.get("chain") == ch}
    for menu in ("ip/firewall/filter", "ip/firewall/raw", "ip/firewall/nat", "ip/firewall/mangle"):
        out |= {id(r) for r in items(snap, menu) if _orphan_ref(r)}
    return out


def _dead_rule_findings(snap, add) -> None:
    """Rules behind a rule that ends the chain for every packet, and user chains nobody jumps to."""
    dead, unused = dead_rules(snap)
    if not dead and not unused:
        return
    # an accept for the listen port of a WireGuard interface is needed - move it instead of deleting it
    wg_ports = {str(w.get("listen-port")): w.get("name") for w in items(snap, "interface/wireguard")
                if str(w.get("listen-port") or "").isdigit()}
    script, needed = [], []
    for menu, r, killer in dead:
        rules = items(snap, menu)
        tunnels = [name for port, name in wg_ports.items() if (r.get("action") or "accept") == "accept"
                   and _proto(r.get("protocol")) == "udp" and _port_match(r.get("dst-port", ""), int(port))]
        if tunnels:
            needed += tunnels
            if _find_unique(r, rules) and _find_unique(killer, rules):
                script.append(f"{cli_menu(menu)} move [ find where {find_expr(r, rules)} ] "
                              f"destination=[ find where {find_expr(killer, rules)} ]")
            else:
                script.append(f"# {cli_menu(menu)}: {_rule_text(r)} – vor die abschließende Regel verschieben "
                              f"(WireGuard {', '.join(tunnels)})")
        elif _find_unique(r, rules):
            script.append(f"{cli_menu(menu)} remove [ find where {find_expr(r, rules)} ]")
        else:
            script.append(f"# {cli_menu(menu)}: {_rule_text(r)} – nicht eindeutig auswählbar, von Hand löschen")
    for menu, ch in unused:
        script.append(f"{cli_menu(menu)} remove [ find where chain={_q(ch)} ]")
    parts = [f"{len(dead)} Regel(n) hinter einer abschließenden Regel"] if dead else []
    parts += [f"{len(unused)} Kette(n) ohne Sprung"] if unused else []
    parts += [f"darunter WireGuard {', '.join(dict.fromkeys(needed))}"] if needed else []
    killers = list(dict.fromkeys(_rule_text(k) for _m, _r, k in dead))
    add(finding("fw.dead", "firewall", CHANGE, "Wirkungslose Firewall-Regeln: " + ", ".join(parts),
                "Eine Regel ohne Bedingungen (z. B. „drop“ am Ende der Input-Kette) behandelt jedes Paket – alle "
                "Regeln danach greifen nie" + (f" (abschließend: {'; '.join(killers[:2])})" if killers else "")
                + ". Benutzerdefinierte Ketten, in die keine aktive jump-Regel springt, werden nie durchlaufen. "
                "Wird eine Regel gebraucht (z. B. ein WireGuard-Port), sie vor die abschließende Regel verschieben; "
                "der Rest kann weg – Löschen ändert nichts am Verhalten."
                + (" Für WireGuard heißt das: Gegenstellen können den Tunnel nicht von außen aufbauen."
                   if needed else ""),
                current="; ".join([_rule_text(r) for _m, r, _k in dead[:5]] + [f"Kette {c}" for _m, c in unused]),
                script=script))


def _log_findings(snap, add) -> None:
    """log=yes on rules that hit every connection flushes the 1000-line memory log."""
    hits: list[tuple[str, dict]] = []
    never = _never_fires(snap)
    for menu in ("ip/firewall/nat", "ip/firewall/filter", "ip/firewall/raw"):
        for r in items(snap, menu):
            if not enabled(r) or not yes(r.get("log")) or id(r) in never:
                continue
            action = r.get("action") or "accept"
            if menu.endswith("nat"):
                busy = action in ("masquerade", "src-nat", "dst-nat", "netmap", "same")
            else:
                busy = (action == "accept" and not r.get("dst-port") and not r.get("port")) or \
                       (action in DROP_ACTIONS and unconditional(r))
            if busy:
                hits.append((menu, r))
    if not hits:
        return
    flagged = {id(r) for _m, r in hits}
    script = []
    for m, r in hits:
        rules = items(snap, m)
        expr = find_expr(r, rules)
        keys = [k for k in FIND_KEYS if r.get(k)]
        # the expression must not also catch a logging rule that was not flagged (e.g. a port-specific one)
        other = not expr.startswith("comment=") and any(
            yes(x.get("log")) and id(x) not in flagged and all(x.get(k) == r.get(k) for k in keys) for x in rules)
        script.append(f"# {cli_menu(m)}: {_rule_text(r)} – nicht eindeutig auswählbar, log=no von Hand setzen"
                      if other else f"{cli_menu(m)} set [ find where log=yes {expr} ] log=no")
    script = list(dict.fromkeys(script))
    add(finding("fw.log", "firewall", CHANGE, f"{len(hits)} Regel(n) schreiben jede Verbindung ins Log",
                "log=yes an NAT-Regeln und an breiten accept- bzw. abschließenden drop-Regeln erzeugt einen Eintrag "
                "pro Verbindung oder Paket. Das Speicher-Log (1000 Zeilen) läuft so in Sekunden über: wichtige "
                "Meldungen wie Anmeldefehler gehen verloren – auch für Skripte, die das Log auswerten – und die "
                "CPU-Last steigt.", severity="info",
                current="; ".join(_rule_text(r) for _m, r in hits[:5]), script=script))


ORPHAN_KEYS = ("interface", "in-interface", "out-interface", "interfaces", "discovery-interfaces", "bridge",
               "master-interface")


def _orphan_ref(item: dict) -> bool:
    refs = [v.strip().lstrip("!") for k in ORPHAN_KEYS for v in str(item.get(k) or "").split(",")]
    gw = str(item.get("gateway") or "")
    refs += [gw.split("%", 1)[1]] if "%" in gw else []
    return any(ORPHAN_RE.match(v) for v in refs if v)


def _orphan_findings(snap, add) -> None:
    """Entries that still point to a deleted interface (RouterOS shows it as its internal id, e.g. *1)."""
    hits: dict[str, list[dict]] = {}
    for menu, lst in (snap.get("menus") or {}).items():
        if menu == "interface":
            continue
        for it in lst:
            if _orphan_ref(it):
                hits.setdefault(menu, []).append(it)
    if not hits:
        return
    total = sum(len(v) for v in hits.values())
    add(finding("sys.orphans", "system", CHANGE, f"{total} Eintrag/Einträge verweisen auf gelöschte Interfaces",
                "Sie stammen von Interfaces, die es nicht mehr gibt (Anzeige als *1, *14A …), und wirken nicht mehr. "
                "Firewall-Regeln dieser Art greifen nie, sind aber beim Lesen irreführend. Anzeigen, prüfen und "
                "löschen (in der Liste als ungültig markiert).", severity="info",
                current="; ".join(f"{cli_menu(m)}: {len(v)}" for m, v in hits.items()),
                script=[f"# {cli_menu(m)} print – Einträge mit *… prüfen, dann entfernen oder korrigieren"
                        for m in hits]))


def _policy_findings(snap, t, add, mangle, fasttrack, table, wan, lan_net, tag) -> None:
    tables = {x.get("name"): x for x in items(snap, "routing/table")}
    if table in tables:
        add(finding("pol.table", "policy", OK, f"Routing-Tabelle {table}"))
    else:
        add(finding("pol.table", "policy", MISSING, f"Routing-Tabelle {table} fehlt",
                    ops=[op_add("routing/table", {"name": table, "fib": "", "comment": tag + "Internet"})],
                    script=[f"/routing table add name={table} fib comment=\"{tag}Internet\""]))
    have_route = any(r.get("dst-address") == "0.0.0.0/0" and r.get("routing-table") == table and enabled(r)
                     for r in items(snap, "ip/route"))
    gw = wan_gateway(snap)
    if have_route:
        add(finding("pol.route", "policy", OK, f"Default-Route in Tabelle {table}"))
    elif gw:
        add(finding("pol.route", "policy", MISSING, f"Default-Route in Tabelle {table} fehlt",
                    ops=[op_add("ip/route", {"dst-address": "0.0.0.0/0", "gateway": gw, "routing-table": table,
                                             "comment": tag + "Internet"})]))
    else:
        add(finding("pol.route", "policy", MISSING, f"Default-Route in Tabelle {table} fehlt",
                    "Gateway nicht ermittelbar (DHCP auf WAN?) – bitte Gateway-IP einsetzen. Bei DHCP kann "
                    "im DHCP-Client ein Skript die Route nachführen.",
                    script=[f"/ip route add dst-address=0.0.0.0/0 gateway=<GATEWAY-IP> routing-table={table} "
                            f"comment=\"{tag}Internet\""]))
    lists = items(snap, "ip/firewall/address-list")
    local_have = {x.get("address") for x in lists if x.get("list") == "sm-local-nets"}
    want = [n for n in dict.fromkeys([lan_net] + PRIVATE_NETS) if n]
    missing_nets = [n for n in want if n not in local_have]
    if missing_nets:
        add(finding("pol.local", "policy", MISSING, "Adressliste sm-local-nets unvollständig",
                    "Interne Ziele werden von der Markierung ausgenommen.",
                    ops=[op_add("ip/firewall/address-list", {"list": "sm-local-nets", "address": n,
                                                              "comment": tag + "lokale Netze"})
                         for n in missing_nets]))
    else:
        add(finding("pol.local", "policy", OK, "Adressliste sm-local-nets"))
    conn_mark = f"{table}-conn"

    def has(pred) -> bool:
        return any(pred(r) for r in mangle)

    rules = [
        ("pol.m1", "Verbindungen aus dem LAN ins Internet markieren",
         lambda r: r.get("action") == "mark-connection" and r.get("new-connection-mark") == conn_mark
         and r.get("src-address") == lan_net,
         {"chain": "prerouting", "action": "mark-connection", "src-address": lan_net,
          "dst-address-list": "!sm-local-nets", "connection-state": "new", "new-connection-mark": conn_mark,
          "passthrough": "yes", "comment": tag + "LAN -> Internet (Verbindung)"}),
        ("pol.m2", "Antworten auf eingehende WAN-Verbindungen markieren",
         lambda r: r.get("action") == "mark-connection" and r.get("new-connection-mark") == conn_mark
         and r.get("in-interface") == wan,
         {"chain": "prerouting", "action": "mark-connection", "in-interface": wan, "connection-state": "new",
          "new-connection-mark": conn_mark, "passthrough": "yes", "comment": tag + "WAN eingehend (Verbindung)"}),
        ("pol.m3", f"Routing-Markierung {table} für markierte Verbindungen aus dem LAN",
         lambda r: r.get("action") == "mark-routing" and r.get("new-routing-mark") == table,
         {"chain": "prerouting", "action": "mark-routing", "connection-mark": conn_mark, "src-address": lan_net,
          "dst-address-list": "!sm-local-nets", "new-routing-mark": table, "passthrough": "no",
          "comment": tag + "LAN -> Internet (Routing)"}),
    ]
    for fid, title, pred, data in rules:
        if has(pred):
            add(finding(fid, "policy", OK, title))
        else:
            add(finding(fid, "policy", MISSING, title, ops=[op_add("ip/firewall/mangle", data)]))
    foreign = [r for r in mangle if r.get("action") == "mark-routing" and not ours(r)
               and r.get("new-routing-mark") != table]
    if foreign:
        add(finding("pol.foreign", "policy", CHECK, f"{len(foreign)} weitere Routing-Markierung(en)",
                    "Bleiben bestehen. Überschneiden sie sich mit dem LAN, gewinnt die zuerst passende Regel "
                    "(Reihenfolge prüfen).", current="; ".join(_rule_text(r) for r in foreign[:5])))
    ft = [r for r in fasttrack if r.get("connection-mark") != "no-mark"]
    if ft:
        add(finding("pol.fasttrack", "policy", CHANGE, "FastTrack umgeht die Mangle-Markierungen",
                    "Per FastTrack beschleunigte Verbindungen durchlaufen Mangle nicht mehr – markierte "
                    "Verbindungen würden falsch geroutet. Die FastTrack-Regel auf unmarkierte Verbindungen "
                    "beschränken (Firewall-Regel – nur als Skript).", current=_rule_text(ft[0]),
                    script=["/ip firewall filter set [ find where action=fasttrack-connection ] "
                            "connection-mark=no-mark"]))


def _firewall_findings(snap, t, add, wan, lan, lan_net) -> None:
    rules = [r for r in items(snap, "ip/firewall/filter") if enabled(r)]
    inp = [r for r in rules if r.get("chain") == "input"]
    fwd = [r for r in rules if r.get("chain") == "forward"]
    est = any(r.get("action") == "accept" and "established" in str(r.get("connection-state", ""))
              for r in inp)
    invalid = any(r.get("action") == "drop" and "invalid" in str(r.get("connection-state", "")) for r in inp)
    wan_drop = any(r.get("action") in ("drop", "reject") and not r.get("protocol") and not r.get("dst-port")
                   and not r.get("src-address") and not r.get("connection-state") and
                   (rule_matches_iface(r, "in", wan, snap) or
                    str(r.get("in-interface-list", "")).startswith("!") or
                    (not r.get("in-interface") and not r.get("in-interface-list")))
                   for r in inp)
    mgmt = split_list(t.get("mgmt_addresses", ""))
    if est and invalid and wan_drop:
        add(finding("fw.input", "firewall", OK, "Input-Kette schützt den Router",
                    "Established/related erlaubt, invalid verworfen, Rest von WAN verworfen."))
    else:
        missing = [x for x, ok in (("established/related erlauben", est), ("invalid verwerfen", invalid),
                                   ("Rest von WAN verwerfen", wan_drop)) if not ok]
        wg_ports = [w.get("listen-port") for w in items(snap, "interface/wireguard") if w.get("listen-port")]
        script = [
            "/ip firewall address-list add list=sm-mgmt address=" + (mgmt[0] if mgmt else "<ADMIN-IP>")
            + " comment=\"servermanager: Management\"",
            *[f"/ip firewall address-list add list=sm-mgmt address={m} comment=\"servermanager: Management\""
              for m in mgmt[1:]],
            "/ip firewall filter",
            "add chain=input action=accept connection-state=established,related,untracked "
            "comment=\"servermanager: established\"",
            "add chain=input action=drop connection-state=invalid comment=\"servermanager: invalid\"",
            "add chain=input action=accept protocol=icmp comment=\"servermanager: icmp\"",
            *[f"add chain=input action=accept protocol=udp dst-port={p} comment=\"servermanager: WireGuard\""
              for p in wg_ports],
            "add chain=input action=accept src-address-list=sm-mgmt comment=\"servermanager: Management\"",
            f"add chain=input action=accept in-interface={lan} comment=\"servermanager: LAN\"",
            f"add chain=input action=drop in-interface={wan} comment=\"servermanager: drop WAN\"",
        ]
        add(finding("fw.input", "firewall", MISSING if not inp else CHANGE,
                    "Input-Kette unvollständig – Router von außen angreifbar",
                    "Fehlt: " + ", ".join(missing) + ". Nur als Skript: vor dem Einspielen prüfen, dass die eigene "
                    "Management-Adresse in sm-mgmt steht (sonst Aussperrung!) und die Regeln vor vorhandenen "
                    "drop-Regeln stehen (place-before).", severity="crit", script=script))
    fwd_est = any(r.get("action") in ("accept", "fasttrack-connection") and "established" in
                  str(r.get("connection-state", "")) for r in fwd)
    fwd_wan = any(r.get("action") == "drop" and rule_matches_iface(r, "in", wan, snap) and
                  "dstnat" in str(r.get("connection-nat-state", "")) for r in fwd)
    if fwd_est and fwd_wan:
        add(finding("fw.forward", "firewall", OK, "Forward-Kette schützt das LAN"))
    else:
        add(finding("fw.forward", "firewall", CHANGE if fwd else MISSING,
                    "Forward-Kette: LAN nicht gegen Zugriffe aus dem Internet geschützt",
                    "Empfohlen: established/related erlauben, invalid verwerfen, von WAN nur Portweiterleitungen "
                    "(dstnat) zulassen. Ausgehender Verkehr aus dem LAN (Newt!) bleibt erlaubt.",
                    script=["/ip firewall filter",
                            "add chain=forward action=accept connection-state=established,related,untracked "
                            "comment=\"servermanager: established\"",
                            "add chain=forward action=drop connection-state=invalid comment=\"servermanager: invalid\"",
                            f"add chain=forward action=drop in-interface={wan} connection-nat-state=!dstnat "
                            "connection-state=new comment=\"servermanager: drop WAN not dstnat\""]))
    dns = single(snap, "ip/dns")
    if yes(dns.get("allow-remote-requests")) and not wan_drop:
        add(finding("fw.dns", "firewall", CHANGE, "Offener DNS-Resolver",
                    "allow-remote-requests ist aktiv, aber die Input-Kette verwirft Anfragen von WAN nicht – der "
                    "Router kann für DNS-Amplification missbraucht werden.", severity="crit",
                    script=[f"/ip firewall filter add chain=input action=drop in-interface={wan} protocol=udp "
                            "dst-port=53 comment=\"servermanager: DNS von WAN\"",
                            f"/ip firewall filter add chain=input action=drop in-interface={wan} protocol=tcp "
                            "dst-port=53 comment=\"servermanager: DNS von WAN\""]))


def _service_findings(snap, t, add, wan) -> None:
    services = {s.get("name"): s for s in items(snap, "ip/service")}
    mgmt = ",".join(split_list(t.get("mgmt_addresses", "")))
    insecure = [n for n in ("telnet", "ftp", "www", "api") if n in services and enabled(services[n])]
    if insecure:
        add(finding("svc.insecure", "services", CHANGE, "Unverschlüsselte Dienste aktiv: " + ", ".join(insecure),
                    "Nur als Skript: Wird der Servermanager noch über http/api angebunden, zuerst auf "
                    "www-ssl (https) umstellen.",
                    script=[f"/ip service disable {','.join(insecure)}"]))
    else:
        add(finding("svc.insecure", "services", OK, "Keine unverschlüsselten Dienste aktiv"))
    ssl = services.get("www-ssl")
    if ssl and enabled(ssl):
        if ssl.get("certificate") in (None, "", "none"):
            add(finding("svc.rest", "services", CHANGE, "www-ssl ohne Zertifikat",
                        script=["/certificate add name=sm-rest common-name=router key-usage=tls-server",
                                "/certificate sign sm-rest",
                                "/ip service set www-ssl certificate=sm-rest"]))
        else:
            add(finding("svc.rest", "services", OK, "REST-API über www-ssl (https)",
                        current=f"Port {ssl.get('port', '443')}, Zertifikat {ssl.get('certificate', '')}"))
    else:
        add(finding("svc.rest", "services", MISSING, "www-ssl (REST-API über https) nicht aktiv",
                    "Der Servermanager nutzt die REST-API – sie sollte nur über https erreichbar sein.",
                    script=["/certificate add name=sm-rest common-name=router key-usage=tls-server",
                            "/certificate sign sm-rest",
                            "/ip service set www-ssl certificate=sm-rest disabled=no"
                            + (f" address={mgmt}" if mgmt else "")]))
    open_mgmt = [n for n in ("ssh", "winbox", "www-ssl", "api-ssl") if n in services and
                 enabled(services[n]) and not services[n].get("address")]
    if open_mgmt:
        add(finding("svc.address", "services", CHANGE,
                    "Management-Dienste ohne Adressbeschränkung: " + ", ".join(open_mgmt),
                    "Nur als Skript – ACHTUNG Aussperrung: die Liste muss die Adresse enthalten, von der der "
                    "Servermanager und die Administratoren zugreifen (z. B. WireGuard-Management-Netz).",
                    script=[f"/ip service set {n} address={mgmt or '<MGMT-NETZ>'}" for n in open_mgmt]))
    elif any(n in services for n in ("ssh", "winbox")):
        add(finding("svc.address", "services", OK, "Management-Dienste auf Adressen beschränkt"))
    disc = single(snap, "ip/neighbor/discovery-settings")
    if disc and disc.get("discover-interface-list") in ("all", "", None):
        add(finding("svc.discovery", "services", CHANGE, "Neighbor Discovery auf allen Interfaces (auch WAN)",
                    script=["/interface list add name=LAN comment=\"servermanager\"",
                            f"/interface list member add list=LAN interface={t['lan_interface']}",
                            "/ip neighbor discovery-settings set discover-interface-list=LAN"]))
    mac = single(snap, "tool/mac-server")
    macw = single(snap, "tool/mac-server/mac-winbox")
    if (mac and mac.get("allowed-interface-list") in ("all", "")) or \
            (macw and macw.get("allowed-interface-list") in ("all", "")):
        add(finding("svc.mac", "services", CHANGE, "MAC-Telnet/MAC-Winbox auf allen Interfaces",
                    script=["/tool mac-server set allowed-interface-list=LAN",
                            "/tool mac-server mac-winbox set allowed-interface-list=LAN"]))
    users = items(snap, "user")
    if any(u.get("name") == "admin" and enabled(u) for u in users):
        add(finding("svc.admin", "services", CHECK, "Standardbenutzer „admin“ aktiv",
                    "Eigenen Administrator anlegen und admin deaktivieren (erschwert Brute-Force).",
                    script=["/user add name=<NAME> group=full password=<PASSWORT>", "/user disable admin"]))


def summarize(findings: list[dict]) -> dict:
    counts = {OK: 0, CHANGE: 0, MISSING: 0, CHECK: 0}
    crit = 0
    for f in findings:
        counts[f["status"]] += 1
        crit += f["severity"] == "crit"
    return {"counts": counts, "crit": crit, "applicable": sum(1 for f in findings if f["applicable"])}


def full_script(findings: list[dict]) -> str:
    lines = ["# Servermanager – Änderungen aus der Konfigurationsanalyse",
             "# Vor dem Einspielen prüfen! Firewall-/Dienst-Regeln können den Zugang sperren."]
    added: set[str] = set()
    for f in findings:
        if f["status"] == OK or not f["script"]:
            continue
        lines.append(f"\n# {AREAS.get(f['area'], f['area'])}: {_cli_escape(f['title'])}")
        for line in f["script"]:
            if line.startswith("/") and " add " in line:
                if line in added:
                    continue  # e.g. the same DHCP option for two networks
                added.add(line)
            lines.append(line)
    return "\n".join(lines) + "\n"


def unique_ops(ops: Iterable[dict]) -> list[dict]:
    """Operations of several findings without repeats (e.g. the same DHCP option for two networks)."""
    out, seen = [], set()
    for op in ops:
        key = (op["m"], op["path"], op.get("id"), op.get("find"), tuple(sorted(op["data"].items())))
        if key not in seen:
            seen.add(key)
            out.append(op)
    return out


# ==========================================================================
# apply
# ==========================================================================
def backup_before_change(mt: MikroTik) -> str:
    name = "sm-before-" + datetime.now().strftime("%Y%m%d-%H%M%S")
    mt.command("system/backup/save", {"name": name, "dont-encrypt": "yes"}, timeout=60)
    try:
        mt.command("export", {"file": name, "hide-sensitive": ""}, timeout=60)
    except MikroTikError:
        pass
    return name


def apply_ops(mt: MikroTik, ops: list[dict], log: Callable[[str], None]) -> int:
    done = 0
    for op in ops:
        if op["m"] == "add":
            mt.create(op["path"], op["data"])
        elif op["m"] == "set" and op.get("id"):
            mt.patch(op["path"], op["id"], op["data"])
        elif op["m"] == "set":
            mt.command(op["path"] + "/set", op["data"])
        else:
            raise RouterOSError(f"Unbekannte Operation {op['m']}")
        log(op_to_cli(op))
        done += 1
    return done


# --------------------------------------------------------------------------
# ping test diagnosis
# --------------------------------------------------------------------------
PING_STATUS = {"timeout": "Zeitüberschreitung", "no route to host": "keine Route zum Ziel",
               "net unreachable": "Netz nicht erreichbar", "host unreachable": "Host nicht erreichbar"}
_IP_IN = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


def ping_result(res: Any) -> dict:
    """Summary of a /ping reply (list of per-packet entries, the last one carries the totals)."""
    rows = res if isinstance(res, list) else ([res] if isinstance(res, dict) else [])
    last = rows[-1] if rows else {}
    statuses = []
    for r in rows:
        st = str(r.get("status") or "").strip()
        if st and st not in statuses:
            statuses.append(st)
    return {"sent": str(last.get("sent", "?")), "received": str(last.get("received", "")),
            "avg": last.get("avg-rtt", "?"), "statuses": statuses}


def ping_diagnosis(mt: MikroTik, target: str, src: str = "") -> list[str]:
    """Likely causes when the router itself cannot reach a host (each check is best effort)."""
    hints: list[str] = []
    try:
        routes = [r for r in mt.get("ip/route") if r.get("dst-address") == "0.0.0.0/0" and enabled(r)
                  and r.get("routing-table", "main") in ("main", "")]
    except MikroTikError:
        routes = None
    gw_ip = ""
    if routes is not None:
        active = [r for r in routes if yes(r.get("active"))]
        if not routes:
            hints.append("Keine Default-Route (0.0.0.0/0) in der Tabelle main – DHCP-Client mit "
                         "add-default-route=yes oder /ip route add dst-address=0.0.0.0/0 gateway=<GATEWAY>.")
        elif not active:
            gws = ", ".join(str(r.get("gateway", "?")) for r in routes)
            hints.append(f"Default-Route vorhanden, aber nicht aktiv (Gateway {gws} nicht erreichbar). Liegt das "
                         "Gateway außerhalb des eigenen Netzes (z. B. Hetzner Cloud: 172.31.1.1 bei einer /32-Adresse), "
                         "das Interface mit angeben: gateway=172.31.1.1%<WAN-Interface>.")
        else:
            m = _IP_IN.search(str(active[0].get("immediate-gw") or active[0].get("gateway") or ""))
            gw_ip = m.group(1) if m else ""
    if gw_ip and gw_ip != target:
        try:
            gw = ping_result(mt.command("ping", {"address": gw_ip, "count": "2"}, timeout=20))
            if gw["received"] in ("0", ""):
                hints.append(f"Auch das Gateway {gw_ip} antwortet nicht – Anbindung zum Provider prüfen "
                             "(manche Gateways beantworten allerdings keinen Ping).")
            else:
                hints.append(f"Das Gateway {gw_ip} antwortet – das Problem liegt dahinter oder in einer Filterregel.")
        except MikroTikError:
            pass
    try:
        drops = [r for r in mt.get("ip/firewall/filter") if r.get("chain") == "output" and enabled(r)
                 and r.get("action") in ("drop", "reject")]
        if drops:
            hints.append(f"{len(drops)} Firewall-Regel(n) in chain=output verwerfen Pakete des Routers selbst.")
    except MikroTikError:
        pass
    try:
        marks = [r for r in mt.get("ip/firewall/mangle") if r.get("chain") == "output" and enabled(r)
                 and r.get("action") == "mark-routing"]
        if marks:
            tables = ", ".join(sorted({str(r.get("new-routing-mark", "?")) for r in marks}))
            hints.append(f"Mangle-Regeln in chain=output leiten Pakete des Routers über die Tabelle(n) {tables} "
                         "– dort muss eine funktionierende Default-Route existieren.")
    except MikroTikError:
        pass
    if src:
        try:
            local = {str(a.get("address", "")).split("/")[0] for a in mt.get("ip/address")}
            if src not in local:
                hints.append(f"Die Quelladresse {src} ist keine Adresse des Routers.")
        except MikroTikError:
            pass
    return hints
