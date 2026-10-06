"""Hetzner root servers (Robot webservice): status, IPs with reverse DNS, traffic, resets.

Rights: on the Robot account (all servers) or on single servers; Auswerten = view, Neustarten = operate,
Ändern = full. Accounts are added/edited by administrators only.
"""
from __future__ import annotations

import ipaddress
from datetime import date, datetime, timezone

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from sqlalchemy import select

from ... import access, hetzner, integrations, security
from ...core import audit
from ...hetzner import RESET_TYPES, RobotError
from ...models import (KIND_HCLOUD, KIND_HETZNER, KIND_HETZNER_SRV, LEVEL_FULL, LEVEL_OPERATE, LEVEL_VIEW,
                       HcloudProject, HetznerAccount, HetznerServer, System)
from ..auth import admin_required, client_ip, login_required, rate_ok
from ..charts import fmt_bytes, line_chart
from . import _integration as common

bp = Blueprint("hetzner", __name__, url_prefix="/hetzner")
GB = 1024 ** 3
# resets anybody with "Neustarten" may trigger; the technician (man) needs "Ändern"
OPERATE_RESETS = ("sw", "hw", "power", "power_long")


def _account(aid: int, level: str) -> HetznerAccount:
    return common.get_or_403(KIND_HETZNER, aid, level)


def _server(sid: int, level: str) -> HetznerServer:
    srv = g.db.get(HetznerServer, sid)
    if srv is None:
        abort(404)
    if not access.has_hetzner_level(g.db, g.user, srv, level):
        abort(403)
    return srv


def _visible_servers() -> list[HetznerServer]:
    rows = g.db.execute(select(HetznerServer).order_by(HetznerServer.name)).scalars().all()
    return [s for s in rows if access.hetzner_server_level(g.db, g.user, s)]


def _level(srv: HetznerServer) -> str:
    return access.hetzner_server_level(g.db, g.user, srv) or ""


@bp.get("/")
@login_required
def index():
    from .hcloud import visible_servers as cloud_visible
    accounts = common.visible(KIND_HETZNER)
    servers = _visible_servers()
    projects = common.visible(KIND_HCLOUD)
    cloud = cloud_visible()
    if not accounts and not servers and not projects and not cloud and not g.user.is_admin:
        abort(403)
    names = {a.id: a.name for a in g.db.execute(select(HetznerAccount)).scalars()}
    pnames = {p.id: p.name for p in g.db.execute(select(HcloudProject)).scalars()}
    systems = {s.id: s for s in g.db.execute(select(System)).scalars()}
    return render_template("hetzner/index.html", accounts=accounts, servers=servers, names=names, systems=systems,
                           levels={s.id: _level(s) for s in servers}, projects=projects, cloud=[c for c, _ in cloud],
                           cloud_levels={c.id: lv for c, lv in cloud}, pnames=pnames)


# ------------------------------------------------------------------ accounts (administrators)
def _save(a: HetznerAccount) -> list[str]:
    f = request.form
    errors = []
    a.name = (f.get("name") or "").strip()[:128]
    if not a.name:
        errors.append("Bitte einen Namen angeben.")
    a.description = (f.get("description") or "").strip()[:2000]
    a.username = (f.get("username") or "").strip()[:128]
    if not a.username:
        errors.append("Webservice-Benutzer angeben (Robot → Einstellungen → Webservice- und App-Einstellungen).")
    if f.get("password"):
        a.password_enc = security.encrypt(f["password"])
    elif not a.password_enc:
        errors.append("Passwort des Webservice-Benutzers angeben.")
    try:
        a.traffic_alert_pct = max(0, min(100, int(f.get("traffic_alert_pct") or 0)))
    except ValueError:
        errors.append("Traffic-Warnung in Prozent angeben.")
    a.monitor = bool(f.get("monitor"))
    a.api_url = a.api_url or hetzner.API_URL
    return errors


def _form(a: HetznerAccount, is_new: bool):
    return render_template("hetzner/form.html", a=a, is_new=is_new)


@bp.route("/new", methods=["GET", "POST"])
@admin_required
def new():
    a = HetznerAccount(monitor=True, traffic_alert_pct=90, api_url=hetzner.API_URL)
    if request.method == "POST":
        errors = _save(a)
        if errors:
            for e in errors:
                flash(e, "danger")
            return _form(a, True)
        g.db.add(a)
        g.db.flush()
        audit(g.db, g.user, "hetzner.create", a.name, a.username, ip=client_ip())
        integrations.poll(g.db, a)
        g.db.commit()
        if a.status_message:
            flash(f"Gespeichert, aber: {a.status_message}", "warning")
        else:
            flash(f"Hetzner-Konto angebunden: {a.data.get('servers', 0)} Server gefunden.", "success")
        return redirect(url_for("hetzner.index"))
    return _form(a, True)


@bp.route("/account/<int:aid>/edit", methods=["GET", "POST"])
@admin_required
def edit(aid: int):
    a = _account(aid, LEVEL_FULL)
    if request.method == "POST":
        errors = _save(a)
        if errors:
            g.db.rollback()
            for e in errors:
                flash(e, "danger")
            return redirect(url_for("hetzner.edit", aid=aid))
        audit(g.db, g.user, "hetzner.update", a.name, ip=client_ip())
        integrations.poll(g.db, a)
        g.db.commit()
        flash("Gespeichert.", "success")
        return redirect(url_for("hetzner.index"))
    return _form(a, False)


@bp.post("/account/<int:aid>/delete")
@admin_required
def delete(aid: int):
    a = _account(aid, LEVEL_FULL)
    for srv in g.db.execute(select(HetznerServer).where(HetznerServer.account_id == a.id)).scalars():
        access.remove_integration(g.db, KIND_HETZNER_SRV, srv.id)
    access.remove_integration(g.db, KIND_HETZNER, a.id)
    audit(g.db, g.user, "hetzner.delete", a.name, ip=client_ip())
    g.db.delete(a)
    g.db.commit()
    flash("Hetzner-Konto entfernt (die Server bei Hetzner bleiben unverändert).", "warning")
    return redirect(url_for("hetzner.index"))


@bp.post("/account/<int:aid>/refresh")
@login_required
def refresh(aid: int):
    a = _account(aid, LEVEL_OPERATE)
    integrations.poll(g.db, a)
    g.db.commit()
    flash(a.status_message or "Aktualisiert.", "danger" if a.status_message else "success")
    return redirect(common.safe_next(url_for("hetzner.index")))


# ------------------------------------------------------------------ server
def _traffic_chart(series: dict, period: str, year: int, month: int):
    rows = []
    for slot, v in series.items():
        try:
            n = int(slot)
            t = datetime(year, n, 1) if period == "year" else datetime(year, month, n)
        except ValueError:
            continue
        rows.append({"time": t.replace(tzinfo=timezone.utc).timestamp(), "in": v["in"] * GB, "out": v["out"] * GB})
    return line_chart(rows, [("Eingehend", "s1", lambda r: r["in"]), ("Ausgehend", "s2", lambda r: r["out"])],
                      fmt_bytes, timeframe="year" if period == "year" else "month", tz=timezone.utc)


def _period_traffic(acc: HetznerAccount, ips: list[str], nets: list[str], cached: dict,
                    no_data: str = "Hetzner liefert für dieses Subnetz keine Werte") -> dict:
    """Traffic for the period chosen in the request: the current month from the cache, others live."""
    today = date.today()
    period = request.args.get("period", "month")
    ym = request.args.get("m", today.strftime("%Y-%m"))
    traffic, error = cached or {}, ""
    try:
        year, month = (int(x) for x in ym.split("-")[:2])
        date(year, month, 1)
    except ValueError:
        year, month = today.year, today.month
    if period == "year" or (year, month) != (today.year, today.month):
        # other periods are fetched live (Robot rate limit: a few per minute and user)
        if not rate_ok(f"hetzner-traffic:{g.user.id}", 20):
            error = "Zu viele Abfragen – bitte eine Minute warten."
        else:
            try:
                robot = integrations.hetzner_client(acc)
                if period == "year":
                    end_month = today.month if year == today.year else 12
                    data = robot.traffic("year", f"{year}-01", f"{year}-{end_month:02d}", ips, nets)
                else:
                    data = robot.traffic("month", *hetzner.month_range(year, month, today), ips, nets)
                days, total = hetzner.sum_series(data, ips + nets)
                skipped = robot.skipped_subnets
                all_skipped = bool(skipped) and not ips and len(skipped) == len(set(n.split("/")[0] for n in nets))
                traffic = {"days": days, "total": total, "limit_gb": traffic.get("limit_gb"),
                           "error": no_data if all_skipped else
                           ("Ohne " + ", ".join(skipped) + " – " + no_data) if skipped else ""}
            except RobotError as exc:
                error, traffic = str(exc), {}
    months = [f"{y:04d}-{m:02d}" for y, m in
              (((today.year * 12 + today.month - 1 - i) // 12, (today.year * 12 + today.month - 1 - i) % 12 + 1)
               for i in range(13))]
    return {"traffic": traffic, "error": error, "period": period, "ym": f"{year:04d}-{month:02d}", "year": year,
            "months": months,
            "chart": _traffic_chart(traffic.get("days") or {}, period, year, month) if traffic else None}


@bp.get("/server/<int:sid>")
@login_required
def server(sid: int):
    srv = _server(sid, LEVEL_VIEW)
    acc = g.db.get(HetznerAccount, srv.account_id)
    info = srv.info
    ips, nets = hetzner.addresses_of(info.get("server") or {})
    ctx = _period_traffic(acc, ips, nets, info.get("traffic") or {})
    system = g.db.get(System, srv.system_id) if srv.system_id else None
    if system is not None and not (g.user.is_admin or access.system_level(g.db, g.user, system.id)):
        system = None
    return render_template("hetzner/server.html", srv=srv, acc=acc, info=info, s=info.get("server") or {},
                           level=_level(srv), system=system, reset_types=RESET_TYPES, operate_resets=OPERATE_RESETS,
                           account_view=common.can(KIND_HETZNER, acc.id, LEVEL_VIEW), **ctx)


# ------------------------------------------------------------------ vSwitch (rights on the whole account)
def _vswitch(aid: int, vid: int, level: str) -> tuple[HetznerAccount, dict]:
    acc = _account(aid, level)
    v = next((x for x in acc.data.get("vswitches") or [] if int(x.get("id") or 0) == vid), None)
    if v is None:
        abort(404)
    return acc, v


@bp.get("/account/<int:aid>/vswitch/<int:vid>")
@login_required
def vswitch(aid: int, vid: int):
    from ...models import KIND_PVE, PveServer
    acc, v = _vswitch(aid, vid, LEVEL_VIEW)
    nets = [f"{n['ip']}/{n['mask']}" for n in v.get("subnets") or []]
    ctx = _period_traffic(acc, [], nets, v.get("traffic") or {}, no_data=integrations.VSWITCH_NO_TRAFFIC)
    rows = {r.number: r for r in g.db.execute(select(HetznerServer).where(HetznerServer.account_id == acc.id)).scalars()}
    pves = [p for p in g.db.execute(select(PveServer).where(PveServer.vswitch_vlan == v.get("vlan"))).scalars()
            if common.can(KIND_PVE, p.id, LEVEL_VIEW)]
    return render_template("hetzner/vswitch.html", acc=acc, v=v, rows=rows, pves=pves,
                           can_full=common.can(KIND_HETZNER, acc.id, LEVEL_FULL), **ctx)


@bp.post("/account/<int:aid>/vswitch/<int:vid>/rdns")
@login_required
def vswitch_rdns(aid: int, vid: int):
    acc, v = _vswitch(aid, vid, LEVEL_FULL)
    back = url_for("hetzner.vswitch", aid=aid, vid=vid)
    try:
        ip = str(ipaddress.ip_address((request.form.get("ip") or "").strip()))
    except ValueError:
        abort(400, description="Ungültige IP-Adresse")
    if not hetzner.in_nets(ip, v.get("subnets") or []):
        abort(400, description="Die Adresse liegt in keinem Netz dieses vSwitches")
    ptr = (request.form.get("ptr") or "").strip()
    try:
        robot = integrations.hetzner_client(acc)
        if ptr:
            ptr = hetzner.validate_ptr(ptr)
            robot.set_rdns(ip, ptr)
        else:
            robot.delete_rdns(ip)
    except RobotError as exc:
        flash(f"PTR-Eintrag nicht gesetzt: {exc}", "danger")
        return redirect(back)
    audit(g.db, g.user, "hetzner.rdns", f"vSwitch {v.get('name')}", f"{ip} → {ptr or '(gelöscht)'}", ip=client_ip())
    data = dict(acc.data)
    switches = [dict(x) for x in data.get("vswitches") or []]
    cur = next(x for x in switches if int(x.get("id") or 0) == vid)
    entries = [r for r in cur.get("rdns") or [] if r["ip"] != ip] + ([{"ip": ip, "ptr": ptr}] if ptr else [])
    cur["rdns"] = sorted(entries, key=lambda r: (":" in r["ip"], r["ip"]))
    data["vswitches"] = switches
    acc.cache = data
    g.db.commit()
    flash(f"PTR für {ip} {'gesetzt: ' + ptr if ptr else 'gelöscht'}.", "success")
    return redirect(back)


def _client_for(srv: HetznerServer):
    acc = g.db.get(HetznerAccount, srv.account_id)
    try:
        return acc, integrations.hetzner_client(acc)
    except RobotError as exc:
        abort(400, description=str(exc))


def _after(srv: HetznerServer, msg: str, ok: bool = True):
    flash(msg, "success" if ok else "danger")
    return redirect(url_for("hetzner.server", sid=srv.id))


@bp.post("/server/<int:sid>/reset")
@login_required
def reset(sid: int):
    kind = request.form.get("type", "")
    if kind not in RESET_TYPES:
        abort(400)
    srv = _server(sid, LEVEL_OPERATE if kind in OPERATE_RESETS else LEVEL_FULL)
    if kind not in (srv.info.get("reset") or list(OPERATE_RESETS)):
        return _after(srv, "Diese Reset-Art bietet Hetzner für den Server nicht an.", False)
    acc, robot = _client_for(srv)
    try:
        robot.reset(srv.number, kind)
    except RobotError as exc:
        audit(g.db, g.user, "hetzner.reset_failed", srv.name, f"#{srv.number} {kind}: {exc}", ip=client_ip())
        g.db.commit()
        return _after(srv, f"Reset fehlgeschlagen: {exc}", False)
    audit(g.db, g.user, "hetzner.reset", srv.name, f"#{srv.number} {kind}", ip=client_ip())
    g.db.commit()
    return _after(srv, f"{RESET_TYPES[kind]} für {srv.name} ausgelöst.")


@bp.post("/server/<int:sid>/wol")
@login_required
def wol(sid: int):
    srv = _server(sid, LEVEL_OPERATE)
    acc, robot = _client_for(srv)
    try:
        robot.wol(srv.number)
    except RobotError as exc:
        return _after(srv, f"Wake-on-LAN fehlgeschlagen: {exc}", False)
    audit(g.db, g.user, "hetzner.wol", srv.name, f"#{srv.number}", ip=client_ip())
    g.db.commit()
    return _after(srv, f"Wake-on-LAN an {srv.name} gesendet.")


@bp.post("/server/<int:sid>/rename")
@login_required
def rename(sid: int):
    srv = _server(sid, LEVEL_FULL)
    name = (request.form.get("name") or "").strip()
    acc, robot = _client_for(srv)
    try:
        robot.rename(srv.number, name)
    except RobotError as exc:
        return _after(srv, f"Umbenennen fehlgeschlagen: {exc}", False)
    audit(g.db, g.user, "hetzner.rename", srv.name, f"#{srv.number} → {name}", ip=client_ip())
    srv.name = (name or f"#{srv.number}")[:128]
    info = dict(srv.info)
    info["server"] = {**(info.get("server") or {}), "server_name": name}
    srv.data = info
    g.db.commit()
    return _after(srv, "Servername geändert.")


def _own_ip(srv: HetznerServer, raw: str) -> str:
    try:
        ip = str(ipaddress.ip_address((raw or "").strip()))
    except ValueError:
        abort(400, description="Ungültige IP-Adresse")
    if not hetzner.belongs_to(ip, srv.info.get("server") or {}):
        abort(400, description="Die Adresse gehört nicht zu diesem Server")
    return ip


def _update_ip(srv: HetznerServer, ip: str, **fields) -> None:
    info = dict(srv.info)
    rows = [dict(r) for r in info.get("ips") or []]
    row = next((r for r in rows if r["ip"] == ip), None)
    if row is None:
        row = {"ip": ip, "ptr": "", "main": False}
        rows.append(row)
    row.update(fields)
    info["ips"] = sorted(rows, key=lambda r: (":" in r["ip"], r["ip"]))
    srv.data = info


@bp.post("/server/<int:sid>/rdns")
@login_required
def rdns(sid: int):
    srv = _server(sid, LEVEL_FULL)
    ip = _own_ip(srv, request.form.get("ip", ""))
    ptr = (request.form.get("ptr") or "").strip()
    acc, robot = _client_for(srv)
    try:
        if ptr:
            ptr = hetzner.validate_ptr(ptr)
            robot.set_rdns(ip, ptr)
        else:
            robot.delete_rdns(ip)
    except RobotError as exc:
        return _after(srv, f"PTR-Eintrag nicht gesetzt: {exc}", False)
    audit(g.db, g.user, "hetzner.rdns", srv.name, f"{ip} → {ptr or '(gelöscht)'}", ip=client_ip())
    _update_ip(srv, ip, ptr=ptr)
    g.db.commit()
    return _after(srv, f"PTR für {ip} {'gesetzt: ' + ptr if ptr else 'gelöscht'}.")


@bp.post("/server/<int:sid>/traffic-warnings")
@login_required
def traffic_warnings(sid: int):
    srv = _server(sid, LEVEL_FULL)
    ip = _own_ip(srv, request.form.get("ip", ""))
    if ":" in ip:
        abort(400, description="Traffic-Warnungen gibt es für einzelne IPv4-Adressen")
    f = request.form
    enabled = f.get("enabled") == "1"
    try:
        hourly, daily, monthly = (int(f.get(k) or 0) for k in ("hourly", "daily", "monthly"))
    except ValueError:
        return _after(srv, "Grenzwerte als ganze Zahlen angeben.", False)
    acc, robot = _client_for(srv)
    try:
        res = robot.set_traffic_warnings(ip, enabled, hourly, daily, monthly)
    except RobotError as exc:
        return _after(srv, f"Traffic-Warnungen nicht gespeichert: {exc}", False)
    audit(g.db, g.user, "hetzner.traffic_warnings", srv.name,
          f"{ip}: {'an' if enabled else 'aus'} {hourly} MB/h {daily} MB/Tag {monthly} GB/Monat", ip=client_ip())
    _update_ip(srv, ip, traffic_warnings=res.get("traffic_warnings", enabled),
               traffic_hourly=res.get("traffic_hourly", hourly), traffic_daily=res.get("traffic_daily", daily),
               traffic_monthly=res.get("traffic_monthly", monthly))
    g.db.commit()
    return _after(srv, f"Traffic-Warnungen für {ip} {'aktiviert' if enabled else 'deaktiviert'}.")
