"""Hetzner root servers (Robot webservice): status, IPs with reverse DNS, traffic, resets.

Rights: on the Robot account (all servers) or on single servers; Auswerten = view, Neustarten = operate,
Ändern = full. Accounts are added/edited by administrators only.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import date, datetime, timezone
from typing import Optional

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from sqlalchemy import func, select

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
    ctx = {}
    if g.user.is_admin:
        from ... import settings, sso_login
        conf = sso_login.active(g.db)
        ctx = {"group_rows": group_rows(), "group_targets": group_targets(), "tile": tile_state(),
               "sso_login": conf[0] if conf else None, "base_url": settings.base_url(g.db),
               "ak_groups": _ak_group_names(conf[0]) if conf else []}
    return render_template("hetzner/index.html", accounts=accounts, servers=servers, names=names, systems=systems,
                           levels={s.id: _level(s) for s in servers}, projects=projects, cloud=[c for c, _ in cloud],
                           cloud_levels={c.id: lv for c, lv in cloud}, pnames=pnames, **ctx)


def _ak_group_names(srv) -> list[str]:
    """Group names of authentik for the input suggestions (empty if authentik is not reachable)."""
    from ...authentik import AuthentikError
    try:
        return sorted({str(x.get("name") or "") for x in integrations.sso_client(srv, timeout=5).groups()} - {""},
                      key=str.lower)
    except (AuthentikError, ValueError):
        return []


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


# ------------------------------------------------------------------ access through authentik (administrators)
TILE_SLUG = "sm-hetzner"
TILE_SETTING = "hetzner.ak_tile"
GROUP_RE = re.compile(r"^[^\x00-\x1f]{1,150}$")


def group_targets() -> list[tuple[str, str, list[tuple[str, str]]]]:
    """(section, kind, [(value, label)]) of everything rights can be granted on."""
    from ...models import KIND_HCLOUD_SRV, HcloudServer
    acc = g.db.execute(select(HetznerAccount).order_by(HetznerAccount.name)).scalars().all()
    srv = g.db.execute(select(HetznerServer).order_by(HetznerServer.name)).scalars().all()
    prj = g.db.execute(select(HcloudProject).order_by(HcloudProject.name)).scalars().all()
    csv = g.db.execute(select(HcloudServer).order_by(HcloudServer.name)).scalars().all()
    return [("Robot-Konten (alle Root-Server)", KIND_HETZNER, [(f"{KIND_HETZNER}:{a.id}", a.name) for a in acc]),
            ("Root-Server", KIND_HETZNER_SRV, [(f"{KIND_HETZNER_SRV}:{s.id}", f"{s.name} (#{s.number})") for s in srv]),
            ("Cloud-Projekte (alle Cloud-Server)", KIND_HCLOUD, [(f"{KIND_HCLOUD}:{p.id}", p.name) for p in prj]),
            ("Cloud-Server", KIND_HCLOUD_SRV, [(f"{KIND_HCLOUD_SRV}:{c.id}", c.name) for c in csv])]


def group_rows() -> list[dict]:
    """Group rights on Hetzner objects (all groups, also those managed under Benutzer → Gruppen)."""
    from ...models import HETZNER_KINDS, GroupRight, UserGroup
    labels = {v: (section, label) for section, _k, items in group_targets() for v, label in items}
    alls = {k: section for section, k, _i in group_targets()}
    rows = []
    for r, grp in g.db.execute(select(GroupRight, UserGroup).join(UserGroup, UserGroup.id == GroupRight.group_id)
                               .where(GroupRight.kind.in_(HETZNER_KINDS))
                               .order_by(UserGroup.name, GroupRight.kind)).all():
        if r.obj_id == 0:
            section, label = alls.get(r.kind, ""), "alle"
        else:
            section, label = labels.get(f"{r.kind}:{r.obj_id}", ("", f"{r.kind} #{r.obj_id}"))
        rows.append({"id": r.id, "group": grp.name, "sso_group": grp.sso_group, "group_id": grp.id, "kind": r.kind,
                     "target": label, "section": section, "level": r.level})
    return rows


def tile_state() -> dict:
    from ... import settings
    return settings.get(g.db, TILE_SETTING) or {}


def _sync_tile(restrict: Optional[bool] = None) -> list[str]:
    """Create/update the tile in authentik; returns warnings. Raises AuthentikError/ValueError."""
    from ... import settings, sso_login
    from ...models import HETZNER_KINDS, GroupRight, UserGroup
    conf = sso_login.active(g.db)
    if conf is None:
        raise ValueError("Die Anmeldung am Servermanager über authentik ist nicht eingerichtet (SSO → Anwendungen "
                         "→ Anmeldung am Servermanager).")
    base = settings.base_url(g.db)
    if not base:
        raise ValueError("Zuerst unter Einstellungen → Allgemein die öffentliche URL des Servermanagers setzen.")
    srv, _client = conf
    state = tile_state()
    restrict = state.get("restrict", True) if restrict is None else restrict
    au = integrations.sso_client(srv)
    launch = f"{base}/login/sso?next=/hetzner/"
    app = au.upsert_link_app("Hetzner", TILE_SLUG, launch, "Root- und Cloud-Server im Servermanager",
                             "Servermanager")
    mapped = g.db.execute(select(UserGroup.name, UserGroup.sso_group).join(GroupRight, GroupRight.group_id == UserGroup.id)
                          .where(GroupRight.kind.in_(HETZNER_KINDS)).distinct()).all()
    groups = sorted({sso for _n, sso in mapped if sso}, key=str.lower)
    warnings = []
    local_only = sorted({n for n, sso in mapped if not sso})
    if restrict and local_only:
        warnings.append("Ohne authentik-Gruppe (sehen die Kachel nicht): " + ", ".join(local_only))
    if restrict:
        missing = au.set_app_groups(app, groups)
        if missing:
            warnings.append("In authentik unbekannte Gruppen: " + ", ".join(missing))
        if not groups:
            warnings.append("Noch keine Gruppe zugeordnet – die Kachel ist bis dahin für alle sichtbar.")
    else:
        au.set_app_groups(app, [])
    settings.set(g.db, TILE_SETTING, {"sso_id": srv.id, "slug": TILE_SLUG, "restrict": bool(restrict),
                                      "launch": launch, "at": integrations.utcnow().isoformat(timespec="minutes")})
    return warnings


def _after_group_change() -> None:
    """Keep the visibility of the tile in step with the groups (best effort)."""
    if not tile_state().get("restrict"):
        return
    try:
        for w in _sync_tile():
            flash(f"Kachel: {w}", "warning")
    except Exception as exc:  # noqa: BLE001 - the rights are saved either way
        flash(f"Kachel in authentik nicht aktualisiert: {exc}", "warning")


@bp.post("/groups")
@admin_required
def group_add():
    """Shortcut: rights of an authentik group on Hetzner objects (the group is created if needed)."""
    from ...integrations import ACCESS_MODELS
    from ...models import HETZNER_KINDS, KIND_LEVEL_LABELS, LEVEL_ORDER, GroupRight, UserGroup
    f = request.form
    name = (f.get("group") or "").strip()
    kind, _, raw = (f.get("target") or "").partition(":")
    level = f.get("level", "")
    if not GROUP_RE.match(name) or kind not in HETZNER_KINDS or not raw.isdigit() or level not in LEVEL_ORDER:
        flash("Gruppe, Ziel und Recht angeben.", "danger")
        return redirect(url_for("hetzner.index") + "#groups")
    obj = g.db.get(ACCESS_MODELS[kind], int(raw)) if int(raw) else None
    if int(raw) and obj is None:
        abort(404)
    grp = g.db.execute(select(UserGroup).where(func.lower(UserGroup.sso_group) == name.lower())).scalars().first() \
        or g.db.execute(select(UserGroup).where(func.lower(UserGroup.name) == name.lower())).scalars().first()
    if grp is None:
        grp = UserGroup(name=name[:128], sso_group=name, description="angelegt auf der Hetzner-Seite")
        g.db.add(grp)
        g.db.flush()
    row = g.db.execute(select(GroupRight).where(GroupRight.group_id == grp.id, GroupRight.kind == kind,
                                                GroupRight.obj_id == int(raw))).scalars().first()
    if row is None:
        g.db.add(GroupRight(group_id=grp.id, kind=kind, obj_id=int(raw), level=level))
    else:
        row.level = level
    label = KIND_LEVEL_LABELS[kind][level]
    target = obj.name if obj is not None else "alle"
    audit(g.db, g.user, "group.right", grp.name, f"{kind} {target}: {label}", ip=client_ip())
    g.db.commit()
    flash(f"Gruppe „{grp.name}“: {label} auf {target}.", "success")
    _after_group_change()
    g.db.commit()
    return redirect(url_for("hetzner.index") + "#groups")


@bp.post("/groups/<int:gid>/delete")
@admin_required
def group_delete(gid: int):
    from ...models import HETZNER_KINDS, GroupRight, UserGroup
    row = g.db.get(GroupRight, gid)
    if row is None or row.kind not in HETZNER_KINDS:
        abort(404)
    grp = g.db.get(UserGroup, row.group_id)
    audit(g.db, g.user, "group.right_remove", grp.name if grp else "?", f"{row.kind} {row.obj_id}", ip=client_ip())
    g.db.delete(row)
    g.db.commit()
    flash(f"Recht der Gruppe „{grp.name if grp else '?'}“ entfernt.", "warning")
    _after_group_change()
    g.db.commit()
    return redirect(url_for("hetzner.index") + "#groups")


@bp.post("/tile")
@admin_required
def tile():
    from ... import settings
    from ...authentik import AuthentikError
    if request.form.get("remove"):
        state = tile_state()
        try:
            from ...models import SsoServer
            srv = g.db.get(SsoServer, int(state.get("sso_id") or 0))
            if srv is not None:
                integrations.sso_client(srv).delete_app(state.get("slug") or TILE_SLUG)
        except (AuthentikError, ValueError) as exc:
            flash(f"Kachel in authentik nicht entfernt: {exc}", "danger")
            return redirect(url_for("hetzner.index") + "#groups")
        settings.set(g.db, TILE_SETTING, {})
        audit(g.db, g.user, "hetzner.tile_remove", "authentik", ip=client_ip())
        g.db.commit()
        flash("Kachel aus authentik entfernt.", "warning")
        return redirect(url_for("hetzner.index") + "#groups")
    try:
        warnings = _sync_tile(restrict=bool(request.form.get("restrict")))
    except (AuthentikError, ValueError) as exc:
        g.db.rollback()
        flash(f"Kachel nicht eingerichtet: {exc}", "danger")
        return redirect(url_for("hetzner.index") + "#groups")
    audit(g.db, g.user, "hetzner.tile", "authentik", tile_state().get("launch", ""), ip=client_ip())
    g.db.commit()
    flash("Kachel „Hetzner“ im authentik-Portal eingerichtet.", "success")
    for w in warnings:
        flash(f"Kachel: {w}", "warning")
    return redirect(url_for("hetzner.index") + "#groups")
