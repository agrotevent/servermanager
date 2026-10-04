"""Hetzner Cloud servers: status, IPs with reverse DNS, traffic, metrics, power actions.

Rights on the Cloud project (all servers) or on single servers; Auswerten = view, Neustarten = operate
(all power actions), Ändern = full (PTR, name). Projects are added/edited by administrators only.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from sqlalchemy import select

from ... import access, hcloud, integrations, security
from ...core import audit
from ...hcloud import METRIC_STEPS, POWER_ACTIONS, STATUS_LABELS, CloudError
from ...hetzner import RobotError
from ...models import KIND_HCLOUD, KIND_HCLOUD_SRV, LEVEL_FULL, LEVEL_OPERATE, LEVEL_VIEW, HcloudProject, HcloudServer, System
from ..auth import admin_required, client_ip, login_required, rate_ok
from ..charts import fmt_pct, fmt_rate, line_chart
from . import _integration as common

bp = Blueprint("hcloud", __name__, url_prefix="/hetzner/cloud")


def visible_servers() -> list[tuple[HcloudServer, str]]:
    rows = g.db.execute(select(HcloudServer).order_by(HcloudServer.name)).scalars().all()
    out = []
    for s in rows:
        lv = access.hcloud_server_level(g.db, g.user, s)
        if lv:
            out.append((s, lv))
    return out


def _project(pid: int, level: str) -> HcloudProject:
    return common.get_or_403(KIND_HCLOUD, pid, level)


def _server(sid: int, level: str) -> HcloudServer:
    srv = g.db.get(HcloudServer, sid)
    if srv is None:
        abort(404)
    if not access.has_hcloud_level(g.db, g.user, srv, level):
        abort(403)
    return srv


# ------------------------------------------------------------------ projects (administrators)
def _save(p: HcloudProject) -> list[str]:
    f = request.form
    errors = []
    p.name = (f.get("name") or "").strip()[:128]
    if not p.name:
        errors.append("Bitte einen Namen angeben.")
    p.description = (f.get("description") or "").strip()[:2000]
    if f.get("token"):
        p.token_enc = security.encrypt(f["token"].strip())
    elif not p.token_enc:
        errors.append("API-Token angeben (Cloud Console → Projekt → Sicherheit → API-Tokens).")
    try:
        p.traffic_alert_pct = max(0, min(100, int(f.get("traffic_alert_pct") or 0)))
    except ValueError:
        errors.append("Traffic-Warnung in Prozent angeben.")
    p.monitor = bool(f.get("monitor"))
    p.api_url = p.api_url or hcloud.API_URL
    return errors


def _form(p: HcloudProject, is_new: bool):
    return render_template("hetzner/cloud_form.html", p=p, is_new=is_new)


@bp.route("/new", methods=["GET", "POST"])
@admin_required
def new():
    p = HcloudProject(monitor=True, traffic_alert_pct=90, api_url=hcloud.API_URL)
    if request.method == "POST":
        errors = _save(p)
        if errors:
            for e in errors:
                flash(e, "danger")
            return _form(p, True)
        g.db.add(p)
        g.db.flush()
        audit(g.db, g.user, "hcloud.create", p.name, ip=client_ip())
        integrations.poll(g.db, p)
        g.db.commit()
        if p.status_message:
            flash(f"Gespeichert, aber: {p.status_message}", "warning")
        else:
            flash(f"Cloud-Projekt angebunden: {p.data.get('servers', 0)} Server gefunden.", "success")
        return redirect(url_for("hetzner.index"))
    return _form(p, True)


@bp.route("/project/<int:pid>/edit", methods=["GET", "POST"])
@admin_required
def edit(pid: int):
    p = _project(pid, LEVEL_FULL)
    if request.method == "POST":
        errors = _save(p)
        if errors:
            g.db.rollback()
            for e in errors:
                flash(e, "danger")
            return redirect(url_for("hcloud.edit", pid=pid))
        audit(g.db, g.user, "hcloud.update", p.name, ip=client_ip())
        integrations.poll(g.db, p)
        g.db.commit()
        flash("Gespeichert.", "success")
        return redirect(url_for("hetzner.index"))
    return _form(p, False)


@bp.post("/project/<int:pid>/delete")
@admin_required
def delete(pid: int):
    p = _project(pid, LEVEL_FULL)
    for srv in g.db.execute(select(HcloudServer).where(HcloudServer.project_id == p.id)).scalars():
        access.remove_integration(g.db, KIND_HCLOUD_SRV, srv.id)
    access.remove_integration(g.db, KIND_HCLOUD, p.id)
    audit(g.db, g.user, "hcloud.delete", p.name, ip=client_ip())
    g.db.delete(p)
    g.db.commit()
    flash("Cloud-Projekt entfernt (die Server in der Hetzner Cloud bleiben unverändert).", "warning")
    return redirect(url_for("hetzner.index"))


@bp.post("/project/<int:pid>/refresh")
@login_required
def refresh(pid: int):
    p = _project(pid, LEVEL_OPERATE)
    integrations.poll(g.db, p)
    g.db.commit()
    flash(p.status_message or "Aktualisiert.", "danger" if p.status_message else "success")
    return redirect(url_for("hetzner.index"))


# ------------------------------------------------------------------ server
def _charts(ts: dict, tz=timezone.utc) -> list[dict]:
    rows: dict[float, dict] = {}
    for name, key in (("cpu", "cpu"), ("network.0.bandwidth.in", "net_in"), ("network.0.bandwidth.out", "net_out")):
        for t, v in hcloud.series(ts, name):
            rows.setdefault(t, {"time": t})[key] = v
    rows_l = list(rows.values())
    out = []
    cpu = line_chart(rows_l, [("CPU", "s1", lambda r: r.get("cpu"))], fmt_pct, timeframe="day", tz=tz)
    if cpu:
        cpu["title"] = "CPU-Auslastung"
        out.append(cpu)
    net = line_chart(rows_l, [("Eingehend", "s1", lambda r: r.get("net_in")),
                              ("Ausgehend", "s2", lambda r: r.get("net_out"))], fmt_rate, timeframe="day", tz=tz)
    if net:
        net["title"] = "Netzwerk (öffentlich)"
        out.append(net)
    return out


@bp.get("/server/<int:sid>")
@login_required
def server(sid: int):
    srv = _server(sid, LEVEL_VIEW)
    proj = g.db.get(HcloudProject, srv.project_id)
    rng = request.args.get("range", "24h")
    if rng not in METRIC_STEPS:
        rng = "24h"
    charts, error = [], ""
    if rate_ok(f"hcloud-metrics:{g.user.id}", 30):
        span, step = METRIC_STEPS[rng]
        end = datetime.now(timezone.utc).replace(microsecond=0)
        start = end - timedelta(seconds=span)
        try:
            ts = integrations.hcloud_client(proj).metrics(srv.cloud_id, "cpu,network", start.isoformat(),
                                                          end.isoformat(), step)
            from ...schedules import get_tz
            charts = _charts(ts, get_tz(g.db))
        except (CloudError, RobotError) as exc:
            error = str(exc)
    else:
        error = "Zu viele Abfragen – bitte eine Minute warten."
    level = access.hcloud_server_level(g.db, g.user, srv) or ""
    system = g.db.get(System, srv.system_id) if srv.system_id else None
    if system is not None and not (g.user.is_admin or access.system_level(g.db, g.user, system.id)):
        system = None
    return render_template("hetzner/cloud_server.html", srv=srv, proj=proj, info=srv.info,
                           s=srv.info.get("server") or {}, level=level, charts=charts, error=error, rng=rng,
                           power_actions=POWER_ACTIONS, status_labels=STATUS_LABELS, system=system)


def _client(srv: HcloudServer):
    proj = g.db.get(HcloudProject, srv.project_id)
    try:
        return integrations.hcloud_client(proj)
    except CloudError as exc:
        abort(400, description=str(exc))


def _after(srv: HcloudServer, msg: str, ok: bool = True):
    flash(msg, "success" if ok else "danger")
    return redirect(url_for("hcloud.server", sid=srv.id))


@bp.post("/server/<int:sid>/power")
@login_required
def power(sid: int):
    action = request.form.get("action", "")
    if action not in POWER_ACTIONS:
        abort(400)
    srv = _server(sid, LEVEL_OPERATE)
    try:
        _client(srv).power(srv.cloud_id, action)
    except CloudError as exc:
        audit(g.db, g.user, "hcloud.power_failed", srv.name, f"{action}: {exc}", ip=client_ip())
        g.db.commit()
        return _after(srv, f"{POWER_ACTIONS[action]} fehlgeschlagen: {exc}", False)
    audit(g.db, g.user, "hcloud.power", srv.name, f"#{srv.cloud_id} {action}", ip=client_ip())
    g.db.commit()
    return _after(srv, f"{POWER_ACTIONS[action]} für {srv.name} ausgelöst – der Status wird beim nächsten "
                       "Aktualisieren übernommen.")


@bp.post("/server/<int:sid>/rename")
@login_required
def rename(sid: int):
    srv = _server(sid, LEVEL_FULL)
    name = (request.form.get("name") or "").strip()
    try:
        _client(srv).rename(srv.cloud_id, name)
    except CloudError as exc:
        return _after(srv, f"Umbenennen fehlgeschlagen: {exc}", False)
    audit(g.db, g.user, "hcloud.rename", srv.name, f"#{srv.cloud_id} → {name}", ip=client_ip())
    srv.name = name
    g.db.commit()
    return _after(srv, "Servername geändert.")


@bp.post("/server/<int:sid>/ptr")
@login_required
def ptr(sid: int):
    srv = _server(sid, LEVEL_FULL)
    try:
        ip = str(ipaddress.ip_address((request.form.get("ip") or "").strip()))
    except ValueError:
        abort(400, description="Ungültige IP-Adresse")
    owner = hcloud.owner_of(ip, srv.info.get("server") or {}, srv.info.get("floating") or [])
    if owner is None:
        abort(400, description="Die Adresse gehört nicht zu diesem Server")
    value = (request.form.get("ptr") or "").strip()
    try:
        _client(srv).set_ptr(ip, value, server_id=srv.cloud_id, floating_id=owner)
    except (CloudError, RobotError) as exc:
        return _after(srv, f"PTR-Eintrag nicht gesetzt: {exc}", False)
    value = value.rstrip(".").lower()
    audit(g.db, g.user, "hcloud.ptr", srv.name, f"{ip} → {value or '(Standard)'}", ip=client_ip())
    info = dict(srv.info)
    rows = [dict(r) for r in info.get("ips") or []]
    row = next((r for r in rows if r["ip"] == ip), None)
    if row is None:
        rows.append({"ip": ip, "ptr": value, "kind": "floating" if owner else "primary", "floating_id": owner})
    else:
        row["ptr"] = value
    info["ips"] = rows
    srv.data = info
    g.db.commit()
    return _after(srv, f"PTR für {ip} {'gesetzt: ' + value if value else 'auf den Standard zurückgesetzt'}.")
