"""Pangolin: publish services from the internal network under a domain (via Newt sites)."""
from __future__ import annotations

import re

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from sqlalchemy import select

from ... import access, integrations, security
from ...core import audit
from ...models import (KIND_PANGOLIN, LEVEL_FULL, LEVEL_OPERATE, LEVEL_VIEW, PANGOLIN_ROLES, PangolinServer,
                       PveServer, System)
from ...pangolin import METHODS, ORG_RE, PROTOCOLS, SUBDOMAIN_RE, PangolinError
from ..auth import admin_required, client_ip, login_required
from . import _integration as common

bp = Blueprint("pangolin", __name__, url_prefix="/pangolin")


def _get(pg_id: int, level: str) -> PangolinServer:
    return common.get_or_403(KIND_PANGOLIN, pg_id, level)


def _client(pg: PangolinServer):
    try:
        return integrations.pangolin_client(pg)
    except (PangolinError, ValueError) as exc:
        abort(400, description=f"Pangolin-Verbindung unvollständig: {exc}")


@bp.get("/")
@login_required
def index():
    items = common.visible(KIND_PANGOLIN)
    if not items and not g.user.is_admin:
        abort(403)
    return render_template("pangolin/index.html", items=items)


def _save(pg: PangolinServer) -> list[str]:
    f = request.form
    errors = common.save_common(pg, f, 443)
    pg.org_id = (f.get("org_id") or "").strip()
    if not ORG_RE.match(pg.org_id):
        errors.append("Organisations-ID angeben (steht in der Pangolin-URL: /<org-id>/settings).")
    if f.get("api_key"):
        pg.api_key_enc = security.encrypt(f["api_key"].strip())
    elif not pg.api_key_enc:
        errors.append("API-Schlüssel angeben.")
    site = (f.get("default_site_id") or "").strip()
    pg.default_site_id = int(site) if site.isdigit() else None
    dom = (f.get("default_domain_id") or "").strip()
    pg.default_domain_id = dom if re.match(r"^[A-Za-z0-9_-]{0,64}$", dom) else ""
    pg.role = f.get("role") if f.get("role") in PANGOLIN_ROLES else "primary"
    tsys = (f.get("tunnel_system_id") or "").strip()
    pg.tunnel_system_id = int(tsys) if tsys.isdigit() and g.db.get(System, int(tsys)) else None
    return errors


def _form(pg: PangolinServer, is_new: bool):
    sites, domains = [], []
    if pg.id and pg.api_key_enc:
        try:
            client = integrations.pangolin_client(pg)
            sites, domains = client.sites(), client.domains()
        except integrations.ApiError:
            pass
    systems = g.db.execute(select(System).order_by(System.name)).scalars().all()
    return render_template("pangolin/form.html", p=pg, is_new=is_new, sites=sites, domains=domains,
                           roles=PANGOLIN_ROLES, systems=systems)


@bp.route("/new", methods=["GET", "POST"])
@admin_required
def new():
    pg = PangolinServer(monitor=True, verify_ca=True)
    if request.method == "POST":
        errors = _save(pg)
        if request.form.get("fetch_fp"):
            fp, err = common.fetch_fp_from_form(443)
            flash(err or "Fingerabdruck abgerufen.", "danger" if err else "info")
            pg.fingerprint = fp or pg.fingerprint
            return _form(pg, True)
        if errors:
            for e in errors:
                flash(e, "danger")
            return _form(pg, True)
        g.db.add(pg)
        g.db.flush()
        audit(g.db, g.user, "pangolin.create", pg.name, pg.api_url, ip=client_ip())
        integrations.poll(g.db, pg)
        g.db.commit()
        flash("Pangolin-Verbindung angelegt.", "success")
        return redirect(url_for("pangolin.detail", pg_id=pg.id))
    return _form(pg, True)


@bp.route("/<int:pg_id>/edit", methods=["GET", "POST"])
@admin_required
def edit(pg_id: int):
    pg = _get(pg_id, LEVEL_FULL)
    if request.method == "POST":
        if request.form.get("fetch_fp"):
            g.db.expunge(pg)
            _save(pg)
            fp, err = common.fetch_fp_from_form(443)
            flash(err or "Fingerabdruck abgerufen.", "danger" if err else "info")
            pg.fingerprint = fp or pg.fingerprint
            return _form(pg, False)
        errors = _save(pg)
        if errors:
            g.db.rollback()
            for e in errors:
                flash(e, "danger")
            return redirect(url_for("pangolin.edit", pg_id=pg_id))
        audit(g.db, g.user, "pangolin.update", pg.name, ip=client_ip())
        integrations.poll(g.db, pg)
        g.db.commit()
        flash("Gespeichert.", "success")
        return redirect(url_for("pangolin.detail", pg_id=pg.id))
    return _form(pg, False)


@bp.post("/<int:pg_id>/delete")
@admin_required
def delete(pg_id: int):
    pg = _get(pg_id, LEVEL_FULL)
    for srv in g.db.query(PveServer).filter(PveServer.pangolin_id == pg.id):
        srv.pangolin_id = None
    access.remove_integration(g.db, KIND_PANGOLIN, pg.id)
    audit(g.db, g.user, "pangolin.delete", pg.name, ip=client_ip())
    g.db.delete(pg)
    g.db.commit()
    flash("Pangolin-Verbindung entfernt (Ressourcen in Pangolin bleiben bestehen).", "warning")
    return redirect(url_for("pangolin.index"))


@bp.get("/<int:pg_id>")
@login_required
def detail(pg_id: int):
    pg = _get(pg_id, LEVEL_VIEW)
    ctx: dict = {"p": pg, "sites": [], "resources": [], "domains": {}, "error": None}
    try:
        client = _client(pg)
        ctx["sites"] = client.sites()
        ctx["resources"] = sorted(client.resources(), key=lambda r: (r.get("fullDomain") or r.get("name") or ""))
        ctx["domains"] = {d.get("domainId"): d.get("baseDomain") for d in client.domains()}
    except integrations.ApiError as exc:
        ctx["error"] = str(exc)
    integrations.poll(g.db, pg)
    g.db.commit()
    ctx["tunnel"] = g.db.get(System, pg.tunnel_system_id) if pg.tunnel_system_id else None
    return render_template("pangolin/detail.html", **ctx)


@bp.get("/<int:pg_id>/resource/<int:rid>")
@login_required
def resource(pg_id: int, rid: int):
    pg = _get(pg_id, LEVEL_VIEW)
    client = _client(pg)
    try:
        res = client.resource(rid)
        targets = client.targets(rid)
    except PangolinError as exc:
        if exc.status == 404:
            abort(404)
        flash(str(exc), "danger")
        return redirect(url_for("pangolin.detail", pg_id=pg_id))
    ips = {t.get("ip") for t in targets}
    systems = [s for s in g.db.query(System).filter(System.host.in_(ips)).all()
               if access.system_level(g.db, g.user, s.id)] if ips else []
    return render_template("pangolin/resource.html", p=pg, res=res, targets=targets, systems=systems)


@bp.post("/<int:pg_id>/resource/<int:rid>/do")
@login_required
def resource_do(pg_id: int, rid: int):
    action = request.form.get("action", "")
    levels = {"toggle": LEVEL_OPERATE, "sso": LEVEL_FULL, "delete": LEVEL_FULL, "add_target": LEVEL_FULL,
              "delete_target": LEVEL_FULL}
    if action not in levels:
        abort(400)
    pg = _get(pg_id, levels[action])
    client = _client(pg)
    try:
        if action == "toggle":
            enabled = request.form.get("enabled") == "1"
            client.update_resource(rid, enabled=enabled)
            msg = "Dienst aktiviert." if enabled else "Dienst deaktiviert (nicht mehr erreichbar)."
        elif action == "sso":
            sso = request.form.get("sso") == "1"
            client.update_resource(rid, sso=sso)
            msg = "Pangolin-Anmeldung aktiviert." if sso else "Pangolin-Anmeldung deaktiviert – der Dienst ist öffentlich."
        elif action == "delete":
            client.delete_resource(rid)
            msg = "Veröffentlichung entfernt."
        elif action == "add_target":
            site = int(request.form.get("site_id") or 0)
            method = request.form.get("method") or None
            if method not in (None, "http", "https"):
                raise PangolinError("Ungültiges Protokoll")
            client.add_target(rid, request.form.get("ip", ""), request.form.get("port", ""), method, site)
            msg = "Ziel hinzugefügt."
        else:
            tid = request.form.get("target_id", "")
            if not tid.isdigit():
                abort(400)
            client.delete_target(int(tid))
            msg = "Ziel entfernt."
        audit(g.db, g.user, f"pangolin.{action}", pg.name, f"resource {rid}", ip=client_ip())
        g.db.commit()
        flash(msg, "success")
    except (PangolinError, ValueError) as exc:
        flash(f"Fehlgeschlagen: {exc}", "danger")
    if action == "delete":
        return redirect(url_for("pangolin.detail", pg_id=pg_id))
    return redirect(url_for("pangolin.resource", pg_id=pg_id, rid=rid))


@bp.route("/<int:pg_id>/publish", methods=["GET", "POST"])
@login_required
def publish(pg_id: int):
    pg = _get(pg_id, LEVEL_FULL)
    client = _client(pg)
    f = request.form if request.method == "POST" else request.args
    if request.method == "POST":
        try:
            name = (f.get("name") or "").strip()[:100]
            if not name:
                raise PangolinError("Namen angeben")
            protocol = f.get("protocol", "http")
            if protocol not in PROTOCOLS:
                raise PangolinError("Ungültiges Protokoll")
            sub = (f.get("subdomain") or "").strip().lower()
            if sub and not SUBDOMAIN_RE.match(sub):
                raise PangolinError("Ungültige Subdomain")
            method = f.get("method", "http")
            if method not in METHODS:
                raise PangolinError("Ungültiges Ziel-Protokoll")
            site = int(f.get("site_id") or 0)
            proxy_port = int(f.get("proxy_port") or 0) or None
            res = client.publish(name, protocol, site, f.get("ip", ""), f.get("port", ""), method, sub,
                                 f.get("domain_id", ""), proxy_port, sso=bool(f.get("sso")))
            label = res.get("fullDomain") or (f"Port {proxy_port}" if proxy_port else name)
            audit(g.db, g.user, "pangolin.publish", pg.name, f"{label} -> {f.get('ip')}:{f.get('port')}",
                  ip=client_ip())
            g.db.commit()
            flash(f"Veröffentlicht: {label}", "success")
            if res.get("resourceId"):
                return redirect(url_for("pangolin.resource", pg_id=pg_id, rid=res["resourceId"]))
            return redirect(url_for("pangolin.detail", pg_id=pg_id))
        except (PangolinError, ValueError) as exc:
            flash(f"Veröffentlichen fehlgeschlagen: {exc}", "danger")
    try:
        sites, domains = client.sites(), client.domains()
    except PangolinError as exc:
        flash(str(exc), "danger")
        sites, domains = [], []
    return render_template("pangolin/publish.html", p=pg, f=f, sites=sites, domains=domains, methods=METHODS,
                           protocols=PROTOCOLS)


# --------------------------------------------------------------------------
# tunnel container (Newt)
# --------------------------------------------------------------------------
@bp.route("/<int:pg_id>/tunnel", methods=["GET", "POST"])
@login_required
def tunnel(pg_id: int):
    from ... import pve as pvemod
    from ...jobs import enqueue
    from ..auth import can
    pg = _get(pg_id, LEVEL_FULL)
    systems = [s for s in g.db.execute(select(System).order_by(System.name)).scalars() if can(s.id, "full")]
    if request.method == "POST":
        sid = request.form.get("system_id", "")
        system = g.db.get(System, int(sid)) if sid.isdigit() else None
        if system is None or not can(system.id, "full"):
            abort(403)
        try:
            newt = pvemod.clean_newt(request.form)
        except pvemod.PveParamError as exc:
            flash(str(exc), "danger")
            return render_template("pangolin/tunnel.html", p=pg, systems=systems, f=request.form)
        job = enqueue(g.db, kind="newt_setup", title=f"Newt für {pg.name} auf {system.name} einrichten", system=system,
                      user=g.user, payload={"pangolin_id": pg.id, "newt": newt})
        audit(g.db, g.user, "newt.setup_start", pg.name, system.name, ip=client_ip())
        g.db.commit()
        return redirect(url_for("jobs.detail", job_id=job.id))
    return render_template("pangolin/tunnel.html", p=pg, systems=systems, f={})


# --------------------------------------------------------------------------
# all publications with primary and backup path
# --------------------------------------------------------------------------
@bp.get("/services")
@login_required
def services():
    from ... import discovery
    visible = common.visible(KIND_PANGOLIN)
    if not visible:
        abort(403)
    data = discovery.services_map(g.db, visible)
    backups = [p for p in visible if p.role == "backup"]
    return render_template("pangolin/services.html", data=data, pangolins=visible, backups=backups)


@bp.post("/services/mirror")
@login_required
def mirror():
    """Publish a target also through the backup Pangolin (same subdomain, backup's default domain/site)."""
    pg = _get(int(request.form.get("pangolin_id", "0") or 0), LEVEL_FULL)
    client = _client(pg)
    f = request.form
    try:
        if not pg.default_site_id or (f.get("protocol") == "http" and not pg.default_domain_id):
            raise PangolinError(f"Für {pg.name} zuerst Standard-Site und -Domain festlegen")
        proxy = int(f.get("proxy_port") or 0) or None
        res = client.publish(f.get("name", "")[:100] or "dienst", f.get("protocol", "http"), pg.default_site_id,
                             f.get("ip", ""), f.get("port", ""), f.get("method") or "http",
                             (f.get("subdomain") or "").lower(), pg.default_domain_id, proxy,
                             sso=bool(f.get("sso")))
        audit(g.db, g.user, "pangolin.mirror", pg.name, f"{f.get('ip')}:{f.get('port')}", ip=client_ip())
        g.db.commit()
        flash(f"Backup-Weg angelegt: {res.get('fullDomain') or res.get('name')}", "success")
    except (PangolinError, ValueError) as exc:
        flash(f"Backup-Weg nicht angelegt: {exc}", "danger")
    return redirect(url_for("pangolin.services"))
