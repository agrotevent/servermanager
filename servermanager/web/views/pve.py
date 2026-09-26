"""Proxmox VE via API: servers, guests (LXC/VM), monitoring, LXC creation."""
from __future__ import annotations

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from sqlalchemy import select

from ... import access, integrations, pve, security, sshkeys
from ...core import audit
from ...jobs import enqueue
from ...models import (KIND_PANGOLIN, KIND_PVE, LEVEL_FULL, PVE_HOSTING, LEVEL_OPERATE, LEVEL_VIEW, Job,
                       PangolinServer, PveServer, RouterDevice, System)
from ...pveapi import TOKEN_ID_RE, PveError
from ...schedules import get_tz
from .. import charts
from ..auth import admin_required, client_ip, get_system_or_403, login_required
from . import _integration as common

bp = Blueprint("pve", __name__, url_prefix="/proxmox")


def _get(pve_id: int, level: str) -> PveServer:
    return common.get_or_403(KIND_PVE, pve_id, level)


def _api(server: PveServer, timeout: int = 15):
    try:
        return pve.client(server, timeout=timeout)
    except (PveError, ValueError) as exc:
        abort(400, description=f"Proxmox-Verbindung unvollständig: {exc}")


# --------------------------------------------------------------------------
# list / server CRUD
# --------------------------------------------------------------------------
@bp.get("/")
@login_required
def index():
    servers = common.visible(KIND_PVE)
    if not servers and not g.user.is_admin:
        abort(403)
    return render_template("pve/index.html", servers=servers)


def _form_ctx(server: PveServer) -> dict:
    return {
        "s": server,
        "pve_systems": g.db.execute(select(System).order_by(System.name)).scalars().all(),
        "routers": g.db.execute(select(RouterDevice).order_by(RouterDevice.name)).scalars().all(),
        "pangolins": g.db.execute(select(PangolinServer).order_by(PangolinServer.name)).scalars().all(),
        "hostings": PVE_HOSTING,
    }


def _save(server: PveServer) -> list[str]:
    f = request.form
    errors = common.save_common(server, f, 8006)
    if server.api_url and not server.api_url.startswith("https://"):
        errors.append("Die Proxmox-API ist nur per https erreichbar.")
    token_id = (f.get("token_id") or "").strip()
    if token_id and not TOKEN_ID_RE.match(token_id):
        errors.append("Token-ID im Format benutzer@realm!tokenname angeben (z. B. servermanager@pve!sm).")
    server.token_id = token_id
    if f.get("token_secret"):
        server.token_secret_enc = security.encrypt(f["token_secret"].strip())
    server.hosting = f.get("hosting") if f.get("hosting") in PVE_HOSTING else "local"
    vlan = (f.get("vswitch_vlan") or "").strip()
    if vlan and (not vlan.isdigit() or not 4000 <= int(vlan) <= 4091):
        errors.append("vSwitch-VLAN: Hetzner vergibt IDs von 4000 bis 4091.")
    server.vswitch_vlan = int(vlan) if vlan.isdigit() else None
    for attr, model, key in (("system_id", System, "system_id"), ("router_id", RouterDevice, "router_id"),
                             ("pangolin_id", PangolinServer, "pangolin_id")):
        raw = f.get(key, "")
        setattr(server, attr, int(raw) if raw.isdigit() and g.db.get(model, int(raw)) else None)
    return errors


@bp.route("/new", methods=["GET", "POST"])
@admin_required
def new():
    server = PveServer(monitor=True, verify_ca=False)
    if request.method == "POST":
        if request.form.get("fetch_fp"):
            return _fetch_fp(server)
        errors = _save(server)
        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("pve/form.html", is_new=True, **_form_ctx(server))
        g.db.add(server)
        g.db.flush()
        audit(g.db, g.user, "pve.create", server.name, server.api_url, ip=client_ip())
        if server.token_id and server.token_secret_enc:
            integrations.poll(g.db, server)
        g.db.commit()
        flash("Proxmox-Verbindung angelegt.", "success")
        return redirect(url_for("pve.server", pve_id=server.id))
    return render_template("pve/form.html", is_new=True, **_form_ctx(server))


def _fetch_fp(server: PveServer):
    _save(server)
    fp, err = common.fetch_fp_from_form(8006)
    if err:
        flash(err, "danger")
    else:
        server.fingerprint = fp
        flash("Fingerabdruck abgerufen – bitte mit dem auf dem Proxmox-Host angezeigten Wert vergleichen "
              "(Datacenter → Node → System → Zertifikate) und dann speichern.", "info")
    return render_template("pve/form.html", is_new=server.id is None, **_form_ctx(server))


@bp.route("/<int:pve_id>/edit", methods=["GET", "POST"])
@admin_required
def edit(pve_id: int):
    server = _get(pve_id, LEVEL_FULL)
    if request.method == "POST":
        if request.form.get("fetch_fp"):
            g.db.expunge(server)
            return _fetch_fp(server)
        errors = _save(server)
        if errors:
            g.db.rollback()
            for e in errors:
                flash(e, "danger")
            return redirect(url_for("pve.edit", pve_id=pve_id))
        audit(g.db, g.user, "pve.update", server.name, ip=client_ip())
        integrations.poll(g.db, server)
        g.db.commit()
        flash("Gespeichert.", "success")
        return redirect(url_for("pve.server", pve_id=server.id))
    return render_template("pve/form.html", is_new=False, **_form_ctx(server))


@bp.post("/<int:pve_id>/delete")
@admin_required
def delete(pve_id: int):
    server = _get(pve_id, LEVEL_FULL)
    for s in g.db.execute(select(System).where(System.pve_server_id == server.id)).scalars():
        s.pve_server_id = None
        s.pve_vmid = None
    access.remove_integration(g.db, KIND_PVE, server.id)
    audit(g.db, g.user, "pve.delete", server.name, ip=client_ip())
    g.db.delete(server)
    g.db.commit()
    flash("Proxmox-Verbindung entfernt (die Gäste auf dem Proxmox bleiben unverändert).", "warning")
    return redirect(url_for("pve.index"))


@bp.post("/<int:pve_id>/token-setup")
@admin_required
def token_setup(pve_id: int):
    server = _get(pve_id, LEVEL_FULL)
    system = g.db.get(System, server.system_id) if server.system_id else None
    if system is None:
        flash("Dafür muss der Proxmox-Host als System (SSH) verknüpft sein.", "danger")
        return redirect(url_for("pve.edit", pve_id=pve_id))
    role = request.form.get("role", "PVEAdmin")
    job = enqueue(g.db, kind="pve_token", title=f"API-Token auf {system.name} einrichten", system=system,
                  user=g.user, payload={"role": role}, pve_id=server.id)
    audit(g.db, g.user, "pve.token_setup", server.name, system.name, ip=client_ip())
    g.db.commit()
    return redirect(url_for("jobs.detail", job_id=job.id))


@bp.post("/<int:pve_id>/mgmt-login")
@admin_required
def mgmt_login(pve_id: int):
    """Create the API token with a one-time administrator login (the password is not stored)."""
    from ... import mgmt
    server = _get(pve_id, LEVEL_FULL)
    f = request.form
    try:
        token_id = mgmt.pve_token_via_login(server, f.get("username", "").strip(), f.get("password", ""),
                                            f.get("otp", "").strip(), f.get("role", "PVEAdmin"))
    except mgmt.MgmtError as exc:
        g.db.rollback()
        flash(f"Token konnte nicht angelegt werden: {exc}", "danger")
        return redirect(url_for("pve.edit", pve_id=pve_id))
    audit(g.db, g.user, "pve.token_login", server.name, token_id, ip=client_ip())
    integrations.poll(g.db, server)
    g.db.commit()
    flash(f"API-Token {token_id} angelegt und gespeichert. Das Admin-Passwort wurde nicht gespeichert.", "success")
    return redirect(url_for("pve.server", pve_id=pve_id))


@bp.route("/<int:pve_id>/import", methods=["GET", "POST"])
@login_required
def import_guests(pve_id: int):
    """Existing guests: create management access and register them as systems."""
    from ... import discovery
    server = _get(pve_id, LEVEL_FULL)
    if not g.user.can_add_systems:
        abort(403)
    if request.method == "POST":
        keys = set(request.form.getlist("guest"))
        inv = {f"{x['node']}/{x['type']}/{x['vmid']}": x for x in server.data.get("guests", [])}
        items = []
        for k in keys:
            x = inv.get(k)
            if x is None:
                continue
            items.append({"node": x["node"], "type": x["type"], "vmid": x["vmid"], "name": x["name"],
                          "ip": request.form.get(f"ip_{x['vmid']}", "").strip()})
        if not items:
            flash("Keine Gäste ausgewählt.", "warning")
            return redirect(url_for("pve.import_guests", pve_id=pve_id))
        job = enqueue(g.db, kind="pve_import", title=f"Bestand übernehmen: {len(items)} Gast/Gäste – {server.name}",
                      user=g.user, pve_id=server.id,
                      payload={"items": items, "install_ssh": bool(request.form.get("install_ssh"))})
        audit(g.db, g.user, "pve.import_start", server.name, ",".join(str(i["vmid"]) for i in items), ip=client_ip())
        g.db.commit()
        return redirect(url_for("jobs.detail", job_id=job.id))
    error = None
    rows = []
    try:
        rows = discovery.pve_inventory(g.db, server)
    except (PveError, ValueError) as exc:
        error = str(exc)
    return render_template("pve/import.html", s=server, rows=rows, error=error)


@bp.post("/<int:pve_id>/refresh")
@login_required
def refresh(pve_id: int):
    server = _get(pve_id, LEVEL_VIEW)
    integrations.poll(g.db, server)
    g.db.commit()
    if server.status_message:
        flash(server.status_message, "danger")
    return redirect(common.safe_next(url_for("pve.server", pve_id=pve_id)))


# --------------------------------------------------------------------------
# server overview
# --------------------------------------------------------------------------
@bp.get("/<int:pve_id>")
@login_required
def server(pve_id: int):
    server = _get(pve_id, LEVEL_VIEW)
    tab = request.args.get("tab", "lxc")
    if request.args.get("live") != "0" and server.token_id:
        integrations.poll(g.db, server)
        g.db.commit()
    jobs = g.db.execute(select(Job).where(Job.pve_id == server.id).order_by(Job.id.desc()).limit(30)).scalars().all()
    linked = {s.pve_vmid: s for s in g.db.execute(select(System).where(System.pve_server_id == server.id)).scalars()}
    return render_template("pve/server.html", s=server, data=server.data, tab=tab, jobs=jobs, linked=linked,
                           ops=pve.OPS)


# --------------------------------------------------------------------------
# guests
# --------------------------------------------------------------------------
def _guest_ref(node: str, gtype: str, vmid: int):
    try:
        return pve.check_guest_ref(node, gtype, vmid)
    except pve.PveParamError:
        abort(404)


@bp.get("/<int:pve_id>/guest/<node>/<gtype>/<int:vmid>")
@login_required
def guest(pve_id: int, node: str, gtype: str, vmid: int):
    server = _get(pve_id, LEVEL_VIEW)
    node, gtype, vmid = _guest_ref(node, gtype, vmid)
    tf = request.args.get("tf", "hour")
    if tf not in pve.TIMEFRAMES:
        tf = "hour"
    api = _api(server)
    ctx: dict = {"s": server, "node": node, "gtype": gtype, "vmid": vmid, "tf": tf, "error": None,
                 "timeframes": pve.TIMEFRAMES, "ops": pve.OPS}
    try:
        ctx["status"] = api.guest_status(node, gtype, vmid)
        ctx["config"] = api.guest_config(node, gtype, vmid)
        ctx["snapshots"] = sorted(api.snapshots(node, gtype, vmid), key=lambda x: x.get("snaptime") or 0,
                                  reverse=True)
        ctx["charts"] = charts.rrd_charts(api.guest_rrd(node, gtype, vmid, tf), tf, gtype, get_tz(g.db))
        ctx["backup_storages"] = [st["storage"] for st in api.storages(node, "backup")]
        ctx["ip"] = ""
        if gtype == "lxc" and ctx["status"].get("status") == "running":
            try:
                ctx["ip"] = pve.container_ipv4(api, node, vmid)
            except PveError:
                pass
    except PveError as exc:
        if exc.status == 404 or "does not exist" in str(exc):
            abort(404, description="Gast existiert nicht (mehr) auf diesem Node.")
        ctx["error"] = str(exc)
    ctx["system"] = g.db.execute(select(System).where(System.pve_server_id == server.id,
                                                      System.pve_vmid == vmid)).scalar_one_or_none()
    ctx["jobs"] = [j for j in g.db.execute(select(Job).where(Job.pve_id == server.id).order_by(Job.id.desc())
                                           .limit(200)).scalars()
                   if int((j.payload or {}).get("vmid", 0) or 0) == vmid][:15]
    ctx["pangolin"] = g.db.get(PangolinServer, server.pangolin_id) if server.pangolin_id else None
    return render_template("pve/guest.html", **ctx)


def _enqueue_op(server: PveServer, node: str, gtype: str, vmid: int, op: str, params: dict,
                system: System | None = None) -> Job:
    name = request.form.get("name", "")[:64]
    label = pve.OPS[op]["label"]
    title = f"{label}: {'CT' if gtype == 'lxc' else 'VM'} {vmid}{f' ({name})' if name else ''} – {server.name}"
    return enqueue(g.db, kind="pve", title=title, system=system, user=g.user, pve_id=server.id,
                   payload={"op": op, "node": node, "type": gtype, "vmid": vmid, "params": params})


@bp.post("/<int:pve_id>/guest/<node>/<gtype>/<int:vmid>/op")
@login_required
def guest_op(pve_id: int, node: str, gtype: str, vmid: int):
    op = request.form.get("op", "")
    if op not in pve.OPS or op == "download":
        abort(400)
    server = _get(pve_id, pve.OPS[op]["level"])
    node, gtype, vmid = _guest_ref(node, gtype, vmid)
    if not pve.op_allowed(op, gtype):
        abort(400)
    try:
        params = pve.clean_op_params(op, request.form)
    except pve.PveParamError as exc:
        flash(str(exc), "danger")
        return redirect(common.safe_next(url_for("pve.guest", pve_id=pve_id, node=node, gtype=gtype, vmid=vmid)))
    if op == "destroy" and request.form.get("confirm_vmid", "") != str(vmid):
        flash("Zum Löschen die VMID zur Bestätigung eingeben.", "danger")
        return redirect(url_for("pve.guest", pve_id=pve_id, node=node, gtype=gtype, vmid=vmid))
    job = _enqueue_op(server, node, gtype, vmid, op, params)
    audit(g.db, g.user, f"pve.{op}", f"{server.name}/{vmid}", str(params)[:200], ip=client_ip())
    g.db.commit()
    if request.form.get("stay"):
        flash(f"{pve.OPS[op]['label']} gestartet (Job #{job.id}).", "info")
        return redirect(common.safe_next(url_for("pve.server", pve_id=pve_id)))
    return redirect(url_for("jobs.detail", job_id=job.id))


@bp.post("/<int:pve_id>/guest/<node>/lxc/<int:vmid>/config")
@login_required
def guest_config(pve_id: int, node: str, vmid: int):
    server = _get(pve_id, LEVEL_FULL)
    node, _t, vmid = _guest_ref(node, "lxc", vmid)
    f = request.form
    try:
        params = {
            "cores": pve._int(f, "cores", 1, 512, "CPU-Kerne"),
            "memory": pve._int(f, "memory", 16, 4 * 1024 * 1024, "RAM (MB)"),
            "swap": pve._int(f, "swap", 0, 4 * 1024 * 1024, "Swap (MB)"),
            "onboot": bool(f.get("onboot")),
            "description": (f.get("description") or "")[:2000],
        }
    except pve.PveParamError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("pve.guest", pve_id=pve_id, node=node, gtype="lxc", vmid=vmid))
    try:
        _api(server).put(f"nodes/{node}/lxc/{vmid}/config", **params)
        audit(g.db, g.user, "pve.config", f"{server.name}/{vmid}", str(params)[:300], ip=client_ip())
        g.db.commit()
        flash("Konfiguration gespeichert (CPU/RAM wirken sofort, soweit der Container läuft).", "success")
    except PveError as exc:
        flash(f"Speichern fehlgeschlagen: {exc}", "danger")
    return redirect(url_for("pve.guest", pve_id=pve_id, node=node, gtype="lxc", vmid=vmid))


@bp.post("/<int:pve_id>/guest/<int:vmid>/watch")
@login_required
def guest_watch(pve_id: int, vmid: int):
    server = _get(pve_id, LEVEL_FULL)
    watch = set(server.watch_list)
    if vmid in watch:
        watch.discard(vmid)
        flash("Überwachung beendet.", "info")
    else:
        watch.add(vmid)
        flash("Gast wird überwacht: läuft er nicht, gibt es eine Warnung.", "success")
    server.watch = sorted(watch)
    audit(g.db, g.user, "pve.watch", f"{server.name}/{vmid}", "an" if vmid in watch else "aus", ip=client_ip())
    g.db.commit()
    return redirect(common.safe_next(url_for("pve.server", pve_id=pve_id)))


# --------------------------------------------------------------------------
# guest controls from the system page (system permissions)
# --------------------------------------------------------------------------
@bp.post("/system/<int:system_id>/op")
@login_required
def system_op(system_id: int):
    system = get_system_or_403(system_id, LEVEL_OPERATE)
    op = request.form.get("op", "")
    if op not in ("start", "shutdown", "reboot", "stop") or not system.pve_server_id or not system.pve_vmid:
        abort(400)
    server = g.db.get(PveServer, system.pve_server_id)
    if server is None:
        abort(404)
    guest = next((x for x in server.data.get("guests", []) if x["vmid"] == system.pve_vmid), None)
    if guest is None:
        flash("Gast im Proxmox nicht gefunden – bitte die Proxmox-Übersicht aktualisieren.", "danger")
        return redirect(url_for("systems.detail", system_id=system_id))
    job = _enqueue_op(server, guest["node"], guest["type"], guest["vmid"], op, {}, system=system)
    audit(g.db, g.user, f"pve.{op}", f"{server.name}/{guest['vmid']}", system.name, ip=client_ip())
    g.db.commit()
    return redirect(url_for("jobs.detail", job_id=job.id))


@bp.post("/system/<int:system_id>/resetup")
@login_required
def system_resetup(system_id: int):
    """Set up the management access of a guest again (e.g. after a failed creation/import)."""
    system = get_system_or_403(system_id, LEVEL_FULL)
    if not system.pve_server_id or not system.pve_vmid:
        abort(400)
    server = _get(system.pve_server_id, LEVEL_FULL)
    guest = next((x for x in server.data.get("guests", []) if x["vmid"] == system.pve_vmid), None)
    if guest is None:
        flash("Gast im Proxmox nicht gefunden – bitte die Proxmox-Übersicht aktualisieren.", "danger")
        return redirect(url_for("systems.detail", system_id=system_id))
    item = {"node": guest["node"], "type": guest["type"], "vmid": guest["vmid"], "name": guest.get("name", ""),
            "ip": ""}
    job = enqueue(g.db, kind="pve_import", title=f"Einrichtung wiederholen: {system.name} – {server.name}",
                  user=g.user, pve_id=server.id, payload={"items": [item], "install_ssh": True})
    audit(g.db, g.user, "pve.resetup", system.name, f"{server.name}/{guest['vmid']}", ip=client_ip())
    g.db.commit()
    return redirect(url_for("jobs.detail", job_id=job.id))


# --------------------------------------------------------------------------
# create LXC
# --------------------------------------------------------------------------
@bp.route("/<int:pve_id>/create", methods=["GET", "POST"])
@login_required
def create(pve_id: int):
    server = _get(pve_id, LEVEL_FULL)
    api = _api(server, timeout=20)
    form = request.form if request.method == "POST" else {}
    if request.method == "POST":
        try:
            payload = pve.build_create(request.form)
        except pve.PveParamError as exc:
            flash(str(exc), "danger")
        else:
            if payload["publish"] and not server.pangolin_id:
                flash("Dieser Proxmox-Verbindung ist keine Pangolin-Instanz zugeordnet.", "danger")
            elif payload["static_lease"] and not server.router_id:
                flash("Dieser Proxmox-Verbindung ist kein RouterOS zugeordnet.", "danger")
            else:
                job = enqueue(g.db, kind="pve_create", title=f"Container {payload['vmid']} ({payload['hostname']}) "
                              f"anlegen – {server.name}", user=g.user, payload=payload, pve_id=server.id)
                audit(g.db, g.user, "pve.create_lxc", f"{server.name}/{payload['vmid']}", payload["hostname"],
                      ip=client_ip())
                g.db.commit()
                return redirect(url_for("jobs.detail", job_id=job.id))
    nodes = [n for n in server.data.get("nodes", []) if n.get("status") == "online"]
    node = (form.get("node") or request.args.get("node") or (nodes[0]["node"] if nodes else ""))
    ctx: dict = {"s": server, "nodes": nodes, "node": node, "f": form, "error": None, "templates": [],
                 "appliances": [], "rootfs": [], "tmpl_storages": [], "bridges": [], "pools": [], "nextid": "",
                 "sm_key": bool(sshkeys.public_key()),
                 "pangolin": None, "pg_domains": [], "pg_sites": [], "router": None}
    if node:
        try:
            pve.check_guest_ref(node, "lxc", 100)
            ctx["tmpl_storages"] = [st["storage"] for st in api.storages(node, "vztmpl")]
            for st in ctx["tmpl_storages"]:
                ctx["templates"] += [c["volid"] for c in api.storage_content(node, st, "vztmpl")]
            have = {t.split("/")[-1] for t in ctx["templates"]}
            ctx["appliances"] = sorted([a for a in api.appliances(node) if a.get("section") == "system"
                                        and a.get("template") not in have], key=lambda a: a.get("template", ""))
            ctx["rootfs"] = [st["storage"] for st in api.storages(node, "rootdir")]
            ctx["bridges"] = [b["iface"] for b in api.bridges(node)]
            ctx["pools"] = [p["poolid"] for p in api.pools()]
            ctx["nextid"] = api.nextid()
        except (PveError, pve.PveParamError) as exc:
            ctx["error"] = str(exc)
    if server.pangolin_id and common.can(KIND_PANGOLIN, server.pangolin_id, LEVEL_FULL):
        pg = g.db.get(PangolinServer, server.pangolin_id)
        ctx["pangolin"] = pg
        try:
            client = integrations.pangolin_client(pg)
            ctx["pg_domains"] = client.domains()
            ctx["pg_sites"] = client.sites()
        except integrations.ApiError as exc:
            ctx["pg_error"] = str(exc)
    if server.router_id:
        ctx["router"] = g.db.get(RouterDevice, server.router_id)
    ctx["all_pangolins"] = [p for p in g.db.execute(select(PangolinServer).order_by(PangolinServer.name)).scalars()
                            if common.can(KIND_PANGOLIN, p.id, LEVEL_FULL)]
    return render_template("pve/create.html", **ctx)
