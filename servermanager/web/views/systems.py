"""Systems: list, create/edit, detail page, module panels and actions."""
from __future__ import annotations

import re

from flask import (Blueprint, abort, flash, g, redirect, render_template, request, send_file, url_for)
from sqlalchemy import select

from ... import access, inventory, security, sshkeys, sysbackup, wireguard
from ...core import audit
from ...jobs import enqueue, log_path as job_log_path, new_batch_id
from ...mikrotik import MikroTikError
from ...models import (AUTH_KEY, AUTH_METHODS, AUTH_PASSWORD, CONN_DIRECT, CONN_WIREGUARD, KIND_PVE, LEVEL_FULL,
                       LEVEL_OPERATE, LEVEL_VIEW, LEVELS, SUDO_MODES, SUDO_NONE, SUDO_PASSWORD, Job, System,
                       PveServer, SystemAccess, SystemBackup, User)
from ...modules import MODULES, ParamError, get_module, modules_for
from ...ssh import SSHError
from ..auth import can, client_ip, get_system_or_403, login_required, manager_required

bp = Blueprint("systems", __name__, url_prefix="/systems")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:\-\[\]]{0,253}$")
USER_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")


# --------------------------------------------------------------------------
# list
# --------------------------------------------------------------------------
@bp.get("/")
@login_required
def index():
    systems = access.accessible_systems(g.db, g.user)
    q = request.args.get("q", "").strip().lower()
    typ = request.args.get("type", "")
    status = request.args.get("status", "")
    tag = request.args.get("tag", "").strip().lower()
    if q:
        systems = [s for s in systems if q in s.name.lower() or q in (s.host or "").lower()
                   or q in (s.hostname or "").lower() or q in (s.tags or "").lower()]
    if typ:
        systems = [s for s in systems if s.has_type(typ)]
    if status:
        systems = [s for s in systems if s.status == status]
    if tag:
        systems = [s for s in systems if tag in [t.lower() for t in s.tag_list]]
    all_tags = sorted({t for s in access.accessible_systems(g.db, g.user) for t in s.tag_list})
    summaries = {s.id: inventory.update_summary(s) for s in systems}
    return render_template("systems/index.html", systems=systems, summaries=summaries, all_tags=all_tags,
                           filters={"q": q, "type": typ, "status": status, "tag": tag})


@bp.post("/bulk")
@login_required
def bulk():
    ids = [int(i) for i in request.form.getlist("ids") if i.isdigit()]
    action = request.form.get("bulk_action", "")
    if not ids:
        flash("Keine Systeme ausgewählt.", "warning")
        return redirect(request.referrer or url_for("systems.index"))
    if action == "plan":
        return redirect(url_for("schedules.new", systems=",".join(map(str, ids))))
    batch = new_batch_id()
    count = 0
    for sid in ids:
        system = g.db.get(System, sid)
        if system is None or not can(sid, LEVEL_OPERATE):
            continue
        if action == "check":
            enqueue(g.db, kind="check", title=f"Update-Prüfung: {system.name}", system=system, user=g.user,
                    batch_id=batch)
        elif action in ("upgrade", "security_upgrade"):
            mod = get_module("debian")
            act = mod.action(action)
            enqueue(g.db, kind="action", title=f"{act.label}: {system.name}", system=system, user=g.user,
                    batch_id=batch, payload={"module": "debian", "action": action,
                                             "params": act.clean_params({"autoremove": "1"})})
        else:
            abort(400)
        count += 1
    audit(g.db, g.user, f"bulk.{action}", f"{count} Systeme", ",".join(map(str, ids)), ip=client_ip())
    g.db.commit()
    flash(f"{count} Job(s) gestartet.", "success")
    return redirect(url_for("jobs.index", batch=batch))


# --------------------------------------------------------------------------
# create / edit / delete
# --------------------------------------------------------------------------
def _form_to_system(system: System, form, is_new: bool) -> list[str]:
    errors: list[str] = []
    system.name = form.get("name", "").strip()[:128]
    if not system.name:
        errors.append("Name ist erforderlich.")
    system.description = form.get("description", "").strip()
    system.tags = ", ".join(t.strip() for t in form.get("tags", "").split(",") if t.strip())[:255]
    system.notes = form.get("notes", "")
    conn = form.get("connection", CONN_DIRECT)
    system.connection = conn if conn in (CONN_DIRECT, CONN_WIREGUARD) else CONN_DIRECT
    host = form.get("host", "").strip()
    if system.connection == CONN_WIREGUARD and system.wg_ip and not host:
        host = system.wg_ip
    if not HOST_RE.match(host):
        errors.append("Ungültige oder fehlende Adresse (Host/IP).")
    system.host = host
    try:
        system.port = int(form.get("port", "22") or 22)
        if not 0 < system.port < 65536:
            raise ValueError
    except ValueError:
        errors.append("Ungültiger SSH-Port.")
    user = form.get("username", "root").strip() or "root"
    if not USER_RE.match(user):
        errors.append("Ungültiger Benutzername.")
    system.username = user
    method = form.get("auth_method", AUTH_KEY)
    system.auth_method = method if method in AUTH_METHODS else AUTH_KEY
    if form.get("password"):
        system.password_enc = security.encrypt(form["password"])
    elif form.get("clear_password"):
        system.password_enc = None
    key_text = form.get("private_key", "").strip()
    passphrase = form.get("key_passphrase", "")
    if key_text:
        try:
            sshkeys.load_private_key(key_text, passphrase or None)
            system.private_key_enc = security.encrypt(key_text)
            system.key_passphrase_enc = security.encrypt(passphrase) if passphrase else None
        except ValueError as exc:
            errors.append(str(exc))
    elif form.get("clear_key"):
        system.private_key_enc = None
        system.key_passphrase_enc = None
    sudo = form.get("sudo_mode", SUDO_NONE)
    system.sudo_mode = sudo if sudo in SUDO_MODES else SUDO_NONE
    if user == "root":
        system.sudo_mode = SUDO_NONE
    if form.get("sudo_password"):
        system.sudo_password_enc = security.encrypt(form["sudo_password"])
    if system.auth_method == AUTH_PASSWORD and not system.password_enc:
        errors.append("Für die Passwort-Anmeldung muss ein Passwort hinterlegt werden.")
    if system.sudo_mode == SUDO_PASSWORD and not (system.sudo_password_enc or system.password_enc):
        errors.append("Für 'sudo mit Passwort' muss ein sudo- oder Login-Passwort hinterlegt werden.")
    if not g.user.is_admin and not system.private_key_enc and system.auth_method != AUTH_PASSWORD:
        # The servermanager key is trusted by every managed host. Without this check a non-admin could
        # point a system at a host he has no access to and log in with that key.
        errors.append("Nur Administratoren dürfen Systeme mit dem Servermanager-Schlüssel ohne Nachweis anlegen: "
                      "bitte die Anmeldung per Passwort wählen (der Schlüssel kann danach automatisch installiert "
                      "werden) oder einen eigenen privaten Schlüssel hinterlegen.")
    types = [t for t in form.getlist("types") if t in MODULES]
    system.types = ["debian"] + [t for t in MODULES if t in types and t != "debian"]
    system.nextcloud_path = form.get("nextcloud_path", "").strip()
    if system.nextcloud_path and not re.match(r"^/[A-Za-z0-9._/@+-]*$", system.nextcloud_path):
        errors.append("Ungültiger Nextcloud-Pfad.")
    system.occ_command = form.get("occ_command", "").strip()[:255]
    try:
        system.backup_paths = " ".join(sysbackup.parse_paths(form.get("backup_paths", "/etc")))
    except ValueError as exc:
        errors.append(str(exc))
    if g.user.is_admin and "pve_server_id" in form:
        # linking grants power control of the guest to everybody with operate rights on the system
        pid, vmid = form.get("pve_server_id", ""), form.get("pve_vmid", "").strip()
        if pid.isdigit() and g.db.get(PveServer, int(pid)):
            if not vmid.isdigit() or not 100 <= int(vmid) <= 999999999:
                errors.append("Für die Proxmox-Verknüpfung die VMID angeben.")
            else:
                system.pve_server_id, system.pve_vmid = int(pid), int(vmid)
        else:
            system.pve_server_id, system.pve_vmid = None, None
    return errors


@bp.route("/new", methods=["GET", "POST"])
@manager_required
def new():
    system = System(port=22, username="root", auth_method=AUTH_KEY, sudo_mode=SUDO_NONE, types=["debian"],
                    connection=CONN_DIRECT, backup_paths="/etc")
    if request.method == "POST":
        errors = _form_to_system(system, request.form, True)
        if not errors and g.db.execute(select(System.id).where(System.name == system.name)).first():
            errors.append("Ein System mit diesem Namen existiert bereits.")
        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("systems/form.html", system=system, is_new=True, **_form_ctx())
        system.created_by = g.user.id
        g.db.add(system)
        g.db.flush()
        if not g.user.is_admin:
            access.grant(g.db, g.user.id, system.id, LEVEL_FULL)
        audit(g.db, g.user, "system.create", system.name, f"{system.username}@{system.host}:{system.port}",
              ip=client_ip())
        job = None
        if request.form.get("deploy_key") and system.password_enc:
            job = enqueue(g.db, kind="deploy_key", title=f"SSH-Schlüssel installieren: {system.name}",
                          system=system, user=g.user, payload={"remove_password": bool(request.form.get("remove_password"))})
        if request.form.get("check"):
            enqueue(g.db, kind="check", title=f"Erstprüfung: {system.name}", system=system, user=g.user,
                    payload={"detect": True})
        g.db.commit()
        flash(f"System '{system.name}' angelegt. Die Verbindung wird jetzt geprüft.", "success")
        if job:
            return redirect(url_for("jobs.detail", job_id=job.id))
        return redirect(url_for("systems.detail", system_id=system.id))
    # prefill (e.g. "Als System verwalten" on a Proxmox container)
    system.name = request.args.get("name", "")[:128]
    system.host = request.args.get("host", "")[:255]
    if g.user.is_admin and request.args.get("pve", "").isdigit() and request.args.get("vmid", "").isdigit():
        system.pve_server_id, system.pve_vmid = int(request.args["pve"]), int(request.args["vmid"])
    return render_template("systems/form.html", system=system, is_new=True, **_form_ctx())


def _form_ctx() -> dict:
    pve_servers = g.db.execute(select(PveServer).order_by(PveServer.name)).scalars().all() if g.user.is_admin else []
    return {"auth_methods": AUTH_METHODS, "sudo_modes": SUDO_MODES, "sm_pubkey": sshkeys.public_key(),
            "pve_servers": pve_servers}


@bp.route("/<int:system_id>/edit", methods=["GET", "POST"])
@login_required
def edit(system_id: int):
    system = get_system_or_403(system_id, LEVEL_FULL)
    if request.method == "POST":
        old_routed = system.routed_subnet_list
        old_conn = (system.host, system.port, system.connection, system.auth_method, system.private_key_enc)
        errors = _form_to_system(system, request.form, False)
        if not g.user.is_admin:
            # changing the target address of a key-authenticated system would allow to reach
            # arbitrary hosts with the servermanager key
            if (system.host, system.port, system.connection) != old_conn[:3]:
                errors.append("Adresse, Port und Verbindungsart können nur von Administratoren geändert werden.")
            errors = [e for e in errors if not e.startswith("Nur Administratoren dürfen Systeme")]
            if system.auth_method != old_conn[3] and not system.private_key_enc and system.auth_method != AUTH_PASSWORD:
                errors.append("Die Umstellung auf den Servermanager-Schlüssel erfolgt über 'SSH-Schlüssel installieren'.")
        routed: list[str] = old_routed
        if system.connection == CONN_WIREGUARD and g.user.is_admin:
            try:
                routed = wireguard.validate_routed(g.db, wireguard.parse_subnets(request.form.get("routed_subnets", "")),
                                                   exclude_system_id=system.id)
            except ValueError as exc:
                errors.append(str(exc))
        dup = g.db.execute(select(System.id).where(System.name == system.name, System.id != system.id)).first()
        if dup:
            errors.append("Ein System mit diesem Namen existiert bereits.")
        if errors:
            g.db.rollback()
            for e in errors:
                flash(e, "danger")
            system = g.db.get(System, system_id)
            return render_template("systems/form.html", system=system, is_new=False, **_form_ctx())
        if system.connection == CONN_WIREGUARD and routed != old_routed:
            try:
                wireguard.update_peer_routes(g.db, system, routed)
                wireguard.refresh_local_routes(g.db)
                flash("Geroutete Netze auf dem MikroTik aktualisiert.", "info")
            except (MikroTikError, ValueError) as exc:
                flash(f"MikroTik konnte nicht aktualisiert werden: {exc}", "danger")
                system.routed_subnets = " ".join(old_routed)
        audit(g.db, g.user, "system.update", system.name, ip=client_ip())
        g.db.commit()
        flash("Gespeichert.", "success")
        return redirect(url_for("systems.detail", system_id=system.id))
    return render_template("systems/form.html", system=system, is_new=False, **_form_ctx())


@bp.post("/<int:system_id>/delete")
@login_required
def delete(system_id: int):
    system = get_system_or_403(system_id, LEVEL_FULL)
    if request.form.get("confirm_name", "").strip() != system.name:
        flash("Zum Löschen bitte den Namen des Systems exakt eingeben.", "danger")
        return redirect(url_for("systems.detail", system_id=system.id, tab="settings"))
    if system.mt_refs and request.form.get("remove_peer", "1"):
        try:
            wireguard.deprovision_peer(g.db, system)
        except MikroTikError as exc:
            flash(f"WireGuard-Peer konnte nicht entfernt werden: {exc}", "warning")
    for b in g.db.execute(select(SystemBackup).where(SystemBackup.system_id == system.id)).scalars():
        sysbackup.file_path(b).unlink(missing_ok=True)
    for (job_id,) in g.db.execute(select(Job.id).where(Job.system_id == system.id)).all():
        job_log_path(job_id).unlink(missing_ok=True)
    name = system.name
    g.db.delete(system)
    audit(g.db, g.user, "system.delete", name, ip=client_ip())
    g.db.commit()
    wireguard.refresh_local_routes(g.db)
    flash(f"System '{name}' gelöscht.", "success")
    return redirect(url_for("systems.index"))


# --------------------------------------------------------------------------
# detail
# --------------------------------------------------------------------------
@bp.get("/<int:system_id>")
@login_required
def detail(system_id: int):
    system = get_system_or_403(system_id, LEVEL_VIEW)
    tab = request.args.get("tab", "overview")
    mods = modules_for(system)
    jobs = g.db.execute(select(Job).where(Job.system_id == system.id).order_by(Job.id.desc()).limit(30)).scalars().all()
    backups = g.db.execute(select(SystemBackup).where(SystemBackup.system_id == system.id)
                           .order_by(SystemBackup.id.desc())).scalars().all()
    access_rows = []
    users = []
    if g.user.is_admin:
        access_rows = g.db.execute(select(SystemAccess).where(SystemAccess.system_id == system.id)).scalars().all()
        users = g.db.execute(select(User).order_by(User.username)).scalars().all()
    pve_guest = None
    if system.pve_server_id and system.pve_vmid:
        srv = g.db.get(PveServer, system.pve_server_id)
        if srv is not None:
            guest = next((x for x in srv.data.get("guests", []) if x.get("vmid") == system.pve_vmid), None)
            pve_guest = {"server": srv, "guest": guest,
                         "can_resetup": bool(guest) and access.system_level(g.db, g.user, system.id) == LEVEL_FULL
                         and (g.user.is_admin or access.has_integration_level(g.db, g.user, KIND_PVE, srv.id,
                                                                              LEVEL_FULL))}
    return render_template("systems/detail.html", system=system, tab=tab, mods=mods, jobs=jobs, backups=backups,
                           summary=inventory.update_summary(system), access_rows=access_rows, users=users,
                           level=access.system_level(g.db, g.user, system.id), pve_guest=pve_guest)


@bp.get("/<int:system_id>/panel/<module_key>")
@login_required
def panel(system_id: int, module_key: str):
    system = get_system_or_403(system_id, LEVEL_VIEW)
    mod = MODULES.get(module_key)
    if mod is None or not mod.applies(system) or not mod.panel_template:
        abort(404)
    data, error = {}, None
    try:
        with inventory.connect(system) as conn:
            data = mod.panel(conn, system)
    except (SSHError, RuntimeError, OSError, ValueError) as exc:
        error = str(exc)
    return render_template(mod.panel_template, system=system, mod=mod, data=data, error=error)


@bp.post("/<int:system_id>/action")
@login_required
def action(system_id: int):
    system = get_system_or_403(system_id, LEVEL_VIEW)
    try:
        mod = get_module(request.form.get("module", ""))
        act = mod.action(request.form.get("action", ""))
        if not mod.applies(system):
            raise ParamError(f"Modul {mod.label} ist für dieses System nicht aktiviert")
        if not can(system.id, act.level):
            abort(403)
        params = act.clean_params(request.form)
    except ParamError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("systems.detail", system_id=system.id))
    job = enqueue(g.db, kind="action", title=f"{act.describe(params)}: {system.name}", system=system, user=g.user,
                  payload={"module": mod.key, "action": act.key, "params": params})
    audit(g.db, g.user, "system.action", system.name, f"{mod.key}.{act.key} {params}", ip=client_ip())
    g.db.commit()
    if request.form.get("stay"):
        flash(f"Job gestartet: {act.describe(params)}", "success")
        return redirect(request.referrer or url_for("systems.detail", system_id=system.id))
    return redirect(url_for("jobs.detail", job_id=job.id))


@bp.post("/<int:system_id>/check")
@login_required
def check(system_id: int):
    system = get_system_or_403(system_id, LEVEL_OPERATE)
    job = enqueue(g.db, kind="check", title=f"Update-Prüfung: {system.name}", system=system, user=g.user,
                  payload={"detect": bool(request.form.get("detect"))})
    g.db.commit()
    return redirect(url_for("jobs.detail", job_id=job.id))


@bp.post("/<int:system_id>/command")
@login_required
def command(system_id: int):
    system = get_system_or_403(system_id, LEVEL_FULL)
    cmd = request.form.get("command", "").strip()
    if not cmd:
        flash("Kein Befehl angegeben.", "warning")
        return redirect(url_for("systems.detail", system_id=system.id, tab="command"))
    job = enqueue(g.db, kind="command", title=f"Befehl: {cmd.splitlines()[0][:80]} ({system.name})",
                  system=system, user=g.user, payload={"command": cmd})
    audit(g.db, g.user, "system.command", system.name, cmd[:2000], ip=client_ip())
    g.db.commit()
    return redirect(url_for("jobs.detail", job_id=job.id))


@bp.post("/<int:system_id>/deploy-key")
@login_required
def deploy_key(system_id: int):
    system = get_system_or_403(system_id, LEVEL_FULL)
    if not system.password_enc:
        flash("Zum Installieren des Schlüssels wird ein hinterlegtes Passwort benötigt.", "danger")
        return redirect(url_for("systems.edit", system_id=system.id))
    job = enqueue(g.db, kind="deploy_key", title=f"SSH-Schlüssel installieren: {system.name}", system=system,
                  user=g.user, payload={"remove_password": bool(request.form.get("remove_password"))})
    g.db.commit()
    return redirect(url_for("jobs.detail", job_id=job.id))


@bp.post("/<int:system_id>/hostkey-reset")
@login_required
def hostkey_reset(system_id: int):
    system = get_system_or_403(system_id, LEVEL_FULL)
    if not g.user.is_admin:
        abort(403)
    system.host_keys = ""
    audit(g.db, g.user, "system.hostkey_reset", system.name, ip=client_ip())
    g.db.commit()
    flash("Gespeicherter Hostkey entfernt. Der Schlüssel wird bei der nächsten Verbindung neu übernommen.", "warning")
    return redirect(url_for("systems.detail", system_id=system.id, tab="settings"))


@bp.post("/<int:system_id>/pause")
@login_required
def pause(system_id: int):
    system = get_system_or_403(system_id, LEVEL_OPERATE)
    system.maintenance_mode = not system.maintenance_mode
    g.db.commit()
    flash("Automatische Prüfungen " + ("pausiert." if system.maintenance_mode else "wieder aktiv."), "info")
    return redirect(url_for("systems.detail", system_id=system.id))


# --------------------------------------------------------------------------
# config backups
# --------------------------------------------------------------------------
@bp.post("/<int:system_id>/backups")
@login_required
def backup_create(system_id: int):
    system = get_system_or_403(system_id, LEVEL_OPERATE)
    try:
        paths = " ".join(sysbackup.parse_paths(request.form.get("paths") or system.backup_paths))
    except ValueError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("systems.detail", system_id=system.id, tab="backups"))
    job = enqueue(g.db, kind="backup", title=f"Konfig-Backup: {system.name}", system=system, user=g.user,
                  payload={"paths": paths, "note": request.form.get("note", "")[:200] or "manuell"})
    g.db.commit()
    return redirect(url_for("jobs.detail", job_id=job.id))


def _backup_or_404(system: System, backup_id: int) -> SystemBackup:
    b = g.db.get(SystemBackup, backup_id)
    if b is None or b.system_id != system.id:
        abort(404)
    return b


@bp.get("/<int:system_id>/backups/<int:backup_id>/download")
@login_required
def backup_download(system_id: int, backup_id: int):
    system = get_system_or_403(system_id, LEVEL_FULL)
    b = _backup_or_404(system, backup_id)
    path = sysbackup.file_path(b)
    if not path.exists():
        abort(404)
    audit(g.db, g.user, "system.backup_download", system.name, b.filename, ip=client_ip())
    g.db.commit()
    return send_file(path, as_attachment=True, download_name=b.filename)


@bp.post("/<int:system_id>/backups/<int:backup_id>/restore")
@login_required
def backup_restore(system_id: int, backup_id: int):
    system = get_system_or_403(system_id, LEVEL_FULL)
    b = _backup_or_404(system, backup_id)
    mode = "inplace" if request.form.get("mode") == "inplace" else "extract"
    job = enqueue(g.db, kind="restore", title=f"Konfig-Restore ({'Originalort' if mode == 'inplace' else 'entpacken'}): "
                  f"{system.name}", system=system, user=g.user, payload={"backup_id": b.id, "mode": mode})
    audit(g.db, g.user, "system.backup_restore", system.name, f"{b.filename} {mode}", ip=client_ip())
    g.db.commit()
    return redirect(url_for("jobs.detail", job_id=job.id))


@bp.post("/<int:system_id>/backups/<int:backup_id>/delete")
@login_required
def backup_delete(system_id: int, backup_id: int):
    system = get_system_or_403(system_id, LEVEL_FULL)
    b = _backup_or_404(system, backup_id)
    sysbackup.file_path(b).unlink(missing_ok=True)
    g.db.delete(b)
    audit(g.db, g.user, "system.backup_delete", system.name, b.filename, ip=client_ip())
    g.db.commit()
    flash("Backup gelöscht.", "success")
    return redirect(url_for("systems.detail", system_id=system.id, tab="backups"))


# --------------------------------------------------------------------------
# access (admin)
# --------------------------------------------------------------------------
@bp.post("/<int:system_id>/access")
@login_required
def access_update(system_id: int):
    if not g.user.is_admin:
        abort(403)
    system = get_system_or_403(system_id, LEVEL_FULL)
    rows = {a.user_id: a for a in g.db.execute(select(SystemAccess).where(SystemAccess.system_id == system.id)).scalars()}
    for user in g.db.execute(select(User)).scalars():
        level = request.form.get(f"level_{user.id}", "")
        if level in LEVELS:
            if user.id in rows:
                rows[user.id].level = level
            else:
                g.db.add(SystemAccess(user_id=user.id, system_id=system.id, level=level))
        elif user.id in rows:
            g.db.delete(rows[user.id])
    audit(g.db, g.user, "system.access", system.name, ip=client_ip())
    g.db.commit()
    flash("Zugriffsrechte gespeichert.", "success")
    return redirect(url_for("systems.detail", system_id=system.id, tab="access"))
