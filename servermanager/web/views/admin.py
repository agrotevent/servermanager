"""Administration: settings, servermanager backups/restore, self update."""
from __future__ import annotations

import os
import time
from datetime import datetime
from zoneinfo import available_timezones

from flask import Blueprint, abort, flash, g, redirect, render_template, request, send_file, session, url_for
from sqlalchemy import select

from ... import __version__, backup, notify, selfupdate, settings, sshkeys
from ...config import get_config
from ...core import audit
from ...helper import HelperError, run_helper
from ...models import JOB_RUNNING, Job
from ..auth import admin_required, client_ip

bp = Blueprint("admin", __name__)

SECTIONS = {
    "general": ["general.site_name", "general.base_url", "general.timezone", "general.session_hours",
                "general.require_2fa_admin"],
    "checks": ["checks.status_interval_min", "checks.deep_interval_hours", "checks.apt_refresh",
               "checks.docker_image_check", "checks.parallel", "ssh.connect_timeout", "jobs.max_parallel",
               "jobs.log_retention_days", "integrations.poll_min", "integrations.disk_alert_pct",
               "integrations.notify", "ispconfig.auto_setup"],
    "enroll": ["enroll.tls_pin", "enroll.insecure_tls", "enroll.restrict_ssh_source", "enroll.direct_source",
               "enroll.default_valid_hours"],
    "mail": ["mail.enabled", "mail.host", "mail.port", "mail.security", "mail.user", "mail.sender",
             "mail.admin_recipients", "mail.notify_failures"],
    "backup": ["backup.auto_enabled", "backup.hour", "backup.keep", "backup.include_system_backups",
               "backup.before_update", "system_backup.keep"],
}


# --------------------------------------------------------------------------
# settings
# --------------------------------------------------------------------------
@bp.get("/settings")
@admin_required
def settings_page():
    values = {k: settings.get(g.db, k) for keys in SECTIONS.values() for k in keys}
    tzs = sorted(t for t in available_timezones() if "/" in t and not t.startswith(("Etc/", "SystemV/")))
    return render_template("admin/settings.html", v=values, sm_pubkey=sshkeys.public_key(), timezones=tzs,
                           mail_ok=notify.mail_configured(g.db), cfg=get_config())


@bp.post("/settings/<section>")
@admin_required
def settings_save(section: str):
    keys = SECTIONS.get(section)
    if keys is None or section == "backup":
        abort(404)
    for key in keys:
        field = key.replace(".", "__")
        settings.set(g.db, key, settings.coerce(key, request.form.get(field, "")))
    if section == "mail" and request.form.get("mail__password"):
        settings.set(g.db, "mail.password", request.form["mail__password"])
    if section == "general":
        base = settings.get(g.db, "general.base_url")
        if base and not base.startswith(("http://", "https://")):
            settings.set(g.db, "general.base_url", "https://" + base)
        settings.set(g.db, "general.base_url", (settings.get(g.db, "general.base_url") or "").rstrip("/"))
    if section == "enroll":
        pin = (settings.get(g.db, "enroll.tls_pin") or "").replace("sha256//", "").strip()
        settings.set(g.db, "enroll.tls_pin", pin)
    audit(g.db, g.user, "settings.update", section, ip=client_ip())
    g.db.commit()
    flash("Einstellungen gespeichert.", "success")
    return redirect(url_for("admin.settings_page") + f"#{section}")


@bp.post("/settings/mail/test")
@admin_required
def mail_test():
    to = notify.recipients(request.form.get("to", "") or g.user.email)
    if not to:
        flash("Keine Empfängeradresse angegeben.", "danger")
        return redirect(url_for("admin.settings_page") + "#mail")
    try:
        notify.send_mail(g.db, to, "Testnachricht", "Dies ist eine Testnachricht des Servermanagers.")
        flash(f"Testnachricht an {', '.join(to)} gesendet.", "success")
    except Exception as exc:  # noqa: BLE001
        flash(f"Versand fehlgeschlagen: {exc}", "danger")
    return redirect(url_for("admin.settings_page") + "#mail")


@bp.post("/settings/tls-pin")
@admin_required
def tls_pin_detect():
    """Compute the public key pin of the local TLS certificate (self signed setups)."""
    import base64
    import hashlib

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    path = get_config().tls_cert_file
    if not path or not os.path.exists(path):
        flash("Kein lokales Zertifikat konfiguriert (tls_cert_file in servermanager.conf).", "danger")
        return redirect(url_for("admin.settings_page") + "#enroll")
    cert = x509.load_pem_x509_certificate(open(path, "rb").read())
    spki = cert.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
    pin = base64.b64encode(hashlib.sha256(spki).digest()).decode()
    settings.set(g.db, "enroll.tls_pin", pin)
    g.db.commit()
    flash(f"Zertifikats-Pin übernommen: sha256//{pin}", "success")
    return redirect(url_for("admin.settings_page") + "#enroll")


@bp.post("/settings/ssh-key/regenerate")
@admin_required
def regenerate_ssh_key():
    if request.form.get("confirm") != "NEU":
        flash("Bitte zur Bestätigung NEU eingeben.", "danger")
        return redirect(url_for("admin.settings_page") + "#ssh")
    old = sshkeys.public_key()
    new = sshkeys.ensure_keypair(force=True)
    audit(g.db, g.user, "ssh.key_regenerated", "", f"alt: {old[:60]}", ip=client_ip())
    g.db.commit()
    flash("Neues SSH-Schlüsselpaar erzeugt. ACHTUNG: Der neue öffentliche Schlüssel muss auf allen Systemen "
          "hinterlegt werden (z. B. per Enrollment mit --force oder manuell). " + new[:40] + "…", "warning")
    return redirect(url_for("admin.settings_page") + "#ssh")


# --------------------------------------------------------------------------
# servermanager backups
# --------------------------------------------------------------------------
@bp.get("/backups")
@admin_required
def backups():
    values = {k: settings.get(g.db, k) for k in SECTIONS["backup"]}
    return render_template("admin/backups.html", backups=backup.list_backups(), v=values,
                           has_passphrase=bool(settings.get(g.db, "backup.passphrase")),
                           staged=session.get("restore_staged"))


@bp.post("/backups/settings")
@admin_required
def backups_settings():
    for key in SECTIONS["backup"]:
        settings.set(g.db, key, settings.coerce(key, request.form.get(key.replace(".", "__"), "")))
    if request.form.get("clear_passphrase"):
        settings.set(g.db, "backup.passphrase", "")
    elif request.form.get("backup__passphrase"):
        settings.set(g.db, "backup.passphrase", request.form["backup__passphrase"])
    audit(g.db, g.user, "settings.update", "backup", ip=client_ip())
    g.db.commit()
    flash("Backup-Einstellungen gespeichert.", "success")
    return redirect(url_for("admin.backups"))


@bp.post("/backups/create")
@admin_required
def backups_create():
    passphrase = request.form.get("passphrase") or None
    try:
        path = backup.create_backup(g.db, note=request.form.get("note", "")[:200], passphrase=passphrase,
                                    include_system_backups=bool(request.form.get("include_system_backups")))
    except (backup.BackupError, OSError) as exc:
        flash(f"Backup fehlgeschlagen: {exc}", "danger")
        return redirect(url_for("admin.backups"))
    audit(g.db, g.user, "backup.create", path.name, ip=client_ip())
    g.db.commit()
    flash(f"Backup erstellt: {path.name}", "success")
    return redirect(url_for("admin.backups"))


@bp.get("/backups/<name>/download")
@admin_required
def backups_download(name: str):
    try:
        path = backup.backup_path(name)
    except backup.BackupError:
        abort(404)
    audit(g.db, g.user, "backup.download", name, ip=client_ip())
    g.db.commit()
    return send_file(path, as_attachment=True, download_name=name)


@bp.post("/backups/<name>/delete")
@admin_required
def backups_delete(name: str):
    try:
        backup.backup_path(name).unlink()
    except backup.BackupError:
        abort(404)
    audit(g.db, g.user, "backup.delete", name, ip=client_ip())
    g.db.commit()
    flash("Backup gelöscht.", "success")
    return redirect(url_for("admin.backups"))


@bp.post("/backups/restore")
@admin_required
def backups_restore_prepare():
    passphrase = request.form.get("passphrase", "")
    upload = request.files.get("file")
    try:
        if upload and upload.filename:
            cfg = get_config()
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            tmp = cfg.backups_dir / f".upload-{ts}"
            upload.save(tmp)
            os.chmod(tmp, 0o600)
            enc = backup.is_encrypted(tmp)
            name = f"servermanager-backup-upload-{ts}.tar.gz" + (".enc" if enc else "")
            os.replace(tmp, cfg.backups_dir / name)
        else:
            name = request.form.get("name", "")
        path = backup.backup_path(name)
        manifest = backup.inspect_backup(path, passphrase)
    except backup.BackupError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("admin.backups"))
    return render_template("admin/restore_confirm.html", name=name, manifest=manifest, passphrase=passphrase)


@bp.post("/backups/restore/confirm")
@admin_required
def backups_restore_confirm():
    name = request.form.get("name", "")
    passphrase = request.form.get("passphrase", "")
    if request.form.get("confirm") != "WIEDERHERSTELLEN":
        flash("Bitte zur Bestätigung WIEDERHERSTELLEN eingeben.", "danger")
        return redirect(url_for("admin.backups"))
    try:
        path = backup.backup_path(name)
        safety = backup.create_backup(g.db, note=f"automatisch vor Wiederherstellung von {name}")
        backup.stage_restore(path, passphrase)
        audit(g.db, g.user, "backup.restore", name, f"Sicherung des alten Stands: {safety.name}", ip=client_ip())
        g.db.commit()
        try:
            run_helper("restore", timeout=60)
        except HelperError as exc:
            if exc.returncode >= 0:  # killed by a signal: the restore is already stopping this service
                raise
    except (backup.BackupError, HelperError, OSError) as exc:
        flash(f"Wiederherstellung fehlgeschlagen: {exc}", "danger")
        return redirect(url_for("admin.backups"))
    return render_template("admin/restarting.html", title="Wiederherstellung läuft",
                           message="Die Sicherung wird eingespielt und die Dienste werden neu gestartet. "
                                   "Anschließend ist eine neue Anmeldung erforderlich.")


# --------------------------------------------------------------------------
# self update
# --------------------------------------------------------------------------
@bp.get("/update")
@admin_required
def update_page():
    running = g.db.execute(select(Job).where(Job.status == JOB_RUNNING)).scalars().all()
    return render_template("admin/update.html", st=selfupdate.status(), info=selfupdate.current(), check=session.pop("update_check", None),
                           log=selfupdate.log_text(), running=running, token=selfupdate.token_status(),
                           branches=selfupdate.branches(),
                           last_check=settings.get(g.db, "state.update_checked"))


@bp.post("/update/branch")
@admin_required
def update_branch():
    name = request.form.get("branch", "").strip()
    try:
        msg = selfupdate.set_branch(name)
        audit(g.db, g.user, "update.branch", name, ip=client_ip())
        g.db.commit()
        flash(msg or f"Update-Branch: {name}", "success")
    except HelperError as exc:
        flash(f"Branch nicht geändert: {exc}", "danger")
    return redirect(url_for("admin.update_page"))


@bp.post("/update/token")
@admin_required
def update_token():
    remove = request.form.get("remove") == "1"
    token = "" if remove else request.form.get("token", "")
    if not remove and not token.strip():
        flash("Bitte ein Token eingeben.", "warning")
        return redirect(url_for("admin.update_page"))
    try:
        msg = selfupdate.set_token(token, request.form.get("token_user", ""))
        audit(g.db, g.user, "update.token_remove" if remove else "update.token_set", "", ip=client_ip())
        g.db.commit()
        flash(msg or "Gespeichert.", "success")
    except HelperError as exc:
        flash(f"Token nicht gespeichert: {exc}", "danger")
    return redirect(url_for("admin.update_page"))


@bp.post("/update/check")
@admin_required
def update_check():
    try:
        result = selfupdate.check()
        settings.set(g.db, "state.update_checked", datetime.now().isoformat(timespec="minutes"))
        settings.set(g.db, "state.update_remote_sha", result["remote"])
        g.db.commit()
        session["update_check"] = result
        if not result["available"]:
            flash("Der Servermanager ist auf dem neuesten Stand.", "success")
    except (HelperError, OSError) as exc:
        flash(f"Prüfung fehlgeschlagen: {exc}", "danger")
    return redirect(url_for("admin.update_page"))


@bp.post("/update/start")
@admin_required
def update_start():
    if selfupdate.running():
        flash("Es läuft bereits ein Update.", "info")
        return redirect(url_for("admin.update_progress"))
    try:
        if settings.get(g.db, "backup.before_update"):
            path = backup.create_backup(g.db, note="automatisch vor Update")
            flash(f"Sicherung vor dem Update: {path.name}", "info")
        audit(g.db, g.user, "update.start", "", ip=client_ip())
        g.db.commit()
        started = time.time()
        try:
            selfupdate.start()
        except HelperError as exc:
            # killed by a signal: the update already runs and is restarting this service (older helpers
            # waited for the whole update) - show the progress page instead of an error
            if exc.returncode >= 0:
                raise
    except (HelperError, backup.BackupError, OSError) as exc:
        flash(f"Update konnte nicht gestartet werden: {exc}", "danger")
        return redirect(url_for("admin.update_page"))
    return redirect(url_for("admin.update_progress", since=int(started)))


@bp.get("/update/progress")
@admin_required
def update_progress():
    try:
        since = int(request.args.get("since", "0"))
    except ValueError:
        since = 0
    return render_template("admin/update_progress.html", since=since, st=selfupdate.status(since),
                           version=__version__, log=selfupdate.log_text(50_000))


@bp.get("/update/status")
@admin_required
def update_status():
    try:
        since = int(request.args.get("since", "0"))
    except ValueError:
        since = 0
    return {"status": selfupdate.status(since), "version": __version__, "log": selfupdate.log_text(50_000)}


@bp.get("/update/log")
@admin_required
def update_log():
    return {"log": selfupdate.log_text()}

