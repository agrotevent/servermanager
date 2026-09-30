"""ISPConfig: remote API (set up via SSH), customers, websites, mail, DNS, databases; panel via Pangolin."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from sqlalchemy import select

from ... import access, integrations, security
from ...core import audit
from ...ispconfig_api import IspError, normalize_url, random_password
from ...jobs import enqueue
from ...models import KIND_ISPC, LEVEL_FULL, LEVEL_OPERATE, LEVEL_VIEW, IspServer, System
from ..auth import admin_required, client_ip, login_required
from . import _integration as common
from .mailcow import primary_pangolin

bp = Blueprint("ispc", __name__, url_prefix="/ispconfig")
TABS = {"overview": "Übersicht", "clients": "Kunden", "sites": "Webseiten", "mail": "E-Mail", "dns": "DNS",
        "databases": "Datenbanken", "access": "Zugang"}


def _get(isp_id: int, level: str) -> IspServer:
    return common.get_or_403(KIND_ISPC, isp_id, level)


@bp.get("/")
@login_required
def index():
    items = common.visible(KIND_ISPC)
    if not items and not g.user.is_admin:
        abort(403)
    linked = {i.system_id for i in g.db.execute(select(IspServer)).scalars()}
    unlinked = [s for s in g.db.execute(select(System).order_by(System.name)).scalars()
                if s.has_type("ispconfig") and s.id not in linked] if g.user.is_admin else []
    return render_template("ispconfig/index.html", items=items, unlinked=unlinked)


def _start_setup(isp: IspServer, system: System, allowed: str = ""):
    job = enqueue(g.db, kind="ispconfig_setup", title=f"ISPConfig-Schnittstelle: {system.name}", system=system,
                  user=g.user, payload={"isp_id": isp.id, "allowed": allowed})
    return job


def _save(isp: IspServer) -> list[str]:
    f = request.form
    errors: list[str] = []
    isp.name = (f.get("name") or "").strip()[:128]
    if not isp.name:
        errors.append("Bitte einen Namen angeben.")
    isp.description = (f.get("description") or "").strip()[:2000]
    isp.monitor = bool(f.get("monitor"))
    raw = f.get("system_id", "")
    isp.system_id = int(raw) if raw.isdigit() and g.db.get(System, int(raw)) else None
    pub = (f.get("public_url") or "").strip().rstrip("/")
    if pub and not re.match(r"^https://[A-Za-z0-9.-]+(:\d+)?$", pub):
        errors.append("Öffentliche Adresse als https://panel.example.com angeben.")
    isp.public_url = pub
    if f.get("mode", "ssh") == "manual":
        try:
            isp.api_url = normalize_url(f.get("api_url", ""))
        except IspError as exc:
            errors.append(str(exc))
        isp.username = (f.get("username") or "").strip()[:64]
        if f.get("password"):
            isp.password_enc = security.encrypt(f["password"])
        if not isp.username or not isp.password_enc:
            errors.append("Remote-Benutzer und Passwort angeben (ISPConfig → System → Remote-Benutzer).")
        fp = (f.get("fingerprint") or "").strip()
        isp.verify_ca = bool(f.get("verify_ca"))
        if fp:
            from ... import tlspin
            try:
                isp.fingerprint = tlspin.normalize_fingerprint(fp)
            except tlspin.PinError as exc:
                errors.append(str(exc))
        elif isp.api_url.startswith("https://") and not isp.verify_ca:
            errors.append("Zertifikats-Fingerabdruck hinterlegen („Abrufen“) oder die CA-Prüfung aktivieren.")
    elif isp.system_id is None:
        errors.append("Für die automatische Einrichtung per SSH das System wählen.")
    return errors


def _form(isp: IspServer, is_new: bool):
    systems = g.db.execute(select(System).order_by(System.name)).scalars().all()
    return render_template("ispconfig/form.html", i=isp, is_new=is_new, systems=systems,
                           mode=request.form.get("mode") or ("manual" if isp.username and not isp.setup else "ssh"))


@bp.route("/new", methods=["GET", "POST"])
@admin_required
def new():
    isp = IspServer(monitor=True, verify_ca=False)
    if request.method == "GET" and request.args.get("system", "").isdigit():
        s = g.db.get(System, int(request.args["system"]))
        if s is not None:
            isp.system_id, isp.name = s.id, s.name
    if request.method == "POST":
        errors = _save(isp)
        if request.form.get("fetch_fp"):
            fp, err = common.fetch_fp_from_form(8080)
            flash(err or "Fingerabdruck abgerufen – bitte vergleichen und speichern.", "danger" if err else "info")
            isp.fingerprint = fp or isp.fingerprint
            return _form(isp, True)
        if errors:
            for e in errors:
                flash(e, "danger")
            return _form(isp, True)
        g.db.add(isp)
        g.db.flush()
        audit(g.db, g.user, "ispconfig.create", isp.name, ip=client_ip())
        if request.form.get("mode", "ssh") == "ssh":
            job = _start_setup(isp, g.db.get(System, isp.system_id), (request.form.get("allowed") or "").strip())
            g.db.commit()
            flash("ISPConfig angelegt – die Schnittstelle wird jetzt per SSH eingerichtet.", "success")
            return redirect(url_for("jobs.detail", job_id=job.id))
        integrations.poll(g.db, isp)
        g.db.commit()
        flash("ISPConfig angelegt." + (f" {isp.status_message}" if isp.status_message else ""),
              "warning" if isp.status_message else "success")
        return redirect(url_for("ispc.detail", isp_id=isp.id))
    return _form(isp, True)


@bp.post("/quick/<int:system_id>")
@admin_required
def quick(system_id: int):
    """One click for a detected ISPConfig system: create the connection and set up the API via SSH."""
    system = g.db.get(System, system_id)
    if system is None:
        abort(404)
    isp = g.db.execute(select(IspServer).where(IspServer.system_id == system.id)).scalars().first()
    if isp is None:
        isp = IspServer(name=system.name, system_id=system.id, monitor=True, verify_ca=False)
        g.db.add(isp)
        g.db.flush()
    job = _start_setup(isp, system)
    audit(g.db, g.user, "ispconfig.setup_start", system.name, ip=client_ip())
    g.db.commit()
    return redirect(url_for("jobs.detail", job_id=job.id))


@bp.route("/<int:isp_id>/edit", methods=["GET", "POST"])
@admin_required
def edit(isp_id: int):
    isp = _get(isp_id, LEVEL_FULL)
    if request.method == "POST":
        errors = _save(isp)
        if errors:
            g.db.rollback()
            for e in errors:
                flash(e, "danger")
            return redirect(url_for("ispc.edit", isp_id=isp_id))
        audit(g.db, g.user, "ispconfig.update", isp.name, ip=client_ip())
        integrations.poll(g.db, isp)
        g.db.commit()
        flash("Gespeichert.", "success")
        return redirect(url_for("ispc.detail", isp_id=isp.id))
    return _form(isp, False)


@bp.post("/<int:isp_id>/setup")
@admin_required
def setup(isp_id: int):
    isp = _get(isp_id, LEVEL_FULL)
    system = g.db.get(System, isp.system_id) if isp.system_id else None
    if system is None:
        flash("Kein System (SSH) zugeordnet – die Schnittstelle kann nicht automatisch eingerichtet werden.", "danger")
        return redirect(url_for("ispc.detail", isp_id=isp_id, tab="access"))
    job = _start_setup(isp, system, (request.form.get("allowed") or "").strip())
    g.db.commit()
    return redirect(url_for("jobs.detail", job_id=job.id))


@bp.post("/<int:isp_id>/delete")
@admin_required
def delete(isp_id: int):
    isp = _get(isp_id, LEVEL_FULL)
    access.remove_integration(g.db, KIND_ISPC, isp.id)
    audit(g.db, g.user, "ispconfig.delete", isp.name, ip=client_ip())
    g.db.delete(isp)
    g.db.commit()
    flash("Verbindung entfernt. Der Remote-Benutzer „servermanager“ bleibt in ISPConfig bestehen und kann dort unter "
          "System → Remote-Benutzer gelöscht werden.", "warning")
    return redirect(url_for("ispc.index"))


def _publish_args(isp: IspServer) -> dict:
    parts = urlsplit(isp.api_url or "")
    return {"name": f"ISPConfig {isp.name}", "ip": parts.hostname or "", "port": parts.port or 8080,
            "method": parts.scheme or "https", "sso": "1",
            "subdomain": (urlsplit(isp.public_url).hostname or "").split(".")[0] if isp.public_url else ""}


@bp.get("/<int:isp_id>")
@login_required
def detail(isp_id: int):
    isp = _get(isp_id, LEVEL_VIEW)
    tab = request.args.get("tab", "overview")
    if tab not in TABS:
        tab = "overview"
    ctx: dict = {"i": isp, "tab": tab, "tabs": TABS, "error": None, "clients": [], "sites": [], "domains": [],
                 "boxes": [], "zones": [], "dbs": []}
    if tab in ("clients", "sites", "mail", "dns", "databases"):
        try:
            with integrations.ispconfig_client(isp) as api:
                if tab == "clients":
                    ctx["clients"] = sorted(api.clients(), key=lambda c: (c.get("company_name") or
                                                                         c.get("contact_name") or "").lower())
                elif tab == "sites":
                    ctx["sites"] = sorted(api.websites(), key=lambda w: w.get("domain", ""))
                elif tab == "mail":
                    ctx["domains"] = sorted(api.mail_domains(), key=lambda d: d.get("domain", ""))
                    ctx["boxes"] = sorted(api.mailboxes(), key=lambda b: b.get("email", ""))
                elif tab == "dns":
                    ctx["zones"] = sorted(api.dns_zones(), key=lambda z: z.get("origin", ""))
                elif tab == "databases":
                    ctx["dbs"] = sorted(api.databases(), key=lambda d: d.get("database_name", ""))
        except (IspError, ValueError) as exc:
            ctx["error"] = str(exc)
    system = g.db.get(System, isp.system_id) if isp.system_id else None
    ctx.update(system=system, publish=_publish_args(isp), pangolin=primary_pangolin())
    return render_template("ispconfig/detail.html", **ctx)


ACTIONS = {"client_add": LEVEL_FULL, "site_active": LEVEL_OPERATE, "mb_add": LEVEL_FULL,
           "mb_password": LEVEL_FULL, "mb_delete": LEVEL_FULL}


@bp.post("/<int:isp_id>/do")
@login_required
def do(isp_id: int):
    action = request.form.get("action", "")
    if action not in ACTIONS:
        abort(400)
    isp = _get(isp_id, ACTIONS[action])
    f = request.form
    tab = {"client_add": "clients", "site_active": "sites"}.get(action, "mail")
    target = ""
    try:
        with integrations.ispconfig_client(isp) as api:
            if action == "client_add":
                pw = f.get("password") or random_password(16)
                cid = api.add_client(f.get("company", ""), f.get("contact", ""), (f.get("email") or "").strip(),
                                     (f.get("username") or "").strip().lower(), pw)
                target = f.get("username", "")
                msg = f"Kunde {target} angelegt (ID {cid})." + ("" if f.get("password") else
                                                              f" Passwort (wird nur jetzt angezeigt): {pw}")
            elif action == "site_active":
                site = next((w for w in api.websites() if str(w.get("domain_id")) == f.get("id")), None)
                if site is None:
                    raise IspError("Webseite nicht gefunden")
                active = f.get("active") == "1"
                api.set_website_active(site, active)
                target = site.get("domain", "")
                msg = f"{target} {'aktiviert' if active else 'deaktiviert'}."
            elif action == "mb_add":
                domain = next((d for d in api.mail_domains() if str(d.get("domain_id")) == f.get("domain_id")), None)
                if domain is None:
                    raise IspError("Mail-Domain nicht gefunden")
                pw = f.get("password") or random_password(16)
                if len(pw) < 10:
                    raise IspError("Passwort mindestens 10 Zeichen")
                api.add_mailbox(domain, f.get("local", ""), (f.get("name") or "").strip(), pw,
                                int(f.get("quota") or 2048))
                target = f"{(f.get('local') or '').strip().lower()}@{domain['domain']}"
                msg = f"Postfach {target} angelegt." + ("" if f.get("password") else
                                                        f" Passwort (wird nur jetzt angezeigt): {pw}")
            else:
                box = next((b for b in api.mailboxes() if str(b.get("mailuser_id")) == f.get("id")), None)
                if box is None:
                    raise IspError("Postfach nicht gefunden")
                target = box.get("email", "")
                if action == "mb_password":
                    pw = random_password(16)
                    api.set_mailbox_password(box, pw)
                    msg = f"Neues Passwort für {target} (wird nur jetzt angezeigt): {pw}"
                else:
                    api.delete_mailbox(int(box["mailuser_id"]))
                    msg = f"Postfach {target} gelöscht."
        audit(g.db, g.user, f"ispconfig.{action}", isp.name, target, ip=client_ip())
        g.db.commit()
        flash(msg, "success")
    except (IspError, ValueError) as exc:
        flash(f"Fehlgeschlagen: {exc}", "danger")
    return redirect(url_for("ispc.detail", isp_id=isp_id, tab=tab))
