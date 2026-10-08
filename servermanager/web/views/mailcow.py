"""Mailcow: mailboxes, aliases, domains; own public IP for IMAP/SMTP; web UI via Pangolin."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from sqlalchemy import select

from ... import access, integrations, security
from ...core import audit
from ...dnsapi import DnsError
from ...mailcow import MailcowError
from ...models import (KIND_MAILCOW, LEVEL_FULL, LEVEL_OPERATE, LEVEL_VIEW, MAIL_PORTS_DEFAULT, MailcowServer,
                       RouterDevice, SsoClient, System)
from ..auth import admin_required, client_ip, login_required
from . import _integration as common

bp = Blueprint("mailcow", __name__, url_prefix="/mailcow")
TABS = {"mailboxes": "Postfächer", "aliases": "Aliase", "domains": "Domains", "mail": "Mail-IP & Veröffentlichung",
        "dns": "DNS"}


def _get(mc_id: int, level: str) -> MailcowServer:
    return common.get_or_403(KIND_MAILCOW, mc_id, level)


def _client(mc: MailcowServer):
    try:
        return integrations.mailcow_client(mc)
    except (MailcowError, ValueError) as exc:
        abort(400, description=f"Mailcow-Verbindung unvollständig: {exc}")


@bp.get("/")
@login_required
def index():
    items = common.visible(KIND_MAILCOW)
    if not items and not g.user.is_admin:
        abort(403)
    return render_template("mailcow/index.html", items=items)


def _ip(value: str, label: str, errors: list) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        errors.append(f"{label}: ungültige IP-Adresse")
        return ""


def _save(mc: MailcowServer) -> list[str]:
    f = request.form
    errors = common.save_common(mc, f, 443)
    if f.get("api_key"):
        mc.api_key_enc = security.encrypt(f["api_key"].strip())
    elif not mc.api_key_enc:
        errors.append("API-Schlüssel angeben (Mailcow → Konfiguration → Zugang → API, Lese-/Schreibzugriff).")
    pub = (f.get("public_url") or "").strip().rstrip("/")
    if pub and not re.match(r"^https://[A-Za-z0-9.-]+(:\d+)?$", pub):
        errors.append("Öffentliche Adresse als https://webmail.example.com angeben.")
    mc.public_url = pub
    host = (f.get("mail_hostname") or "").strip().lower()
    if host and not re.match(r"^(?=.{1,253}$)[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$", host):
        errors.append("Ungültiger Mail-Hostname")
    mc.mail_hostname = host
    mc.mail_public_ip = _ip(f.get("mail_public_ip"), "Mail-IP", errors)
    internal = f.get("mail_internal_ip") or (urlsplit(mc.api_url).hostname if mc.api_url else "")
    mc.mail_internal_ip = _ip(internal, "Interne Adresse", errors) if internal and re.match(r"^[0-9a-f.:]+$", internal) \
        else ""
    ports = (f.get("mail_ports") or MAIL_PORTS_DEFAULT).replace(" ", "")
    if not re.match(r"^\d{1,5}(,\d{1,5})*$", ports) or any(not 0 < int(p) < 65536 for p in ports.split(",")):
        errors.append("Ports als Liste, z. B. 25,465,587,993")
    mc.mail_ports = ports
    # one name for both only breaks mail once the web interface really runs through Pangolin: its DNS
    # record then points to Pangolin instead of the mail IP
    web_host = urlsplit(mc.public_url).hostname if mc.public_url else ""
    if web_host and mc.mail_hostname and web_host == mc.mail_hostname:
        via = integrations.published_via_pangolin(g.db, web_host)
        if via:
            errors.append(f"{web_host} ist über Pangolin ({via}) veröffentlicht und zeigt damit auf Pangolin – der "
                          "Mailserver braucht einen eigenen Namen auf seiner eigenen IP, z. B. webmail.example.com "
                          "für die Weboberfläche und mail.example.com für den Mailserver.")
    for attr, model, key in (("system_id", System, "system_id"), ("router_id", RouterDevice, "router_id")):
        raw = f.get(key, "")
        setattr(mc, attr, int(raw) if raw.isdigit() and g.db.get(model, int(raw)) else None)
    return errors


def _form(mc: MailcowServer, is_new: bool):
    return render_template("mailcow/form.html", m=mc, is_new=is_new,
                           systems=g.db.execute(select(System).order_by(System.name)).scalars().all(),
                           routers=g.db.execute(select(RouterDevice).order_by(RouterDevice.name)).scalars().all(),
                           default_ports=MAIL_PORTS_DEFAULT)


@bp.route("/new", methods=["GET", "POST"])
@admin_required
def new():
    mc = MailcowServer(monitor=True, verify_ca=False, mail_ports=MAIL_PORTS_DEFAULT)
    if request.method == "POST":
        errors = _save(mc)
        if request.form.get("fetch_fp"):
            fp, err = common.fetch_fp_from_form(443)
            flash(err or "Fingerabdruck abgerufen – bitte vergleichen und speichern.", "danger" if err else "info")
            mc.fingerprint = fp or mc.fingerprint
            return _form(mc, True)
        if errors:
            for e in errors:
                flash(e, "danger")
            return _form(mc, True)
        g.db.add(mc)
        g.db.flush()
        audit(g.db, g.user, "mailcow.create", mc.name, mc.api_url, ip=client_ip())
        integrations.poll(g.db, mc)
        g.db.commit()
        flash("Mailcow-Verbindung angelegt.", "success")
        return redirect(url_for("mailcow.detail", mc_id=mc.id))
    return _form(mc, True)


@bp.route("/<int:mc_id>/edit", methods=["GET", "POST"])
@admin_required
def edit(mc_id: int):
    mc = _get(mc_id, LEVEL_FULL)
    if request.method == "POST":
        if request.form.get("fetch_fp"):
            g.db.expunge(mc)
            _save(mc)
            fp, err = common.fetch_fp_from_form(443)
            flash(err or "Fingerabdruck abgerufen.", "danger" if err else "info")
            mc.fingerprint = fp or mc.fingerprint
            return _form(mc, False)
        errors = _save(mc)
        if errors:
            g.db.rollback()
            for e in errors:
                flash(e, "danger")
            return redirect(url_for("mailcow.edit", mc_id=mc_id))
        audit(g.db, g.user, "mailcow.update", mc.name, ip=client_ip())
        integrations.poll(g.db, mc)
        g.db.commit()
        flash("Gespeichert.", "success")
        return redirect(url_for("mailcow.detail", mc_id=mc.id))
    return _form(mc, False)


@bp.post("/<int:mc_id>/delete")
@admin_required
def delete(mc_id: int):
    mc = _get(mc_id, LEVEL_FULL)
    access.remove_integration(g.db, KIND_MAILCOW, mc.id)
    for c in g.db.execute(select(SsoClient).where(SsoClient.target_kind == "mailcow",
                                                  SsoClient.target_id == mc.id)).scalars():
        g.db.delete(c)
    audit(g.db, g.user, "mailcow.delete", mc.name, ip=client_ip())
    g.db.delete(mc)
    g.db.commit()
    flash("Mailcow-Verbindung entfernt (Mailcow selbst bleibt unverändert).", "warning")
    return redirect(url_for("mailcow.index"))


@bp.get("/<int:mc_id>")
@login_required
def detail(mc_id: int):
    mc = _get(mc_id, LEVEL_VIEW)
    tab = request.args.get("tab", "mailboxes")
    if tab not in TABS:
        tab = "mailboxes"
    ctx: dict = {"m": mc, "tab": tab, "tabs": TABS, "error": None, "mailboxes": [], "aliases": [], "domains": []}
    try:
        client = _client(mc)
        ctx["domains"] = client.domains()
        if tab == "mailboxes":
            ctx["mailboxes"] = sorted(client.mailboxes(), key=lambda b: b.get("username", ""))
        elif tab == "aliases":
            ctx["aliases"] = sorted(client.aliases(), key=lambda a: a.get("address", ""))
        elif tab == "dns":
            ctx["dns_rows"], ctx["dns_accounts"] = _mail_dns(mc, client, ctx["domains"])
    except (MailcowError, DnsError) as exc:
        ctx["error"] = str(exc)
    ctx["sso"] = g.db.execute(select(SsoClient).where(SsoClient.target_kind == "mailcow",
                                                      SsoClient.target_id == mc.id)).scalars().first()
    ctx["router"] = g.db.get(RouterDevice, mc.router_id) if mc.router_id else None
    ctx["publish"] = _publish_args(mc)
    ctx["pangolin"] = primary_pangolin()
    host = g.db.get(System, mc.system_id) if mc.system_id else None
    ctx["host"] = host if host is not None and access.system_level(g.db, g.user, host.id) else None
    return render_template("mailcow/detail.html", **ctx)


def _dns_accounts(level: str = LEVEL_VIEW) -> list:
    from ...models import KIND_DNS, DnsAccount
    return [a for a in g.db.execute(select(DnsAccount).order_by(DnsAccount.name)).scalars()
            if common.can(KIND_DNS, a.id, level)]


def _mail_dns(mc: MailcowServer, client, domains: list[dict]) -> tuple[list[dict], list]:
    """Expected mail records of all active Mailcow domains compared with the managed zones."""
    from ... import dnscheck
    accounts = _dns_accounts()
    if not accounts:
        return [], []
    names = [str(d.get("domain_name") or "") for d in domains if str(d.get("active", 1)) not in ("0", "False", "false")]
    dkim = {}
    for n in names:
        try:
            dkim[n.lower()] = client.dkim(n)
        except MailcowError:
            dkim[n.lower()] = {}
    zones = dnscheck.Zones(g.db, accounts)
    try:
        return dnscheck.mail_rows(zones, mc, names, dkim), accounts
    finally:
        zones.close()


@bp.post("/<int:mc_id>/dns-fix")
@login_required
def dns_fix(mc_id: int):
    """Write one proposed mail record – the row is computed again from its key, nothing is taken from the form."""
    from ... import dnscheck
    from ...models import KIND_DNS
    mc = _get(mc_id, LEVEL_VIEW)
    key = request.form.get("key", "")
    try:
        client = _client(mc)
        domains = client.domains()
        rows, accounts = _mail_dns(mc, client, domains)
        row = next((r for r in rows if r["key"] == key), None)
        if row is None or row["state"] not in ("missing", "wrong") or not row["account_id"]:
            raise DnsError("Für diesen Eintrag gibt es nichts zu tun – Seite neu laden")
        need = LEVEL_OPERATE if row["state"] == "missing" else LEVEL_FULL
        if not common.can(KIND_DNS, row["account_id"], need):
            raise DnsError("Dafür fehlt das Recht auf die DNS-Verbindung ("
                           + ("Bedienen" if need == LEVEL_OPERATE else "Vollzugriff") + ")")
        account = next(a for a in accounts if a.id == row["account_id"])
        zones = dnscheck.Zones(g.db, accounts)
        try:
            rec, replaces = dnscheck.mail_fix_record(row, account.default_ttl or 3600)
            msg = dnscheck.fix(zones, row, rec, replaces)
        finally:
            zones.close()
        audit(g.db, g.user, "dns.mail_fix", mc.name, msg[:300], ip=client_ip())
        g.db.commit()
        flash(msg, "success")
    except (MailcowError, DnsError) as exc:
        flash(f"Fehlgeschlagen: {exc}", "danger")
    return redirect(url_for("mailcow.detail", mc_id=mc_id, tab="dns"))


def primary_pangolin():
    from ...models import KIND_PANGOLIN, PangolinServer
    for p in g.db.execute(select(PangolinServer).where(PangolinServer.role == "primary")
                          .order_by(PangolinServer.id)).scalars():
        if common.can(KIND_PANGOLIN, p.id, LEVEL_FULL):
            return p
    return None


def _publish_args(mc: MailcowServer) -> dict:
    parts = urlsplit(mc.api_url or "")
    return {"name": f"Mailcow {mc.name}", "ip": parts.hostname or "", "port": parts.port or 443,
            "method": "https", "sso": "0", "subdomain": (urlsplit(mc.public_url).hostname or "").split(".")[0]
            if mc.public_url else ""}


ACTIONS = {"mb_add": LEVEL_FULL, "mb_delete": LEVEL_FULL, "mb_active": LEVEL_OPERATE, "mb_password": LEVEL_FULL,
           "mb_edit": LEVEL_FULL,
           "alias_add": LEVEL_FULL, "alias_delete": LEVEL_FULL}


@bp.post("/<int:mc_id>/do")
@login_required
def do(mc_id: int):
    action = request.form.get("action", "")
    if action not in ACTIONS:
        abort(400)
    mc = _get(mc_id, ACTIONS[action])
    client = _client(mc)
    f = request.form
    tab = "aliases" if action.startswith("alias") else "mailboxes"
    try:
        address = (f.get("address") or "").strip().lower()
        if action == "mb_add":
            pw = f.get("password") or security.generate_password()
            quota = int(f.get("quota") or 3072)
            address = client.add_mailbox(f.get("local", ""), f.get("domain", ""), f.get("name", "").strip(), pw,
                                         quota, force_pw_update=bool(f.get("force_pw_update")))
            msg = f"Postfach {address} angelegt." + ("" if f.get("password") else
                                                     f" Passwort (wird nur jetzt angezeigt): {pw}")
        elif action == "mb_active":
            client.set_mailbox(address, active="1" if f.get("active") == "1" else "0")
            msg = f"{address} {'aktiviert' if f.get('active') == '1' else 'deaktiviert'}."
        elif action == "mb_edit":
            quota = int(f.get("quota") or 0)
            client.edit_mailbox(address, quota, f.get("name", ""))
            address = f"{address}: {quota} MB, Name „{f.get('name', '').strip()}“"
            msg = f"Postfach {address.split(':')[0]} geändert: Größe {quota} MB" + (" (unbegrenzt)" if quota == 0 else "") + "."
        elif action == "mb_password":
            pw = security.generate_password()
            client.set_password(address, pw)
            msg = f"Neues Passwort für {address} (wird nur jetzt angezeigt): {pw}"
        elif action == "mb_delete":
            client.delete_mailbox(address)
            msg = f"Postfach {address} gelöscht."
        elif action == "alias_add":
            client.add_alias(address, f.get("goto", ""))
            msg = f"Alias {address} angelegt."
        else:
            client.delete_alias(f.get("id", ""))
            msg = "Alias gelöscht."
        audit(g.db, g.user, f"mailcow.{action}", mc.name, address, ip=client_ip())
        g.db.commit()
        flash(msg, "success")
    except (MailcowError, ValueError) as exc:
        flash(f"Fehlgeschlagen: {exc}", "danger")
    return redirect(url_for("mailcow.detail", mc_id=mc_id, tab=tab))
