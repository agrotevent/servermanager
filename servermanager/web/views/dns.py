"""DNS & domains at the registrar (hosting.de platform, INWX): domains, zones, records, checks."""
from __future__ import annotations

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from sqlalchemy import select

from ... import access, dnscheck, integrations, security
from ...core import audit
from ...dnsapi import DEFAULT_URLS, PROVIDERS, RECORD_TYPES, DnsError, days_left, fqdn, normalize_url, validate_record
from ...models import KIND_DNS, KIND_PANGOLIN, LEVEL_FULL, LEVEL_OPERATE, LEVEL_VIEW, DnsAccount, PangolinServer
from ..auth import admin_required, client_ip, login_required
from . import _integration as common

bp = Blueprint("dns", __name__, url_prefix="/dns")
TABS = {"domains": "Domains", "zones": "Zonen", "check": "Prüfung"}


def _get(did: int, level: str) -> DnsAccount:
    return common.get_or_403(KIND_DNS, did, level)


def _client(a: DnsAccount):
    try:
        return integrations.dns_client(a)
    except (DnsError, ValueError) as exc:
        abort(400, description=f"DNS-Verbindung unvollständig: {exc}")


@bp.get("/")
@login_required
def index():
    items = common.visible(KIND_DNS)
    if not items and not g.user.is_admin:
        abort(403)
    return render_template("dns/index.html", items=items, providers=PROVIDERS)


def _save(a: DnsAccount) -> list[str]:
    f = request.form
    a.provider = f.get("provider") if f.get("provider") in PROVIDERS else "hostingde"
    errors = common.save_common(a, f, 443)
    try:
        a.api_url = normalize_url(f.get("api_url", ""), a.provider)
    except DnsError as exc:
        errors.append(str(exc))
    if a.provider == "inwx":
        a.username = (f.get("username") or "").strip()[:128]
        if not a.username:
            errors.append("INWX-Benutzernamen angeben.")
        if f.get("totp"):
            a.totp_enc = security.encrypt(f["totp"].replace(" ", "").strip())
        elif f.get("totp_remove"):
            a.totp_enc = None
    else:
        a.username, a.totp_enc = "", None
    if f.get("secret"):
        a.secret_enc = security.encrypt(f["secret"].strip())
    elif not a.secret_enc:
        errors.append("API-Schlüssel angeben." if a.provider == "hostingde" else "Passwort angeben.")
    try:
        a.default_ttl = max(300, min(86400, int(f.get("default_ttl") or 3600)))
        a.expiry_days = max(1, min(365, int(f.get("expiry_days") or 30)))
    except ValueError:
        errors.append("TTL und Vorwarnzeit als Zahl angeben.")
    a.auto_pangolin = bool(f.get("auto_pangolin"))
    return errors


def _form(a: DnsAccount, is_new: bool):
    return render_template("dns/form.html", a=a, is_new=is_new, providers=PROVIDERS, default_urls=DEFAULT_URLS)


@bp.route("/new", methods=["GET", "POST"])
@admin_required
def new():
    a = DnsAccount(provider=request.values.get("provider", "hostingde"), monitor=True, verify_ca=True,
                   auto_pangolin=True, default_ttl=3600, expiry_days=30)
    if a.provider not in PROVIDERS:
        a.provider = "hostingde"
    a.api_url = DEFAULT_URLS[a.provider]
    if request.method == "POST":
        errors = _save(a)
        if request.form.get("fetch_fp"):
            fp, err = common.fetch_fp_from_form(443)
            flash(err or "Fingerabdruck abgerufen – bitte vergleichen und speichern.", "danger" if err else "info")
            a.fingerprint = fp or a.fingerprint
            return _form(a, True)
        if errors:
            for e in errors:
                flash(e, "danger")
            return _form(a, True)
        g.db.add(a)
        g.db.flush()
        audit(g.db, g.user, "dns.create", a.name, f"{a.provider} {a.api_url}", ip=client_ip())
        integrations.poll(g.db, a)
        g.db.commit()
        if a.status_message:
            flash(f"Gespeichert, aber die Verbindung schlägt fehl: {a.status_message}", "warning")
        else:
            flash(f"Verbunden: {len(a.data.get('zones') or [])} Zone(n), {len(a.data.get('domains') or [])} Domain(s).",
                  "success")
        return redirect(url_for("dns.detail", did=a.id))
    return _form(a, True)


@bp.route("/<int:did>/edit", methods=["GET", "POST"])
@admin_required
def edit(did: int):
    a = _get(did, LEVEL_FULL)
    if request.method == "POST":
        if request.form.get("fetch_fp"):
            g.db.expunge(a)
            _save(a)
            fp, err = common.fetch_fp_from_form(443)
            flash(err or "Fingerabdruck abgerufen.", "danger" if err else "info")
            a.fingerprint = fp or a.fingerprint
            return _form(a, False)
        errors = _save(a)
        if errors:
            g.db.rollback()
            for e in errors:
                flash(e, "danger")
            return redirect(url_for("dns.edit", did=did))
        audit(g.db, g.user, "dns.update", a.name, ip=client_ip())
        integrations.poll(g.db, a)
        g.db.commit()
        flash("Gespeichert." + (f" Verbindung: {a.status_message}" if a.status_message else ""),
              "warning" if a.status_message else "success")
        return redirect(url_for("dns.detail", did=a.id))
    return _form(a, False)


@bp.post("/<int:did>/delete")
@admin_required
def delete(did: int):
    a = _get(did, LEVEL_FULL)
    access.remove_integration(g.db, KIND_DNS, a.id)
    audit(g.db, g.user, "dns.delete", a.name, ip=client_ip())
    g.db.delete(a)
    g.db.commit()
    flash("DNS-Verbindung entfernt (beim Anbieter ändert sich nichts).", "warning")
    return redirect(url_for("dns.index"))


@bp.post("/<int:did>/sync")
@login_required
def sync(did: int):
    a = _get(did, LEVEL_OPERATE)
    integrations.poll(g.db, a)
    g.db.commit()
    flash(a.status_message or "Aktualisiert.", "danger" if a.status_message else "success")
    return redirect(common.safe_next(url_for("dns.detail", did=did)))


@bp.get("/<int:did>")
@login_required
def detail(did: int):
    a = _get(did, LEVEL_VIEW)
    tab = request.args.get("tab", "domains")
    if tab not in TABS:
        tab = "domains"
    rows, error = [], None
    if tab == "check":
        zones = dnscheck.Zones(g.db, [a])
        try:
            pgs = [p for p in g.db.execute(select(PangolinServer).order_by(PangolinServer.name)).scalars()
                   if common.can(KIND_PANGOLIN, p.id, LEVEL_VIEW)]
            rows = dnscheck.pangolin_rows(g.db, zones, pgs)
        except DnsError as exc:
            error = str(exc)
        finally:
            zones.close()
    domains = []
    for d in a.data.get("domains") or []:
        domains.append({**d, "days": days_left(d.get("expires") or ""), "managed": d["name"] in (a.data.get("zones") or [])})
    return render_template("dns/detail.html", a=a, tab=tab, tabs=TABS, domains=domains, rows=rows, error=error,
                           providers=PROVIDERS)


@bp.get("/<int:did>/zone/<zone>")
@login_required
def zone(did: int, zone: str):
    a = _get(did, LEVEL_VIEW)
    zone = fqdn(zone)
    if zone not in (a.data.get("zones") or []):
        abort(404)
    records, error = [], None
    client = _client(a)
    try:
        records = client.records(zone)
    except DnsError as exc:
        error = str(exc)
    finally:
        client.close()
    for r in records:
        r["short"] = "@" if r["name"] == zone else r["name"][: -len(zone) - 1]
    return render_template("dns/zone.html", a=a, zone=zone, records=records, error=error, types=RECORD_TYPES)


@bp.post("/<int:did>/zone/<zone>/records")
@login_required
def record_action(did: int, zone: str):
    a = _get(did, LEVEL_FULL)
    zone = fqdn(zone)
    if zone not in (a.data.get("zones") or []):
        abort(404)
    f = request.form
    action = f.get("action", "")
    if action not in ("add", "edit", "delete"):
        abort(400)
    client = _client(a)
    try:
        current = client.records(zone)
        old = None
        if action in ("edit", "delete"):
            old = next((r for r in current if r["id"] and r["id"] == f.get("id")), None)
            if old is None:
                raise DnsError("Eintrag nicht gefunden – die Seite neu laden")
            if old["type"] == "NS" and old["name"] == zone:
                raise DnsError("Die NS-Einträge der Zone werden hier nicht geändert")
        if action == "delete":
            client.delete(zone, old)
            msg = f"{old['type']} {old['name']} gelöscht."
            detail = f"{old['type']} {old['name']} {old['content'][:100]}"
        else:
            rec = validate_record(zone, {k: f.get(k) for k in ("name", "type", "content", "ttl", "prio")})
            if action == "add":
                if any(r["name"] == rec["name"] and r["type"] == "CNAME" for r in current) or (
                        rec["type"] == "CNAME" and any(r["name"] == rec["name"] for r in current)):
                    raise DnsError("Neben einem CNAME darf es unter demselben Namen keine anderen Einträge geben")
                client.add(zone, rec)
                msg = f"{rec['type']} {rec['name']} angelegt."
            else:
                client.update(zone, old, rec)
                msg = f"{rec['type']} {rec['name']} geändert."
            detail = f"{rec['type']} {rec['name']} {rec['content'][:100]}"
        audit(g.db, g.user, f"dns.record_{action}", a.name, f"{zone}: {detail}", ip=client_ip())
        g.db.commit()
        flash(msg, "success")
    except DnsError as exc:
        flash(f"Fehlgeschlagen: {exc}", "danger")
    finally:
        client.close()
    return redirect(url_for("dns.zone", did=did, zone=zone))


@bp.post("/<int:did>/fix")
@login_required
def fix(did: int):
    """Create/replace a record proposed by the Pangolin check (computed again here, not taken from the form)."""
    a = _get(did, LEVEL_OPERATE)
    key = request.form.get("key", "")
    try:
        _p, pid, host = key.split(":", 2)
        pg = common.get_or_403(KIND_PANGOLIN, int(pid), LEVEL_VIEW)
    except ValueError:
        abort(400)
    zones = dnscheck.Zones(g.db, [a])
    try:
        row = dnscheck.check_host(zones, key, host, dnscheck.pangolin_target(pg))
        if row["account_id"] != a.id:
            abort(400)
        if row["state"] == "wrong" and not common.can(KIND_DNS, a.id, LEVEL_FULL):
            raise DnsError("Abweichende Einträge ersetzen erfordert Vollzugriff auf die DNS-Verbindung")
        rec = dnscheck.expected_host_record(host, dnscheck.pangolin_target(pg), row["zone"], a.default_ttl or 3600)
        msg = dnscheck.fix(zones, row, rec, ["A", "AAAA", "CNAME"])
        audit(g.db, g.user, "dns.fix", a.name, msg, ip=client_ip())
        g.db.commit()
        flash(msg, "success")
    except DnsError as exc:
        flash(f"Fehlgeschlagen: {exc}", "danger")
    finally:
        zones.close()
    return redirect(url_for("dns.detail", did=did, tab="check"))
