"""Login / logout / second factor."""
from __future__ import annotations

import time

from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for
from sqlalchemy import func, select

import secrets

from ... import integrations, security, sso_login
from ...authentik import AuthentikError
from ...core import audit
from ...models import User, utcnow
from ..auth import client_ip, login_user, logout_user, record_failure, throttled

bp = Blueprint("auth", __name__)
LOCK_AFTER = 8
LOCK_MINUTES = 15


def _safe_next(target: str | None) -> str:
    from ..auth import is_local_path
    if is_local_path(target):
        return target  # type: ignore[return-value]
    return url_for("main.dashboard")


def _login_page(status: int = 200, **ctx):
    try:
        conf = sso_login.active(g.db)
    except Exception:  # noqa: BLE001 - the password login must always work
        conf = None
    return render_template("login.html", sso_name=conf[0].name if conf else "", **ctx), status


def _finish_login(user: User, nxt: str | None, how: str):
    """Second factor if set up, otherwise the session starts."""
    if user.totp_enabled:
        session.clear()
        session["pending_uid"] = user.id
        session["pending_at"] = int(time.time())
        session["pending_next"] = _safe_next(nxt)
        g.db.commit()
        return redirect(url_for("auth.login_2fa"))
    login_user(user)
    audit(g.db, user, "auth.login", user.username, how, ip=client_ip())
    g.db.commit()
    return redirect(_safe_next(nxt))


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("main.dashboard"))
    if request.method == "POST":
        ip = client_ip()
        if throttled(ip):
            flash("Zu viele fehlgeschlagene Anmeldungen. Bitte einige Minuten warten.", "danger")
            return _login_page(429)
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = g.db.execute(select(User).where(func.lower(User.username) == username.lower())).scalar_one_or_none()
        now = utcnow()
        if user and user.locked_until and user.locked_until > now:
            # same answer as a wrong password: does not reveal that the account exists or is locked
            record_failure(ip)
            audit(g.db, None, "auth.failed", username[:64], "Konto gesperrt", ip=ip)
            g.db.commit()
            time.sleep(0.5)
            flash("Benutzername oder Passwort falsch (nach mehreren Fehlversuchen ist das Konto kurz gesperrt).",
                  "danger")
            return _login_page(401, username=username)
        ok = bool(user and user.active and security.verify_password(user.password_hash, password))
        if not ok:
            record_failure(ip)
            if user:
                user.failed_logins = (user.failed_logins or 0) + 1
                if user.failed_logins >= LOCK_AFTER:
                    from datetime import timedelta
                    user.locked_until = now + timedelta(minutes=LOCK_MINUTES)
                    user.failed_logins = 0
                    audit(g.db, user, "auth.locked", user.username, ip=ip)
            audit(g.db, None, "auth.failed", username[:64], ip=ip)
            g.db.commit()
            time.sleep(0.5)
            flash("Benutzername oder Passwort falsch.", "danger")
            return _login_page(401, username=username)
        if security.password_needs_rehash(user.password_hash):
            user.password_hash = security.hash_password(password)
        if user.sso_groups:
            # rights through authentik groups only for logins through authentik (removals there take effect)
            user.sso_groups, user.sso_groups_at = [], None
        return _finish_login(user, request.args.get("next"), "")
    return _login_page()


@bp.get("/login/sso")
def login_sso():
    if g.user:
        # e.g. a tile in the authentik portal pointing here while the session is still valid
        return redirect(_safe_next(request.args.get("next")))
    conf = sso_login.active(g.db)
    if conf is None:
        flash("Die Anmeldung per SSO ist nicht eingerichtet.", "warning")
        return redirect(url_for("auth.login"))
    srv, client = conf
    try:
        au = integrations.sso_client(srv)
    except (AuthentikError, ValueError) as exc:
        flash(f"SSO nicht verfügbar: {exc}", "danger")
        return redirect(url_for("auth.login"))
    verifier, challenge = sso_login.pkce()
    state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    session.clear()
    session["sso"] = {"state": state, "nonce": nonce, "verifier": verifier, "at": int(time.time()),
                      "next": _safe_next(request.args.get("next")), "client": client.id}
    return redirect(sso_login.authorize_url(au, client, state, nonce, challenge))


@bp.get("/login/sso/callback")
def login_sso_callback():
    pending = session.pop("sso", None) or {}
    ip = client_ip()

    def fail(msg: str, detail: str = ""):
        record_failure(ip)
        audit(g.db, None, "auth.sso_failed", (detail or msg)[:200], ip=ip)
        g.db.commit()
        flash(msg, "danger")
        return redirect(url_for("auth.login"))
    if throttled(ip):
        flash("Zu viele fehlgeschlagene Anmeldungen. Bitte einige Minuten warten.", "danger")
        return redirect(url_for("auth.login"))
    state = request.args.get("state", "")
    if (not pending or not state or not secrets.compare_digest(state, str(pending.get("state", "")))
            or time.time() - pending.get("at", 0) > sso_login.STATE_TTL):
        return fail("Die SSO-Anmeldung ist abgelaufen oder ungültig – bitte erneut versuchen.")
    if request.args.get("error"):
        err = request.args.get("error_description") or request.args.get("error")
        return fail(f"authentik hat die Anmeldung abgebrochen: {err[:200]}")
    conf = sso_login.active(g.db)
    if conf is None or conf[1].id != pending.get("client"):
        return fail("Die Anmeldung per SSO ist nicht (mehr) eingerichtet.")
    srv, client = conf
    try:
        info = sso_login.exchange(integrations.sso_client(srv), client, request.args.get("code", ""),
                                  pending.get("verifier", ""), pending.get("nonce", ""))
        user, created = sso_login.resolve_user(g.db, info)
    except (AuthentikError, sso_login.LoginError, ValueError) as exc:
        g.db.rollback()
        return fail(str(exc))
    if user.locked_until and user.locked_until > utcnow():
        return fail("Das Konto ist vorübergehend gesperrt.", user.username)
    if created:
        audit(g.db, user, "user.create", user.username, f"automatisch per SSO ({srv.name})", ip=ip)
    user.sso_groups = sso_login.groups_of(info)
    user.sso_groups_at = utcnow()
    return _finish_login(user, pending.get("next"), f"SSO {srv.name}")


@bp.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    uid = session.get("pending_uid")
    if not uid or time.time() - session.get("pending_at", 0) > 300:
        session.clear()
        return redirect(url_for("auth.login"))
    user = g.db.get(User, uid)
    if user is None or not user.active:
        session.clear()
        return redirect(url_for("auth.login"))
    if request.method == "POST":
        ip = client_ip()
        if throttled(ip):
            flash("Zu viele Fehlversuche. Bitte einige Minuten warten.", "danger")
            return render_template("login_2fa.html"), 429
        code = request.form.get("code", "")
        secret = security.decrypt(user.totp_secret_enc)
        step = security.totp_step(secret, code, user.totp_last_step)
        if step is None or (user.locked_until and user.locked_until > utcnow()):
            # wrong (or already used) codes count towards the account lock like wrong passwords
            record_failure(ip)
            user.failed_logins = (user.failed_logins or 0) + 1
            if user.failed_logins >= LOCK_AFTER:
                from datetime import timedelta
                user.locked_until = utcnow() + timedelta(minutes=LOCK_MINUTES)
                user.failed_logins = 0
                session.clear()
                audit(g.db, user, "auth.locked", user.username, ip=ip)
            audit(g.db, user, "auth.2fa_failed", user.username, ip=ip)
            g.db.commit()
            time.sleep(0.5)
            flash("Der Code ist ungültig oder wurde bereits verwendet.", "danger")
            if not session.get("pending_uid"):
                return redirect(url_for("auth.login"))
            return render_template("login_2fa.html"), 401
        user.totp_last_step = step
        nxt = session.get("pending_next")
        login_user(user)
        audit(g.db, user, "auth.login", user.username, "2FA", ip=ip)
        g.db.commit()
        return redirect(_safe_next(nxt))
    return render_template("login_2fa.html")


@bp.route("/logout", methods=["POST"])
def logout():
    if g.user:
        # invalidates this session everywhere (also a copied cookie); other sessions of the user end too
        g.user.auth_version = (g.user.auth_version or 1) + 1
        audit(g.db, g.user, "auth.logout", g.user.username, ip=client_ip())
        g.db.commit()
    logout_user()
    flash("Abgemeldet.", "info")
    return redirect(url_for("auth.login"))
