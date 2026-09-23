"""Login / logout / second factor."""
from __future__ import annotations

import time

from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for
from sqlalchemy import func, select

from ... import security
from ...core import audit
from ...models import User, utcnow
from ..auth import client_ip, login_user, logout_user, record_failure, throttled

bp = Blueprint("auth", __name__)
LOCK_AFTER = 8
LOCK_MINUTES = 15


def _safe_next(target: str | None) -> str:
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return url_for("main.dashboard")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("main.dashboard"))
    if request.method == "POST":
        ip = client_ip()
        if throttled(ip):
            flash("Zu viele fehlgeschlagene Anmeldungen. Bitte einige Minuten warten.", "danger")
            return render_template("login.html"), 429
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = g.db.execute(select(User).where(func.lower(User.username) == username.lower())).scalar_one_or_none()
        now = utcnow()
        if user and user.locked_until and user.locked_until > now:
            record_failure(ip)
            flash("Das Konto ist vorübergehend gesperrt. Bitte später erneut versuchen.", "danger")
            return render_template("login.html", username=username), 403
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
            return render_template("login.html", username=username), 401
        if security.password_needs_rehash(user.password_hash):
            user.password_hash = security.hash_password(password)
        if user.totp_enabled:
            session.clear()
            session["pending_uid"] = user.id
            session["pending_at"] = int(time.time())
            session["pending_next"] = _safe_next(request.args.get("next"))
            g.db.commit()
            return redirect(url_for("auth.login_2fa"))
        login_user(user)
        audit(g.db, user, "auth.login", user.username, ip=ip)
        g.db.commit()
        return redirect(_safe_next(request.args.get("next")))
    return render_template("login.html")


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
        if not security.verify_totp(secret, code):
            record_failure(ip)
            audit(g.db, user, "auth.2fa_failed", user.username, ip=ip)
            g.db.commit()
            flash("Der Code ist ungültig.", "danger")
            return render_template("login_2fa.html"), 401
        nxt = session.get("pending_next")
        login_user(user)
        audit(g.db, user, "auth.login", user.username, "2FA", ip=ip)
        g.db.commit()
        return redirect(_safe_next(nxt))
    return render_template("login_2fa.html")


@bp.route("/logout", methods=["POST"])
def logout():
    if g.user:
        audit(g.db, g.user, "auth.logout", g.user.username, ip=client_ip())
        g.db.commit()
    logout_user()
    flash("Abgemeldet.", "info")
    return redirect(url_for("auth.login"))
