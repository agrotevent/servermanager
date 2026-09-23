"""Session based authentication, CSRF protection and permission decorators."""
from __future__ import annotations

import functools
import secrets
import time
from collections import defaultdict, deque
from datetime import timedelta
from typing import Callable, Optional

from flask import abort, flash, g, redirect, request, session, url_for

from .. import access, settings
from ..models import LEVEL_ORDER, System, User, utcnow

CSRF_EXEMPT_PREFIXES = ("/api/enroll", "/enroll/", "/healthz", "/static/")
_failures: dict[str, deque] = defaultdict(deque)


# --------------------------------------------------------------------------
# login throttling (per client IP, in memory)
# --------------------------------------------------------------------------
def throttled(ip: str, limit: int = 10, window: int = 600) -> bool:
    q = _failures[ip]
    now = time.monotonic()
    while q and now - q[0] > window:
        q.popleft()
    return len(q) >= limit


def record_failure(ip: str) -> None:
    _failures[ip].append(time.monotonic())


# --------------------------------------------------------------------------
# session
# --------------------------------------------------------------------------
def login_user(user: User) -> None:
    session.clear()
    session["uid"] = user.id
    session["av"] = user.auth_version
    session["at"] = int(time.time())
    session["csrf"] = secrets.token_urlsafe(32)
    session.permanent = True
    user.last_login = utcnow()
    user.failed_logins = 0
    user.locked_until = None


def logout_user() -> None:
    session.clear()


def load_user() -> None:
    g.user = None
    uid = session.get("uid")
    if not uid:
        return
    user = g.db.get(User, uid)
    hours = int(settings.get(g.db, "general.session_hours") or 12)
    if (user is None or not user.active or session.get("av") != user.auth_version
            or time.time() - session.get("at", 0) > hours * 3600):
        session.clear()
        return
    g.user = user


def csrf_token() -> str:
    tok = session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["csrf"] = tok
    return tok


def check_csrf() -> None:
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    if request.path.startswith(CSRF_EXEMPT_PREFIXES):
        return
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
    expected = session.get("csrf", "")
    if not expected or not secrets.compare_digest(sent, expected):
        abort(400, description="Ungültiges oder abgelaufenes Formular (CSRF). Bitte Seite neu laden.")


# --------------------------------------------------------------------------
# decorators
# --------------------------------------------------------------------------
def login_required(fn: Callable) -> Callable:
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if g.get("user") is None:
            if request.path.startswith("/jobs/") and request.path.endswith("/log"):
                abort(401)
            return redirect(url_for("auth.login", next=request.full_path if request.method == "GET" else None))
        user: User = g.user
        if user.must_change_password and request.endpoint not in ("main.profile", "main.change_password",
                                                                   "auth.logout"):
            flash("Bitte zuerst ein neues Passwort festlegen.", "warning")
            return redirect(url_for("main.profile"))
        if (user.is_admin and not user.totp_enabled and settings.get(g.db, "general.require_2fa_admin")
                and request.endpoint not in ("main.profile", "main.totp_setup", "main.totp_enable",
                                             "main.change_password", "auth.logout")):
            flash("Für Administratoren ist die Zwei-Faktor-Anmeldung vorgeschrieben. Bitte jetzt einrichten.",
                  "warning")
            return redirect(url_for("main.profile"))
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn: Callable) -> Callable:
    @functools.wraps(fn)
    @login_required
    def wrapper(*args, **kwargs):
        if not g.user.is_admin:
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


def manager_required(fn: Callable) -> Callable:
    @functools.wraps(fn)
    @login_required
    def wrapper(*args, **kwargs):
        if not g.user.can_add_systems:
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


def get_system_or_403(system_id: int, level: str) -> System:
    system = g.db.get(System, system_id)
    if system is None:
        abort(404)
    if not access.has_level(g.db, g.user, system.id, level):
        abort(403)
    return system


def level_of(system_id: int) -> Optional[str]:
    cache = g.setdefault("_levels", {})
    if system_id not in cache:
        cache[system_id] = access.system_level(g.db, g.user, system_id)
    return cache[system_id]


def can(system_id: int, level: str) -> bool:
    lv = level_of(system_id)
    return bool(lv) and LEVEL_ORDER[lv] >= LEVEL_ORDER[level]


def client_ip() -> str:
    return request.remote_addr or ""


def session_lifetime(hours: int) -> timedelta:
    return timedelta(hours=hours)
