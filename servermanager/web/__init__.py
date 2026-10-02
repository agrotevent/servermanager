"""Flask application factory."""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

from flask import Flask, abort, g, render_template, request
from markupsafe import Markup, escape
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from .. import __version__, settings
from ..config import get_config
from ..core import bootstrap, setup_logging
from ..db import new_session
from ..models import (CONNECTIONS, JOB_STATUSES, LEVELS, ROLES, STATUSES, utcnow)
from ..modules import MODULES, TYPE_LABELS
from ..schedules import get_tz
from ..security import derive_key
from .auth import can, check_csrf, csrf_token, load_user


def create_app(testing: bool = False) -> Flask:
    setup_logging()
    bootstrap()
    cfg = get_config()
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config.update(
        SECRET_KEY=derive_key("flask-session"),
        SESSION_COOKIE_NAME="sm_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=cfg.secure_cookies and not testing,
        PERMANENT_SESSION_LIFETIME=timedelta(hours=24),
        MAX_CONTENT_LENGTH=2 * 1024 * 1024 * 1024,
        TESTING=testing,
        JSON_AS_ASCII=False,
    )
    if cfg.trusted_proxies and not testing:
        n = cfg.trusted_proxies
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=n, x_proto=n, x_host=n)  # type: ignore[method-assign]

    # endpoints reachable without a session only get small bodies (large uploads need a login)
    small_body_prefixes = ("/api/", "/enroll/", "/login")

    @app.before_request
    def _before():
        if request.path.startswith(small_body_prefixes):
            limit = 1024 * 1024
            request.max_content_length = limit
            if request.content_length is not None and request.content_length > limit:
                abort(413)
        g.db = new_session()
        load_user()
        check_csrf()

    @app.teardown_request
    def _teardown(exc):
        db = g.pop("db", None)
        if db is not None:
            if exc is not None:
                db.rollback()
            db.close()

    @app.after_request
    def _headers(resp):
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; "
            "frame-ancestors 'none'; form-action 'self'; base-uri 'self'")
        if request.path.startswith(("/jobs/", "/api/")) or resp.mimetype == "text/html":
            resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    @app.errorhandler(HTTPException)
    def _http_error(exc: HTTPException):
        if request.path.startswith("/api/") or request.accept_mimetypes.best == "application/json":
            return {"error": exc.description}, exc.code
        return render_template("error.html", code=exc.code, message=exc.description), exc.code

    # ---- template helpers ----------------------------------------------------
    @app.context_processor
    def _ctx():
        db = g.get("db")
        site = settings.get(db, "general.site_name") if db is not None else "Servermanager"
        return {
            "csrf_token": csrf_token, "can": can, "user": g.get("user"), "site_name": site,
            "version": __version__, "MODULES": MODULES, "TYPE_LABELS": TYPE_LABELS, "LEVELS": LEVELS,
            "ROLES": ROLES, "STATUSES": STATUSES, "JOB_STATUSES": JOB_STATUSES, "CONNECTIONS": CONNECTIONS,
            "now": utcnow(), "nav_integrations": _nav_integrations, "int_can": _int_can,
        }

    def _int_can(kind: str, obj_id: int, level: str) -> bool:
        from .views._integration import can as int_can
        return int_can(kind, obj_id, level)

    def _nav_integrations() -> set:
        if "nav_int" not in g:
            from .. import access
            g.nav_int = access.any_integration_access(g.db, g.user) if g.get("user") else set()
        return g.nav_int

    def _tz():
        if "tz" not in g:
            g.tz = get_tz(g.db) if g.get("db") is not None else timezone.utc
        return g.tz

    @app.template_filter("dt")
    def _dt(value: Optional[datetime], fmt: str = "%d.%m.%Y %H:%M") -> str:
        if not value:
            return "–"
        if isinstance(value, (int, float)):
            value = datetime.fromtimestamp(value, timezone.utc).replace(tzinfo=None)
        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value)
            except ValueError:
                return value
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(_tz()).strftime(fmt)

    @app.template_filter("ago")
    def _ago(value) -> str:
        if not value:
            return "nie"
        if isinstance(value, (int, float)):
            value = datetime.fromtimestamp(value, timezone.utc).replace(tzinfo=None)
        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value)
            except ValueError:
                return value
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        secs = int((utcnow() - value).total_seconds())
        future = secs < 0
        secs = abs(secs)
        if secs < 60:
            txt = f"{secs} s"
        elif secs < 3600:
            txt = f"{secs // 60} Min."
        elif secs < 86400:
            txt = f"{secs // 3600} Std."
        else:
            txt = f"{secs // 86400} Tg."
        return f"in {txt}" if future else f"vor {txt}"

    @app.template_filter("bytes")
    def _bytes(value, unit: str = "B") -> str:
        try:
            n = float(value or 0)
        except (TypeError, ValueError):
            return str(value)
        if unit == "KB":
            n *= 1024
        for u in ("B", "KB", "MB", "GB", "TB"):
            if n < 1024 or u == "TB":
                return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
            n /= 1024
        return f"{n:.1f} TB"

    @app.template_filter("duration")
    def _duration(secs) -> str:
        if secs is None:
            return "–"
        secs = int(secs)
        if secs < 60:
            return f"{secs} s"
        if secs < 3600:
            return f"{secs // 60} min {secs % 60} s"
        days, rest = divmod(secs, 86400)
        h, m = rest // 3600, (rest % 3600) // 60
        return f"{days} Tg. {h} Std." if days else f"{h} Std. {m} min"

    @app.template_filter("tojson_pretty")
    def _json(value) -> str:
        return json.dumps(value, indent=2, ensure_ascii=False, default=str)

    @app.template_filter("nl2br")
    def _nl2br(value: str) -> Markup:
        return Markup("<br>".join(escape(line) for line in (value or "").splitlines()))

    @app.template_filter("fingerprint")
    def _fp(line: str) -> str:
        from ..ssh import host_key_fingerprint
        parts = (line or "").split()
        if len(parts) < 2:
            return line
        try:
            return host_key_fingerprint(parts[0], parts[1])
        except ValueError:
            return line

    @app.template_filter("shortkey")
    def _shortkey(value: str) -> str:
        return (value[:10] + "…" + value[-6:]) if value and len(value) > 20 else (value or "")

    @app.template_filter("slug")
    def _slug(value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "-", (value or "").lower()).strip("-")

    # ---- blueprints ------------------------------------------------------------
    from .views import (admin, auth_views, easybell, enroll, help, ispconfig, jobs, mailcow, main, nextcloud_users,
                        optimize,
                        pangolin, pbx, pve, routers, schedules, sso, systems, tickets, updates, users, wg, zabbix,
                        zammad)
    for bp in (auth_views.bp, main.bp, systems.bp, updates.bp, schedules.bp, jobs.bp, enroll.bp,
               wg.bp, users.bp, admin.bp, help.bp, pve.bp, routers.bp, pangolin.bp, optimize.bp, mailcow.bp, sso.bp,
               nextcloud_users.bp, pbx.bp, zabbix.bp, tickets.bp, ispconfig.bp, zammad.bp, easybell.bp):
        app.register_blueprint(bp)

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "version": __version__}

    return app
