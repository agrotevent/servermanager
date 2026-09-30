"""Shared helpers for the API connection views (Proxmox, RouterOS, Pangolin)."""
from __future__ import annotations

from typing import Optional
from urllib.parse import urlsplit

from flask import abort, g, request
from sqlalchemy import select

from ... import access, integrations, tlspin
from ...models import LEVEL_ORDER


def get_or_403(kind: str, obj_id: int, level: str):
    obj = integrations.get(g.db, kind, obj_id)
    if obj is None:
        abort(404)
    if not access.has_integration_level(g.db, g.user, kind, obj.id, level):
        abort(403)
    return obj


def level(kind: str, obj_id: int) -> Optional[str]:
    cache = g.setdefault("_int_levels", {})
    key = (kind, obj_id)
    if key not in cache:
        cache[key] = access.integration_level(g.db, g.user, kind, obj_id)
    return cache[key]


def can(kind: str, obj_id: int, lvl: str) -> bool:
    cur = level(kind, obj_id)
    return bool(cur) and LEVEL_ORDER[cur] >= LEVEL_ORDER[lvl]


def visible(kind: str) -> list:
    model = integrations.MODELS[kind]
    objs = g.db.execute(select(model).order_by(model.name)).scalars().all()
    levels = access.integration_levels(g.db, g.user, kind)
    if levels is None:
        return list(objs)
    return [o for o in objs if o.id in levels]


def save_common(obj, form, default_port: int) -> list[str]:
    """Name, description, URL, TLS settings, monitoring. Returns error messages."""
    errors = []
    obj.name = (form.get("name") or "").strip()[:128]
    if not obj.name:
        errors.append("Bitte einen Namen angeben.")
    obj.description = (form.get("description") or "").strip()[:2000]
    url = (form.get("api_url") or "").strip().rstrip("/")
    if url and "://" not in url:
        url = "https://" + url
    parts = urlsplit(url) if url else None
    if not parts or not parts.hostname or parts.scheme not in ("https", "http"):
        errors.append("Ungültige API-Adresse.")
    elif parts.username or parts.password:
        errors.append("Zugangsdaten gehören nicht in die Adresse.")
    obj.api_url = url
    fp = (form.get("fingerprint") or "").strip()
    obj.verify_ca = bool(form.get("verify_ca"))
    if fp:
        try:
            obj.fingerprint = tlspin.normalize_fingerprint(fp)
        except tlspin.PinError as exc:
            errors.append(str(exc))
    else:
        obj.fingerprint = ""
    if url.startswith("https://") and not obj.fingerprint and not obj.verify_ca:
        errors.append("Bitte den Zertifikats-Fingerabdruck hinterlegen (Button „Abrufen“) oder die Prüfung über "
                      "die System-CAs aktivieren.")
    obj.monitor = bool(form.get("monitor"))
    return errors


def fetch_fp_from_form(default_port: int) -> tuple[str, str]:
    """(fingerprint, error) for the URL in the submitted form."""
    url = (request.form.get("api_url") or "").strip()
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    if not parts.hostname or parts.scheme != "https":
        return "", "Für den Fingerabdruck wird eine https-Adresse benötigt."
    try:
        return tlspin.fetch_fingerprint(parts.hostname, parts.port or default_port), ""
    except tlspin.PinError as exc:
        return "", str(exc)


def safe_next(default: str) -> str:
    """Only local redirect targets (no open redirect via the 'next' form field)."""
    from ..auth import is_local_path
    nxt = request.form.get("next") or ""
    if is_local_path(nxt):
        return nxt
    return default
