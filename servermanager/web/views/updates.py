"""Update overview: which system has which pending updates."""
from __future__ import annotations

from datetime import timedelta

from flask import Blueprint, g, render_template, request

from ... import access, inventory, settings
from ...models import utcnow
from ..auth import login_required

bp = Blueprint("updates", __name__, url_prefix="/updates")

FILTERS = {
    "all": "Alle Systeme",
    "pending": "Mit Updates",
    "security": "Sicherheitsupdates",
    "reboot": "Neustart erforderlich",
    "release": "Release-Upgrade verfügbar",
    "stale": "Nicht aktuell geprüft",
}


@bp.get("/")
@login_required
def index():
    flt = request.args.get("filter", "pending")
    if flt not in FILTERS:
        flt = "pending"
    deep_h = int(settings.get(g.db, "checks.deep_interval_hours") or 6)
    rows = []
    totals = {"systems": 0, "pending": 0, "packages": 0, "security": 0, "reboot": 0, "release": 0, "modules": 0}
    for s in access.accessible_systems(g.db, g.user):
        summ = inventory.update_summary(s)
        apt = s.upd.get("apt") or {}
        stale = s.last_deep_check is None or utcnow() - s.last_deep_check > timedelta(hours=deep_h * 2)
        row = {"system": s, "summary": summ, "apt": apt, "stale": stale,
               "modules": [i for i in summ["items"] if i["module"] != "debian"]}
        totals["systems"] += 1
        totals["pending"] += 1 if summ["total"] else 0
        totals["packages"] += int(apt.get("count") or 0)
        totals["security"] += summ["security"]
        totals["reboot"] += 1 if summ["reboot"] else 0
        totals["release"] += 1 if summ["release"] else 0
        totals["modules"] += sum(i["count"] for i in row["modules"])
        keep = {
            "all": True,
            "pending": summ["total"] > 0 or summ["reboot"] or bool(summ["release"]),
            "security": summ["security"] > 0,
            "reboot": summ["reboot"],
            "release": bool(summ["release"]),
            "stale": stale,
        }[flt]
        if keep:
            rows.append(row)
    rows.sort(key=lambda r: (-r["summary"]["security"], -r["summary"]["total"], r["system"].name.lower()))
    return render_template("updates/index.html", rows=rows, totals=totals, flt=flt, filters=FILTERS)
