"""Optimisation proposals: scan, select, confirm, apply (administrators)."""
from __future__ import annotations

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from sqlalchemy import select

from ... import optimize
from ...core import audit
from ...jobs import enqueue
from ...models import JOB_QUEUED, JOB_RUNNING, Job
from ..auth import admin_required, client_ip

bp = Blueprint("optimize", __name__, url_prefix="/optimierung")


def _running_scan():
    return g.db.execute(select(Job).where(Job.kind == "optimize_scan", Job.status.in_((JOB_QUEUED, JOB_RUNNING)))
                        .order_by(Job.id.desc())).scalars().first()


@bp.get("/")
@admin_required
def index():
    result = optimize.load(g.db)
    props = result.get("proposals", [])
    groups = {}
    for idx, p in enumerate(props):
        groups.setdefault(p["area"], []).append((idx, p))
    ordered = [(a, optimize.AREAS[a], groups[a]) for a in optimize.AREAS if a in groups]
    return render_template("optimize/index.html", result=result, groups=ordered, summary=optimize.summary(result),
                           running=_running_scan())


@bp.post("/scan")
@admin_required
def scan():
    _running_scan() or enqueue(g.db, kind="optimize_scan", title="Optimierungs-Scan der Infrastruktur",
                                     user=g.user)
    audit(g.db, g.user, "optimize.scan", "", ip=client_ip())
    g.db.commit()
    flash("Scan läuft – die Seite aktualisiert sich automatisch.", "info")
    return redirect(url_for("optimize.index"))


def _selected() -> list[dict]:
    result = optimize.load(g.db)
    if request.form.get("scan_at") != result.get("at"):
        abort(409, description="Inzwischen wurde neu gescannt – bitte die Auswahl wiederholen.")
    props = result.get("proposals", [])
    items = []
    for raw in request.form.getlist("sel"):
        if not raw.isdigit() or int(raw) >= len(props):
            continue
        p = props[int(raw)]
        if not p.get("action"):
            continue
        inputs = {}
        for inp in p.get("inputs", []):
            val = request.form.get(f"in_{raw}_{inp['name']}", "")
            inputs[inp["name"]] = bool(val) if inp.get("kind") == "bool" else val.strip()[:100]
        items.append({"idx": int(raw), "id": p["id"], "title": p["title"], "detail": p["detail"],
                      "action": p["action"], "params": p["params"], "obj": p["obj"], "inputs": inputs,
                      "input_defs": p.get("inputs", [])})
    return items


@bp.post("/confirm")
@admin_required
def confirm():
    items = _selected()
    if not items:
        flash("Keine umsetzbaren Vorschläge ausgewählt.", "warning")
        return redirect(url_for("optimize.index"))
    return render_template("optimize/confirm.html", items=items, scan_at=request.form.get("scan_at"))


@bp.post("/apply")
@admin_required
def apply():
    items = _selected()
    if not items or request.form.get("confirmed") != "1":
        flash("Keine bestätigten Vorschläge.", "warning")
        return redirect(url_for("optimize.index"))
    job = enqueue(g.db, kind="optimize", title=f"Optimierungen umsetzen ({len(items)})", user=g.user,
                  payload={"items": [{k: v for k, v in i.items() if k not in ("input_defs", "detail", "idx")}
                                     for i in items]})
    audit(g.db, g.user, "optimize.confirm", f"{len(items)} Vorschläge", "\n".join(i["title"] for i in items)[:2000],
          ip=client_ip())
    g.db.commit()
    return redirect(url_for("jobs.detail", job_id=job.id))
