"""Job list, job detail with live log, cancel."""
from __future__ import annotations

from flask import Blueprint, abort, flash, g, jsonify, redirect, render_template, request, url_for
from sqlalchemy import select

from ... import access
from ...core import audit
from ... import jobs as jobq
from ...jobs import KIND_LABELS, read_log, request_cancel
from ...models import JOB_QUEUED, JOB_RUNNING, JOB_STATUSES, KIND_PVE, LEVEL_FULL, LEVEL_OPERATE, Job
from ..auth import can, client_ip, login_required

bp = Blueprint("jobs", __name__, url_prefix="/jobs")


def _get(job_id: int) -> Job:
    job = g.db.get(Job, job_id)
    if job is None:
        abort(404)
    if not access.can_view_job(g.db, g.user, job):
        abort(403)
    return job


def _can_cancel(job: Job) -> bool:
    if job.is_final:
        return False
    if g.user.is_admin or job.user_id == g.user.id:
        return True
    if job.pve_id and access.has_integration_level(g.db, g.user, KIND_PVE, job.pve_id, LEVEL_OPERATE):
        return True
    return bool(job.system_id and can(job.system_id, LEVEL_OPERATE))


def _retry_plan(job: Job):
    """Retry of a failed container creation / guest import (same rights as starting it)."""
    plan = jobq.retry_plan(job)
    if plan is None or not job.pve_id:
        return None
    if not g.user.is_admin:
        if not access.has_integration_level(g.db, g.user, KIND_PVE, job.pve_id, LEVEL_FULL):
            return None
        if plan["register"] and not g.user.can_add_systems:
            return None
    return plan


@bp.get("/")
@login_required
def index():
    q = select(Job).order_by(Job.id.desc())
    ids = access.accessible_system_ids(g.db, g.user)
    if ids is not None:
        pve_ids = list((access.integration_levels(g.db, g.user, KIND_PVE) or {}).keys())
        q = q.where((Job.system_id.in_(ids)) | ((Job.system_id.is_(None)) & (Job.user_id == g.user.id))
                    | (Job.pve_id.in_(pve_ids)))
    status = request.args.get("status", "")
    if status in JOB_STATUSES:
        q = q.where(Job.status == status)
    batch = request.args.get("batch", "")
    if batch:
        q = q.where(Job.batch_id == batch)
    system_id = request.args.get("system", "")
    if system_id.isdigit():
        q = q.where(Job.system_id == int(system_id))
    page = max(1, int(request.args.get("page", "1") or 1)) if request.args.get("page", "1").isdigit() else 1
    per_page = 50
    jobs = g.db.execute(q.offset((page - 1) * per_page).limit(per_page + 1)).scalars().all()
    has_more = len(jobs) > per_page
    jobs = jobs[:per_page]
    active = any(j.status in (JOB_QUEUED, JOB_RUNNING) for j in jobs)
    return render_template("jobs/index.html", jobs=jobs, status=status, batch=batch, page=page, has_more=has_more,
                           active=active, kinds=KIND_LABELS)


@bp.get("/<int:job_id>")
@login_required
def detail(job_id: int):
    job = _get(job_id)
    retry_of = (job.remote or {}).get("retried_by")
    return render_template("jobs/detail.html", job=job, kinds=KIND_LABELS, can_cancel=_can_cancel(job),
                           retry=_retry_plan(job), retried_by=retry_of)


@bp.get("/<int:job_id>/log")
@login_required
def log(job_id: int):
    job = _get(job_id)
    try:
        offset = max(0, int(request.args.get("offset", "0")))
    except ValueError:
        offset = 0
    text, new_offset = read_log(job.id, offset)
    return jsonify({
        "text": text, "offset": new_offset, "status": job.status, "status_label": JOB_STATUSES.get(job.status, ""),
        "final": job.is_final, "summary": job.summary, "exit_code": job.exit_code,
        "duration": int(job.duration or 0),
    })


@bp.post("/<int:job_id>/cancel")
@login_required
def cancel(job_id: int):
    job = _get(job_id)
    if not _can_cancel(job):
        abort(403)
    request_cancel(g.db, job)
    audit(g.db, g.user, "job.cancel", f"#{job.id}", job.title, ip=client_ip())
    g.db.commit()
    flash("Abbruch angefordert.", "warning")
    return redirect(url_for("jobs.detail", job_id=job.id))


@bp.post("/<int:job_id>/retry")
@login_required
def retry(job_id: int):
    job = _get(job_id)
    if _retry_plan(job) is None:
        flash("Dieser Job kann nicht (mehr) wiederholt werden.", "warning")
        return redirect(url_for("jobs.detail", job_id=job.id))
    new = jobq.retry(g.db, job, g.user)
    audit(g.db, g.user, "job.retry", f"#{job.id}", f"-> #{new.id} {job.title}", ip=client_ip())
    g.db.commit()
    return redirect(url_for("jobs.detail", job_id=new.id))
