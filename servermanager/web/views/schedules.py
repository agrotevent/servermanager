"""Maintenance scheduler (plan updates / maintenance e.g. for night hours)."""
from __future__ import annotations

from datetime import datetime, timedelta

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from sqlalchemy import select, update

from ... import access, notify, schedules as sched
from ...core import audit
from ...models import (JOB_CANCELLED, JOB_QUEUED, JOB_RUNNING, LEVEL_FULL, LEVEL_OPERATE, RECURRENCES,
                       REBOOT_POLICIES, Job, MaintenanceSchedule, ScheduleRun, utcnow)
from ...modules import ParamError, schedulable_actions
from ..auth import can, client_ip, login_required

bp = Blueprint("schedules", __name__, url_prefix="/schedules")


def _visible(s: MaintenanceSchedule) -> bool:
    return g.user.is_admin or s.created_by == g.user.id


def _get(schedule_id: int) -> MaintenanceSchedule:
    s = g.db.get(MaintenanceSchedule, schedule_id)
    if s is None:
        abort(404)
    if not _visible(s):
        abort(403)
    return s


def _next_night(tz, hour: int = 3) -> datetime:
    now = datetime.now(tz)
    cand = now.replace(hour=hour, minute=0, second=0, microsecond=0)
    if cand <= now + timedelta(minutes=10):
        cand += timedelta(days=1)
    return cand.replace(tzinfo=None)


def _form_ctx(s: MaintenanceSchedule) -> dict:
    systems = access.accessible_systems(g.db, g.user, LEVEL_OPERATE)
    groups: dict[str, list] = {}
    for mod, act in schedulable_actions():
        groups.setdefault(mod.label, []).append((f"{mod.key}.{act.key}", act))
    selected_steps = {f"{st.get('module')}.{st.get('action')}" for st in (s.steps or []) if st.get("module") != "command"}
    command = next((st.get("command", "") for st in (s.steps or []) if st.get("module") == "command"), "")
    all_tags = sorted({t for x in systems for t in x.tag_list})
    return {"s": s, "systems": systems, "groups": groups, "selected_steps": selected_steps, "command": command,
            "recurrences": RECURRENCES, "reboot_policies": REBOOT_POLICIES, "weekdays": sched.WEEKDAYS,
            "all_tags": all_tags, "selected_ids": {int(i) for i in (s.system_ids or [])},
            "can_command": g.user.is_admin or all(can(x.id, LEVEL_FULL) for x in systems),
            "mail_ok": notify.mail_configured(g.db)}


def _apply_form(s: MaintenanceSchedule) -> list[str]:
    f = request.form
    errors = []
    s.name = f.get("name", "").strip()[:128]
    if not s.name:
        errors.append("Bitte einen Namen angeben.")
    s.description = f.get("description", "").strip()
    s.enabled = bool(f.get("enabled"))
    s.recurrence = f.get("recurrence") if f.get("recurrence") in RECURRENCES else "once"
    if s.recurrence == "once":
        try:
            s.run_at = datetime.strptime(f.get("run_at", ""), "%Y-%m-%dT%H:%M")
        except ValueError:
            errors.append("Bitte Datum und Uhrzeit für die einmalige Ausführung angeben.")
    s.time_of_day = sched.parse_hhmm(f.get("time_of_day", "03:00")).strftime("%H:%M")
    s.weekdays = sorted({int(w) for w in f.getlist("weekdays") if w.isdigit() and int(w) < 7})
    if s.recurrence == "weekly" and not s.weekdays:
        errors.append("Bitte mindestens einen Wochentag auswählen.")
    try:
        s.day_of_month = min(31, max(1, int(f.get("day_of_month", "1") or 1)))
    except ValueError:
        s.day_of_month = 1
    allowed = {x.id for x in access.accessible_systems(g.db, g.user, LEVEL_OPERATE)}
    s.system_ids = sorted({int(i) for i in f.getlist("systems") if i.isdigit() and int(i) in allowed})
    s.tag = f.get("tag", "").strip()[:64]
    if not s.system_ids and not s.tag:
        errors.append("Bitte mindestens ein System oder ein Tag auswählen.")
    raw_steps = []
    chosen = set(f.getlist("steps"))
    for mod, act in schedulable_actions():
        if f"{mod.key}.{act.key}" in chosen:
            raw_steps.append({"module": mod.key, "action": act.key, "params": {}})
    cmd = f.get("command", "").strip()
    if cmd:
        if not (g.user.is_admin or all(can(i, LEVEL_FULL) for i in s.system_ids)) or (s.tag and not g.user.is_admin):
            errors.append("Eigene Befehle erfordern Vollzugriff auf alle ausgewählten Systeme.")
        raw_steps.append({"module": "command", "command": cmd})
    try:
        s.steps = sched.validate_steps(raw_steps)
    except ParamError as exc:
        errors.append(str(exc))
    s.reboot_policy = f.get("reboot_policy") if f.get("reboot_policy") in REBOOT_POLICIES else "never"
    if not s.steps and s.reboot_policy == "never":
        errors.append("Bitte mindestens eine Aufgabe auswählen.")
    level = sched.required_level(s.steps or [])
    if level == LEVEL_FULL and not g.user.is_admin and not all(can(i, LEVEL_FULL) for i in s.system_ids):
        errors.append("Mindestens eine Aufgabe erfordert Vollzugriff auf alle ausgewählten Systeme.")
    s.only_if_updates = bool(f.get("only_if_updates"))
    s.pre_backup = bool(f.get("pre_backup"))
    s.stop_on_error = bool(f.get("stop_on_error"))
    try:
        s.max_parallel = min(50, max(1, int(f.get("max_parallel", "3") or 3)))
        s.window_minutes = min(24 * 60, max(0, int(f.get("window_minutes", "180") or 0)))
    except ValueError:
        errors.append("Ungültige Zahl bei Parallelität/Wartungsfenster.")
    s.notify_email = ", ".join(notify.recipients(f.get("notify_email", "")))[:255]
    return errors


@bp.get("/")
@login_required
def index():
    q = select(MaintenanceSchedule).order_by(MaintenanceSchedule.enabled.desc(), MaintenanceSchedule.next_run_at)
    if not g.user.is_admin:
        q = q.where(MaintenanceSchedule.created_by == g.user.id)
    items = g.db.execute(q).scalars().all()
    runs = g.db.execute(select(ScheduleRun).order_by(ScheduleRun.id.desc()).limit(15)).scalars().all()
    runs = [r for r in runs if r.schedule is None or _visible(r.schedule)]
    return render_template("schedules/index.html", items=items, runs=runs, describe=sched.describe)


@bp.route("/new", methods=["GET", "POST"])
@login_required
def new():
    tz = sched.get_tz(g.db)
    s = MaintenanceSchedule(enabled=True, recurrence="once", run_at=_next_night(tz), time_of_day="03:00",
                            weekdays=[6], day_of_month=1, reboot_policy="if_required", only_if_updates=True,
                            pre_backup=False, stop_on_error=True, max_parallel=3, window_minutes=180,
                            steps=[{"module": "debian", "action": "upgrade", "params": {"autoremove": "1"}}])
    if request.method == "GET":
        ids = [int(i) for i in request.args.get("systems", "").split(",") if i.isdigit()]
        s.system_ids = [i for i in ids if can(i, LEVEL_OPERATE)]
        if s.system_ids:
            s.name = f"Updates {s.run_at.strftime('%d.%m.%Y %H:%M')}" if s.run_at else "Updates"
        return render_template("schedules/form.html", is_new=True, **_form_ctx(s))
    errors = _apply_form(s)
    if errors:
        for e in errors:
            flash(e, "danger")
        return render_template("schedules/form.html", is_new=True, **_form_ctx(s))
    s.created_by = g.user.id
    sched.refresh_next_run(g.db, s)
    if s.enabled and s.next_run_at is None:
        flash("Der gewählte Zeitpunkt liegt in der Vergangenheit.", "danger")
        return render_template("schedules/form.html", is_new=True, **_form_ctx(s))
    g.db.add(s)
    g.db.flush()
    audit(g.db, g.user, "schedule.create", s.name, sched.describe(s), ip=client_ip())
    g.db.commit()
    flash(f"Wartungsplan '{s.name}' gespeichert - nächste Ausführung: "
          f"{sched.to_local(s.next_run_at, tz).strftime('%d.%m.%Y %H:%M') if s.next_run_at else '-'}", "success")
    return redirect(url_for("schedules.detail", schedule_id=s.id))


@bp.route("/<int:schedule_id>/edit", methods=["GET", "POST"])
@login_required
def edit(schedule_id: int):
    s = _get(schedule_id)
    if request.method == "POST":
        errors = _apply_form(s)
        if not errors:
            sched.refresh_next_run(g.db, s)
            if s.enabled and s.next_run_at is None:
                errors.append("Der gewählte Zeitpunkt liegt in der Vergangenheit.")
        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("schedules/form.html", is_new=False, **_form_ctx(s))
        audit(g.db, g.user, "schedule.update", s.name, sched.describe(s), ip=client_ip())
        g.db.commit()
        flash("Wartungsplan gespeichert.", "success")
        return redirect(url_for("schedules.detail", schedule_id=s.id))
    return render_template("schedules/form.html", is_new=False, **_form_ctx(s))


@bp.get("/<int:schedule_id>")
@login_required
def detail(schedule_id: int):
    s = _get(schedule_id)
    tz = sched.get_tz(g.db)
    upcoming = []
    t = utcnow()
    if s.enabled:
        for _ in range(5):
            nxt = sched.compute_next_run(s, t, tz)
            if nxt is None:
                break
            upcoming.append(nxt)
            t = nxt
    runs = g.db.execute(select(ScheduleRun).where(ScheduleRun.schedule_id == s.id)
                        .order_by(ScheduleRun.id.desc()).limit(20)).scalars().all()
    run_jobs = {}
    for r in runs[:5]:
        run_jobs[r.id] = g.db.execute(select(Job).where(Job.run_id == r.id).order_by(Job.id)).scalars().all()
    targets = sched.target_systems(g.db, s)
    if not g.user.is_admin:
        visible = access.accessible_system_ids(g.db, g.user) or set()
        hidden = len([t for t in targets if t.id not in visible])
        targets = [t for t in targets if t.id in visible]
    else:
        hidden = 0
    return render_template("schedules/detail.html", s=s, upcoming=upcoming, runs=runs, run_jobs=run_jobs,
                           targets=targets, hidden_targets=hidden, describe=sched.describe, step_label=sched.step_label,
                           REBOOT_POLICIES=REBOOT_POLICIES)


@bp.post("/<int:schedule_id>/toggle")
@login_required
def toggle(schedule_id: int):
    s = _get(schedule_id)
    s.enabled = not s.enabled
    sched.refresh_next_run(g.db, s)
    audit(g.db, g.user, "schedule.toggle", s.name, "aktiv" if s.enabled else "pausiert", ip=client_ip())
    g.db.commit()
    flash("Wartungsplan " + ("aktiviert." if s.enabled else "pausiert."), "info")
    return redirect(request.referrer or url_for("schedules.index"))


@bp.post("/<int:schedule_id>/run")
@login_required
def run_now(schedule_id: int):
    s = _get(schedule_id)
    run = sched.start_run(g.db, s, utcnow(), manual_user=g.user)
    audit(g.db, g.user, "schedule.run_now", s.name, ip=client_ip())
    g.db.commit()
    flash(f"Wartung gestartet: {run.summary.splitlines()[0]}", "success")
    return redirect(url_for("schedules.detail", schedule_id=s.id))


@bp.post("/<int:schedule_id>/delete")
@login_required
def delete(schedule_id: int):
    s = _get(schedule_id)
    name = s.name
    # queued jobs of unfinished runs would otherwise lose their run (and parallelism limit)
    run_ids = [r.id for r in g.db.execute(select(ScheduleRun).where(ScheduleRun.schedule_id == s.id,
                                                                    ScheduleRun.status == JOB_RUNNING)).scalars()]
    if run_ids:
        g.db.execute(update(Job).where(Job.run_id.in_(run_ids), Job.status == JOB_QUEUED)
                     .values(status=JOB_CANCELLED, finished_at=utcnow(), summary="Wartungsplan gelöscht"))
    g.db.delete(s)
    audit(g.db, g.user, "schedule.delete", name, ip=client_ip())
    g.db.commit()
    flash(f"Wartungsplan '{name}' gelöscht.", "success")
    return redirect(url_for("schedules.index"))
