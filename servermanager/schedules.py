"""Maintenance scheduler: computes run times and turns due schedules into jobs."""
from __future__ import annotations

import calendar
import logging
from datetime import date, datetime, time, timedelta, timezone
from typing import Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import access, notify, settings
from .jobs import enqueue, new_batch_id
from .models import (JOB_FAILED, JOB_FINAL, JOB_RUNNING, JOB_SKIPPED, JOB_SUCCESS, LEVEL_FULL, LEVEL_OPERATE,
                     STATUS_PENDING, Job, MaintenanceSchedule, ScheduleRun, System, User, utcnow)
from .modules import ParamError, resolve_action

log = logging.getLogger(__name__)
WEEKDAYS = ["Mo", "Di", "Mi", "Do", "Fr", "Sa", "So"]


def get_tz(db: Session) -> ZoneInfo:
    try:
        return ZoneInfo(settings.get(db, "general.timezone") or "Europe/Berlin")
    except ZoneInfoNotFoundError:
        return ZoneInfo("UTC")


def to_utc_naive(local: datetime, tz: ZoneInfo) -> datetime:
    return local.replace(tzinfo=tz).astimezone(timezone.utc).replace(tzinfo=None)


def to_local(utc_naive: Optional[datetime], tz: ZoneInfo) -> Optional[datetime]:
    if utc_naive is None:
        return None
    return utc_naive.replace(tzinfo=timezone.utc).astimezone(tz)


def parse_hhmm(value: str) -> time:
    try:
        h, m = (value or "03:00").split(":")[:2]
        return time(int(h) % 24, int(m) % 60)
    except (ValueError, TypeError):
        return time(3, 0)


def compute_next_run(s: MaintenanceSchedule, after_utc: datetime, tz: ZoneInfo) -> Optional[datetime]:
    """Next run (naive UTC) strictly after ``after_utc``."""
    if s.recurrence == "once":
        if s.run_at is None:
            return None
        run_utc = to_utc_naive(s.run_at, tz)
        return run_utc if run_utc > after_utc else None
    after_local = to_local(after_utc, tz)
    assert after_local is not None
    tod = parse_hhmm(s.time_of_day)
    day: date = after_local.date()
    for _ in range(0, 400):
        candidate: Optional[datetime] = None
        if s.recurrence == "daily":
            candidate = datetime.combine(day, tod)
        elif s.recurrence == "weekly":
            wds = [int(w) for w in (s.weekdays or []) if str(w).isdigit()] or [0]
            if day.weekday() in wds:
                candidate = datetime.combine(day, tod)
        elif s.recurrence == "monthly":
            last = calendar.monthrange(day.year, day.month)[1]
            if day.day == min(max(1, s.day_of_month or 1), last):
                candidate = datetime.combine(day, tod)
        if candidate is not None:
            cand_utc = to_utc_naive(candidate, tz)
            if cand_utc > after_utc:
                return cand_utc
        day += timedelta(days=1)
    return None


def describe(s: MaintenanceSchedule) -> str:
    if s.recurrence == "once":
        return f"einmalig am {s.run_at.strftime('%d.%m.%Y %H:%M') if s.run_at else '?'}"
    if s.recurrence == "daily":
        return f"täglich um {s.time_of_day}"
    if s.recurrence == "weekly":
        days = ", ".join(WEEKDAYS[int(w)] for w in sorted(s.weekdays or []) if str(w).isdigit() and int(w) < 7)
        return f"wöchentlich ({days or 'Mo'}) um {s.time_of_day}"
    if s.recurrence == "monthly":
        return f"monatlich am {s.day_of_month}. um {s.time_of_day}"
    return s.recurrence


def target_systems(db: Session, s: MaintenanceSchedule) -> list[System]:
    ids = {int(i) for i in (s.system_ids or []) if str(i).isdigit()}
    systems = list(db.execute(select(System).where(System.id.in_(ids))).scalars()) if ids else []
    if s.tag:
        tag = s.tag.strip().lower()
        for sys_ in db.execute(select(System)).scalars():
            if tag in [t.lower() for t in sys_.tag_list] and sys_.id not in ids:
                systems.append(sys_)
                ids.add(sys_.id)
    return [x for x in systems if x.status != STATUS_PENDING]


def required_level(steps: list[dict]) -> str:
    level = LEVEL_OPERATE
    for st in steps or []:
        if st.get("module") == "command":
            return LEVEL_FULL
        try:
            _, action = resolve_action(st.get("module", ""), st.get("action", ""))
        except ParamError:
            continue
        if action.level == LEVEL_FULL:
            level = LEVEL_FULL
    return level


def validate_steps(steps: list[dict]) -> list[dict]:
    clean = []
    for st in steps:
        if st.get("module") == "command":
            cmd = (st.get("command") or "").strip()
            if cmd:
                clean.append({"module": "command", "action": "run", "command": cmd})
            continue
        mod, action = resolve_action(st.get("module", ""), st.get("action", ""))
        params = action.clean_params(st.get("params") or {})
        clean.append({"module": mod.key, "action": action.key, "params": params})
    return clean


def step_label(step: dict) -> str:
    if step.get("module") == "command":
        return f"Befehl: {step.get('command', '')[:60]}"
    try:
        mod, action = resolve_action(step.get("module", ""), step.get("action", ""))
    except ParamError:
        return f"{step.get('module')}.{step.get('action')}"
    return f"{mod.label}: {action.label}"


def start_run(db: Session, s: MaintenanceSchedule, now: datetime, manual_user: Optional[User] = None) -> ScheduleRun:
    """Create a ScheduleRun with one maintenance job per target system."""
    run = ScheduleRun(schedule_id=s.id, started_at=now, status=JOB_RUNNING, max_parallel=max(1, s.max_parallel or 1))
    db.add(run)
    db.flush()
    creator = manual_user or s.creator
    level = required_level(s.steps or [])
    batch = new_batch_id()
    not_after = now + timedelta(minutes=s.window_minutes) if s.window_minutes else None
    created = skipped = 0
    notes = []
    for system in target_systems(db, s):
        if creator is None or not creator.active or not access.has_level(db, creator, system.id, level):
            notes.append(f"{system.name}: keine Berechtigung ({creator.username if creator else 'kein Ersteller'})")
            skipped += 1
            continue
        enqueue(db, kind="maintenance", title=f"Wartung: {s.name}", system=system, user=creator,
                batch_id=batch, run_id=run.id, not_after=not_after,
                payload={"schedule_id": s.id, "steps": s.steps or [], "reboot_policy": s.reboot_policy,
                         "pre_backup": s.pre_backup, "stop_on_error": s.stop_on_error,
                         "only_if_updates": s.only_if_updates})
        created += 1
    run.summary = f"{created} System(e) eingeplant" + (f", {skipped} übersprungen" if skipped else "")
    if notes:
        run.summary += "\n" + "\n".join(notes)
    if created == 0:
        run.status = JOB_SKIPPED
        run.finished_at = now
    s.last_run_at = now
    s.last_status = run.status
    return run


def tick(db: Session, now: Optional[datetime] = None) -> int:
    """Start all due schedules. Returns number of started runs."""
    now = now or utcnow()
    tz = get_tz(db)
    started = 0
    due = db.execute(select(MaintenanceSchedule).where(MaintenanceSchedule.enabled.is_(True),
                                                       MaintenanceSchedule.next_run_at.is_not(None),
                                                       MaintenanceSchedule.next_run_at <= now)).scalars().all()
    for s in due:
        late = (now - s.next_run_at).total_seconds() / 60
        if s.window_minutes and late > s.window_minutes:
            log.warning("schedule %s missed (%.0f min late) - skipping this run", s.id, late)
            s.last_status = "missed"
        else:
            start_run(db, s, now)
            started += 1
        s.next_run_at = compute_next_run(s, now, tz)
        if s.next_run_at is None:
            s.enabled = False if s.recurrence == "once" else s.enabled
    return started


def refresh_next_run(db: Session, s: MaintenanceSchedule) -> None:
    s.next_run_at = compute_next_run(s, utcnow(), get_tz(db)) if s.enabled else None


def finalize_runs(db: Session) -> None:
    """Close finished runs and send notifications."""
    runs = db.execute(select(ScheduleRun).where(ScheduleRun.status == JOB_RUNNING)).scalars().all()
    for run in runs:
        jobs = db.execute(select(Job).where(Job.run_id == run.id)).scalars().all()
        if any(j.status not in JOB_FINAL for j in jobs):
            continue
        ok = sum(1 for j in jobs if j.status == JOB_SUCCESS)
        skipped = sum(1 for j in jobs if j.status == JOB_SKIPPED)
        failed = [j for j in jobs if j.status not in (JOB_SUCCESS, JOB_SKIPPED)]
        run.finished_at = utcnow()
        run.status = JOB_FAILED if failed else JOB_SUCCESS
        lines = [f"Erfolgreich: {ok}, übersprungen: {skipped}, fehlgeschlagen: {len(failed)}"]
        for j in jobs:
            name = j.system.name if j.system else "-"
            lines.append(f"- {name}: {j.status} {('- ' + j.summary) if j.summary else ''}")
        run.summary = (run.summary.split("\n")[0] + "\n" if run.summary else "") + "\n".join(lines)
        sched = run.schedule
        if sched is not None:
            sched.last_status = run.status
            to = notify.recipients(sched.notify_email)
            if failed and settings.get(db, "mail.notify_failures"):
                to += [r for r in notify.recipients(settings.get(db, "mail.admin_recipients")) if r not in to]
            if to:
                base = settings.base_url(db)
                subject = f"Wartung '{sched.name}': {'FEHLER' if failed else 'erfolgreich'}"
                body = "\n".join([f"Wartungsplan: {sched.name}", f"Start: {run.started_at} UTC", ""] + lines +
                                 ["", f"Details: {base}/schedules/{sched.id}"])
                notify.notify(db, to, subject, body)
