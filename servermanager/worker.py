"""Background worker: executes jobs, periodic status checks, schedules, auto backups.

Runs as its own process (systemd unit ``servermanager-worker``). Long running
package operations are executed "detached" on the target system, so a worker
restart (e.g. during a self-update) does not interrupt them - the worker
re-attaches to the remote log after the restart.
"""
from __future__ import annotations

import logging
import signal
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from typing import Optional

import requests
from sqlalchemy import select, update

from . import access, integrations, inventory, pve, schedules, security, settings, sshkeys, sysbackup
from .core import audit, bootstrap, setup_logging
from .db import session_scope
from .jobs import PHASE_LABELS, log_path
from .models import (AUTH_KEY, CONN_DIRECT, JOB_CANCELLED, JOB_FAILED, JOB_FINAL, JOB_QUEUED, JOB_RUNNING,
                     JOB_SKIPPED, JOB_SUCCESS, LEVEL_FULL, STATUS_ERROR, STATUS_ONLINE, STATUS_PENDING, Job,
                     PangolinServer, PveServer, RouterDevice, ScheduleRun, System, User, utcnow)
from .modules import ParamError, resolve_action
from .ssh import DETACHED_DIED, CancelledError, Connection, SSHError, target_from_system
from .mikrotik import MikroTikError
from .pangolin import PangolinError
from .pveapi import PveError
from .authentik import AuthentikError
from .mailcow import MailcowError
from .sso import SsoError

log = logging.getLogger("servermanager.worker")


def sshquote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"

POLL_LIMIT = 256 * 1024


class JobFailed(Exception):
    pass


class JobSkipped(Exception):
    pass


class Interrupted(Exception):
    """Worker shutdown while a detached remote process is still running."""


def resumable(remote: Optional[dict]) -> bool:
    """Job state that survives a worker restart (remote process, reboot wait, Proxmox task)."""
    remote = remote or {}
    return bool(remote.get("detached") or remote.get("reboot") or remote.get("pve_task") or remote.get("phase"))


# --------------------------------------------------------------------------
class JobContext:
    def __init__(self, worker: "Worker", job_id: int):
        self.worker = worker
        self.job_id = job_id
        self.fh = open(log_path(job_id), "ab")
        self._last_check = 0.0
        self._cancel = False
        self._line_start = self.fh.tell() == 0

    def write(self, text: str) -> None:
        if text:
            self.write_bytes(text.encode("utf-8", "replace"))

    def write_bytes(self, data: bytes) -> None:
        if data:
            self.fh.write(data)
            self.fh.flush()
            self._line_start = data.endswith(b"\n")

    def say(self, msg: str) -> None:
        prefix = "" if self._line_start else "\n"
        self.write(f"{prefix}[servermanager {datetime.now().strftime('%H:%M:%S')}] {msg}\n")

    def cancelled(self) -> bool:
        if self._cancel:
            return True
        now = time.monotonic()
        if now - self._last_check > 2:
            self._last_check = now
            with session_scope() as db:
                job = db.get(Job, self.job_id)
                self._cancel = bool(job and job.cancel_requested)
        return self._cancel

    def save_remote(self, remote: dict) -> None:
        with session_scope() as db:
            job = db.get(Job, self.job_id)
            if job is not None:
                job.remote = dict(remote)

    def close(self) -> None:
        try:
            self.fh.close()
        except OSError:
            pass


# --------------------------------------------------------------------------
class Worker:
    def __init__(self) -> None:
        with session_scope() as db:
            self.max_parallel = max(1, int(settings.get(db, "jobs.max_parallel") or 8))
            check_parallel = max(1, int(settings.get(db, "checks.parallel") or 8))
        self.pool = ThreadPoolExecutor(max_workers=self.max_parallel, thread_name_prefix="job")
        self.check_pool = ThreadPoolExecutor(max_workers=check_parallel, thread_name_prefix="check")
        self.lock = threading.Lock()
        self.running: dict[int, Optional[int]] = {}   # job id -> system id
        self.checking: set[int] = set()
        self.stop = threading.Event()
        self._last_periodic = 0.0
        self._last_daily: Optional[str] = None
        self._last_ispc = 0.0
        self.polling: set[tuple[str, int]] = set()

    # ------------------------------------------------------------------ main
    def run_forever(self) -> None:
        self.recover()
        log.info("worker started (max %s parallel jobs)", self.max_parallel)
        while not self.stop.is_set():
            try:
                self.claim_jobs()
            except Exception:  # noqa: BLE001
                log.exception("claiming jobs failed")
            if time.monotonic() - self._last_periodic > 30:
                self._last_periodic = time.monotonic()
                try:
                    self.periodic()
                except Exception:  # noqa: BLE001
                    log.exception("periodic tasks failed")
            self.stop.wait(1.0)
        log.info("worker stopping - waiting for running jobs")
        self.pool.shutdown(wait=True)
        self.check_pool.shutdown(wait=False, cancel_futures=True)

    def recover(self) -> None:
        with session_scope() as db:
            for job in db.execute(select(Job).where(Job.status == JOB_RUNNING)).scalars():
                if resumable(job.remote):
                    log.info("job %s: resuming after worker restart", job.id)
                    job.status = JOB_QUEUED  # will be claimed again and resumed
                else:
                    job.status = JOB_FAILED
                    job.finished_at = utcnow()
                    job.summary = "Unterbrochen (Worker wurde neu gestartet)"
                    with open(log_path(job.id), "ab") as fh:
                        fh.write(b"\n[servermanager] Job wurde durch einen Neustart des Workers unterbrochen.\n")

    # ------------------------------------------------------------------ jobs
    def claim_jobs(self) -> None:
        with self.lock:
            free = self.max_parallel - len(self.running)
            busy_systems = {s for s in self.running.values() if s}
        if free <= 0:
            return
        now = utcnow()
        with session_scope() as db:
            queued = db.execute(select(Job).where(Job.status == JOB_QUEUED).order_by(Job.id).limit(1000)).scalars().all()
            run_counts: dict[int, int] = {}
            for rid, in db.execute(select(Job.run_id).where(Job.status == JOB_RUNNING, Job.run_id.is_not(None))):
                run_counts[rid] = run_counts.get(rid, 0) + 1
            for job in queued:
                if free <= 0:
                    break
                resuming = resumable(job.remote)
                if job.not_after and now > job.not_after and not resuming:
                    job.status = JOB_SKIPPED
                    job.finished_at = now
                    job.summary = "Wartungsfenster überschritten - nicht gestartet"
                    continue
                if job.system_id and job.system_id in busy_systems:
                    continue
                if job.run_id:
                    run = db.get(ScheduleRun, job.run_id)
                    limit = run.max_parallel if run else 1
                    if run_counts.get(job.run_id, 0) >= limit:
                        continue
                    run_counts[job.run_id] = run_counts.get(job.run_id, 0) + 1
                res = db.execute(update(Job).where(Job.id == job.id, Job.status == JOB_QUEUED)
                                 .values(status=JOB_RUNNING, started_at=job.started_at or now))
                if res.rowcount != 1:
                    continue
                db.commit()
                with self.lock:
                    self.running[job.id] = job.system_id
                if job.system_id:
                    busy_systems.add(job.system_id)
                free -= 1
                self.pool.submit(self._execute, job.id)

    def _execute(self, job_id: int) -> None:
        ctx = JobContext(self, job_id)
        status, summary, exit_code = JOB_FAILED, "", None
        try:
            with session_scope() as db:
                job = db.get(Job, job_id)
                kind, payload = job.kind, dict(job.payload or {})
                system_id = job.system_id
                resumed = resumable(job.remote)
                retry_of = (job.remote or {}).get("retry_of")
                retry_phase = (job.remote or {}).get("phase", "")
                if retry_of:
                    job.remote = {k: v for k, v in job.remote.items() if k != "retry_of"}
            if retry_of:
                ctx.fh.truncate(0)
                ctx._line_start = True
                ctx.say(f"Job #{job_id} gestartet ({kind}) – Wiederholung von Job #{retry_of}"
                        + (f", fortgesetzt ab Schritt „{PHASE_LABELS.get(retry_phase, retry_phase)}“"
                           if retry_phase else ""))
            elif resumed:
                ctx.say("Worker neu gestartet - verbinde mich wieder mit dem laufenden Prozess ...")
            else:
                ctx.fh.truncate(0)
                ctx._line_start = True
                ctx.say(f"Job #{job_id} gestartet ({kind})")
            handler = getattr(self, f"job_{kind}", None)
            if handler is None:
                raise JobFailed(f"Unbekannter Job-Typ {kind}")
            summary = handler(ctx, job_id, system_id, payload) or "OK"
            status = JOB_SUCCESS
            exit_code = 0
        except Interrupted:
            ctx.say("Worker wird beendet - der Prozess läuft auf dem Zielsystem weiter und wird nach dem "
                    "Neustart wieder aufgenommen.")
            with self.lock:
                self.running.pop(job_id, None)
            ctx.close()
            return
        except JobSkipped as exc:
            status, summary = JOB_SKIPPED, str(exc)
            ctx.say(f"Übersprungen: {exc}")
        except CancelledError:
            status, summary = JOB_CANCELLED, "Abgebrochen"
            ctx.say("Job abgebrochen.")
        except (JobFailed, SSHError, ParamError, ValueError, PveError, MikroTikError, PangolinError,
                AuthentikError, MailcowError, SsoError) as exc:
            status, summary = JOB_FAILED, str(exc)
            ctx.say(f"FEHLER: {exc}")
        except Exception as exc:  # noqa: BLE001
            log.exception("job %s crashed", job_id)
            status, summary = JOB_FAILED, f"Interner Fehler: {exc}"
            ctx.say(f"Interner Fehler: {exc}")
        finally:
            with self.lock:
                self.running.pop(job_id, None)
        if status == JOB_SUCCESS:
            ctx.say(f"Job erfolgreich abgeschlossen: {summary}")
        with session_scope() as db:
            job = db.get(Job, job_id)
            if job is not None:
                job.status = status
                job.summary = (summary or "")[:2000]
                job.exit_code = exit_code if exit_code is not None else job.exit_code
                job.finished_at = utcnow()
                remote = dict(job.remote or {})
                if status in (JOB_FAILED, JOB_CANCELLED) and remote.get("phase"):
                    remote["resume_phase"] = remote["phase"]  # a retry continues here
                job.remote = {k: v for k, v in remote.items() if k not in ("detached", "pve_task", "phase")}
        ctx.close()

    # ------------------------------------------------------------------ helpers
    def _system(self, system_id: Optional[int]) -> System:
        if not system_id:
            raise JobFailed("Kein Zielsystem")
        with session_scope() as db:
            system = db.get(System, system_id)
            if system is None:
                raise JobFailed("System existiert nicht mehr")
            db.expunge(system)
            return system

    def _connect(self, ctx: JobContext, system: System) -> Connection:
        ctx.say(f"Verbinde mit {system.username}@{system.host}:{system.port} ...")
        return inventory.connect(system)

    def _refresh(self, ctx: JobContext, conn: Connection, system_id: int) -> System:
        with session_scope() as db:
            system = db.get(System, system_id)
            facts, apt = inventory.run_facts(conn, system)
            inventory.apply_facts(system, facts, apt)
            db.commit()
            db.expunge(system)
            return system

    def _run_script(self, ctx: JobContext, conn: Connection, system: System, body: str, env: dict,
                    detached: bool, timeout: int, state: dict, step: int) -> tuple[int, Connection]:
        if not detached:
            code = conn.run_script(body, env=env, root=True, on_output=ctx.write, cancel=ctx.cancelled,
                                   timeout=timeout)
            return code, conn
        key = f"job-{ctx.job_id}-{step}"
        conn.start_detached(body, key, env)
        state.update({"detached": {"key": key, "offset": 0, "step": step}})
        ctx.save_remote(state)
        ctx.say("Prozess läuft im Hintergrund auf dem Zielsystem (übersteht Verbindungsabbrüche).")
        return self._tail(ctx, conn, system, state, timeout)

    def _tail(self, ctx: JobContext, conn: Optional[Connection], system: System, state: dict,
              timeout: int) -> tuple[int, Connection]:
        det = state["detached"]
        key, offset = det["key"], int(det.get("offset", 0))
        if "started" not in det:
            det["started"] = time.time()   # wall clock: survives worker restarts
            ctx.save_remote(state)
        last_ok = time.monotonic()
        cancel_sent = timed_out = False
        while True:
            if self.stop.is_set():
                if conn:
                    conn.close()
                raise Interrupted()
            try:
                if conn is None or not conn.alive:
                    conn = inventory.connect(system)
                data, rc = conn.poll_detached(key, offset, POLL_LIMIT)
                last_ok = time.monotonic()
                if data:
                    ctx.write_bytes(data)
                    offset += len(data)
                    det["offset"] = offset
                    ctx.save_remote(state)
                if rc is not None and len(data) < POLL_LIMIT:
                    conn.cleanup_detached(key)
                    state.pop("detached", None)
                    ctx.save_remote(state)
                    if rc == DETACHED_DIED:
                        raise JobFailed("Der Prozess auf dem Zielsystem wurde unerwartet beendet (z. B. durch einen "
                                        "Neustart oder Absturz des Systems) - siehe Protokoll.")
                    if timed_out:
                        raise JobFailed(f"Zeitlimit von {timeout // 60} Minuten überschritten - Prozess beendet")
                    if cancel_sent:
                        raise CancelledError("Abgebrochen")
                    return rc, conn
                if len(data) >= POLL_LIMIT:
                    continue
                if not cancel_sent:
                    if ctx.cancelled():
                        ctx.say("Abbruch angefordert - beende Prozess auf dem Zielsystem")
                        conn.cancel_detached(key)
                        cancel_sent = True
                    elif time.time() - det["started"] > timeout:
                        ctx.say(f"Zeitlimit von {timeout // 60} Minuten überschritten - beende Prozess")
                        conn.cancel_detached(key)
                        cancel_sent = timed_out = True
            except SSHError as exc:
                if conn:
                    conn.close()
                conn = None
                if time.monotonic() - last_ok > 1800:
                    raise JobFailed("Keine Verbindung zum System seit 30 Minuten - der Prozess läuft evtl. "
                                    f"weiter (Log auf dem System: /var/lib/servermanager-jobs/{key}.log)") from exc
                ctx.say(f"Verbindung unterbrochen ({exc}) - neuer Versuch in 15 s")
                self.stop.wait(15)
                continue
            self.stop.wait(2)

    def _reboot(self, ctx: JobContext, conn: Connection, system: System, state: dict, phase: str,
                step: int = 0) -> Connection:
        boot_before = conn.exec("cat /proc/sys/kernel/random/boot_id", timeout=20).stdout.strip()
        ctx.say("Neustart wird ausgelöst ...")
        conn.exec("systemd-run --on-active=5 --timer-property=AccuracySec=1s /bin/systemctl reboot "
                  ">/dev/null 2>&1 || (nohup sh -c 'sleep 5; /sbin/reboot' >/dev/null 2>&1 &)", root=True, timeout=30)
        conn.close()
        state["reboot"] = {"boot_before": boot_before, "since": time.time(), "phase": phase, "step": step}
        ctx.save_remote(state)
        return self._await_reboot(ctx, system, state)

    def _await_reboot(self, ctx: JobContext, system: System, state: dict) -> Connection:
        """Wait until the system is back with a new boot id (resumable after a worker restart)."""
        rb = state["reboot"]
        self.stop.wait(max(0.0, 30 - (time.time() - rb["since"])))
        while time.time() - rb["since"] < 20 * 60:
            if self.stop.is_set():
                raise Interrupted()
            if ctx.cancelled():
                raise CancelledError("Abgebrochen")
            try:
                new = inventory.connect(system, timeout=10)
                boot_now = new.exec("cat /proc/sys/kernel/random/boot_id", timeout=20).stdout.strip()
                if boot_now and boot_now != rb["boot_before"]:
                    ctx.say(f"System ist wieder erreichbar (nach {int(time.time() - rb['since'])} s).")
                    state.pop("reboot", None)
                    ctx.save_remote(state)
                    return new
                new.close()
            except SSHError:
                pass
            self.stop.wait(10)
        raise JobFailed("System ist nach 20 Minuten nicht wieder erreichbar")

    def _backup(self, ctx: JobContext, conn: Connection, system: System, note: str,
                paths: Optional[list[str]] = None) -> None:
        paths = paths or sysbackup.parse_paths(system.backup_paths or "/etc")
        with session_scope() as db:
            sysbackup.create_backup(conn, db, db.get(System, system.id), paths, note, ctx.job_id, ctx.write,
                                    cancel=ctx.cancelled)

    # ------------------------------------------------------------------ step engine
    def _run_steps(self, ctx: JobContext, job_id: int, system_id: int, payload: dict) -> str:
        system = self._system(system_id)
        with session_scope() as db:
            state = dict(db.get(Job, job_id).remote or {})
        steps: list[dict] = payload.get("steps") or []
        start_step = int(state.get("next_step", 0))
        conn: Optional[Connection] = None
        failures: list[str] = []
        final_reboot_done = False
        try:
            if state.get("reboot"):
                # the worker was restarted while waiting for a reboot to finish
                rb = state["reboot"]
                ctx.say("Warte weiter darauf, dass das System nach dem Neustart erreichbar ist ...")
                conn = self._await_reboot(ctx, system, state)
                if rb.get("phase") == "final":
                    start_step = len(steps)
                    final_reboot_done = True
                else:
                    idx = int(rb.get("step", start_step))
                    self._step_result(ctx, steps[idx] if idx < len(steps) else {}, 0, failures)
                    start_step = idx + 1
                state["next_step"] = start_step
                ctx.save_remote(state)
            elif state.get("detached"):
                # resume a detached step after a worker restart
                idx = int(state["detached"].get("step", start_step))
                code, conn = self._tail(ctx, None, system, state, 6 * 3600)
                self._step_result(ctx, steps[idx] if idx < len(steps) else {}, code, failures)
                start_step = idx + 1
                state["next_step"] = start_step
                ctx.save_remote(state)
                if failures and payload.get("stop_on_error", True):
                    raise JobFailed(failures[0])
            if conn is None:
                conn = self._connect(ctx, system)

            if start_step == 0 and not state.get("prechecked"):
                if payload.get("only_if_updates"):
                    ctx.say("Prüfe auf ausstehende Updates ...")
                    with session_scope() as db:
                        s = db.get(System, system_id)
                        inventory.deep_check(conn, db, s, ctx.write, manual=True)
                        db.commit()
                        pending = inventory.has_pending_updates(s)
                        reboot = (s.upd.get("reboot") or {}).get("required")
                    if not pending and not (reboot and payload.get("reboot_policy") == "if_required"):
                        raise JobSkipped("Keine Updates ausstehend")
                if payload.get("pre_backup"):
                    ctx.say("Konfigurations-Backup vor der Wartung ...")
                    self._backup(ctx, conn, system, "vor Wartung")
                state["prechecked"] = True
                ctx.save_remote(state)

            for idx in range(start_step, len(steps)):
                step = steps[idx]
                if ctx.cancelled():
                    raise CancelledError("Abgebrochen")
                conn = self._run_step(ctx, conn, system, step, idx, state, failures)
                state["next_step"] = idx + 1
                ctx.save_remote(state)
                if failures and payload.get("stop_on_error", True):
                    break

            policy = payload.get("reboot_policy", "never")
            if not failures and not final_reboot_done and policy in ("always", "if_required"):
                system = self._refresh(ctx, conn, system_id)
                needed = system.fact.get("reboot_required")
                if policy == "always" or needed:
                    ctx.say("Neustart " + ("(immer)" if policy == "always" else "erforderlich") + " ...")
                    conn = self._reboot(ctx, conn, system, state, "final")
                else:
                    ctx.say("Kein Neustart erforderlich.")
            try:
                system = self._refresh(ctx, conn, system_id)
            except SSHError as exc:
                ctx.say(f"Inventur nach dem Job fehlgeschlagen: {exc}")
        finally:
            if conn:
                conn.close()
        if failures:
            raise JobFailed("; ".join(failures))
        pend = inventory.update_summary(system)
        extra = f", noch {pend['total']} Update(s) offen" if pend["total"] else ""
        extra += ", Neustart erforderlich" if pend["reboot"] else ""
        return f"{len(steps)} Schritt(e) erfolgreich{extra}"

    def _step_result(self, ctx: JobContext, step: dict, code: int, failures: list[str]) -> None:
        label = schedules.step_label(step) if step else "Schritt"
        if code == 0:
            ctx.say(f"✔ {label} erfolgreich")
        else:
            ctx.say(f"✘ {label} fehlgeschlagen (Exit-Code {code})")
            failures.append(f"{label} fehlgeschlagen (Exit-Code {code})")

    def _run_step(self, ctx: JobContext, conn: Connection, system: System, step: dict, idx: int,
                  state: dict, failures: list[str]) -> Connection:
        label = schedules.step_label(step)
        ctx.say(f"── Schritt {idx + 1}: {label}")
        if step.get("module") == "command":
            code = conn.run_script(step.get("command", ""), root=True, on_output=ctx.write, cancel=ctx.cancelled,
                                   timeout=int(step.get("timeout") or 3600))
            self._step_result(ctx, step, code, failures)
            return conn
        mod, action = resolve_action(step.get("module", ""), step.get("action", ""))
        if not mod.applies(system):
            ctx.say(f"Übersprungen - Modul '{mod.label}' ist für dieses System nicht aktiv.")
            return conn
        params = action.clean_params(step.get("params") or {})
        if action.special == "reboot":
            conn = self._reboot(ctx, conn, system, state, "step", idx)
            self._step_result(ctx, step, 0, failures)
            return conn
        if action.special == "reboot_if_required":
            system = self._refresh(ctx, conn, system.id)
            if system.fact.get("reboot_required"):
                conn = self._reboot(ctx, conn, system, state, "step", idx)
            else:
                ctx.say("Kein Neustart erforderlich.")
            self._step_result(ctx, step, 0, failures)
            return conn
        if action.key == "release_upgrade":
            ctx.say("Konfigurations-Backup (/etc) vor dem Release-Upgrade ...")
            self._backup(ctx, conn, system, "vor Release-Upgrade", ["/etc"])
        body, env = mod.script_for(action, system, params)
        code, conn = self._run_script(ctx, conn, system, body, env, action.detached, action.timeout, state, idx)
        self._step_result(ctx, step, code, failures)
        return conn

    # ------------------------------------------------------------------ job kinds
    def job_action(self, ctx, job_id, system_id, payload) -> str:
        return self._run_steps(ctx, job_id, system_id, {
            "steps": [{"module": payload["module"], "action": payload["action"], "params": payload.get("params", {})}],
            "stop_on_error": True, "reboot_policy": "never"})

    def job_maintenance(self, ctx, job_id, system_id, payload) -> str:
        return self._run_steps(ctx, job_id, system_id, payload)

    def job_command(self, ctx, job_id, system_id, payload) -> str:
        return self._run_steps(ctx, job_id, system_id, {
            "steps": [{"module": "command", "command": payload.get("command", ""),
                       "timeout": payload.get("timeout", 3600)}], "stop_on_error": True})

    def job_check(self, ctx, job_id, system_id, payload) -> str:
        system = self._system(system_id)
        with self._connect(ctx, system) as conn:
            with session_scope() as db:
                s = db.get(System, system_id)
                inventory.deep_check(conn, db, s, ctx.write, manual=True, detect=bool(payload.get("detect")))
                db.commit()
                summ = inventory.update_summary(s)
        lines = [f"{i['label']}: {i['text']}" for i in summ["items"]]
        if summ["release"]:
            lines.append(f"Release-Upgrade verfügbar: {summ['release']['label']}")
        if summ["reboot"]:
            lines.append("Neustart erforderlich")
        ctx.write("\n" + ("\n".join(lines) if lines else "Keine Updates ausstehend.") + "\n")
        return f"{summ['total']} Update(s) ausstehend" if summ["total"] else "Keine Updates ausstehend"

    def job_backup(self, ctx, job_id, system_id, payload) -> str:
        system = self._system(system_id)
        paths = sysbackup.parse_paths(payload.get("paths") or system.backup_paths or "/etc")
        with self._connect(ctx, system) as conn:
            self._backup(ctx, conn, system, payload.get("note", "manuell"), paths)
        return "Backup erstellt"

    def job_restore(self, ctx, job_id, system_id, payload) -> str:
        from .models import SystemBackup
        system = self._system(system_id)
        with session_scope() as db:
            b = db.get(SystemBackup, int(payload.get("backup_id", 0)))
            if b is None or b.system_id != system_id:
                raise JobFailed("Backup nicht gefunden")
            db.expunge(b)
        with self._connect(ctx, system) as conn:
            result = sysbackup.restore_backup(conn, b, payload.get("mode", "extract"), ctx.write)
        return f"Wiederhergestellt: {result}"

    def job_deploy_key(self, ctx, job_id, system_id, payload) -> str:
        system = self._system(system_id)
        pub = sshkeys.public_key()
        if not pub:
            raise JobFailed("Kein Servermanager-Schlüssel vorhanden")
        blob = pub.split()[1]
        script = f"""umask 077
mkdir -p "$HOME/.ssh" && touch "$HOME/.ssh/authorized_keys"
if grep -qF '{blob}' "$HOME/.ssh/authorized_keys"; then echo "Schlüssel bereits vorhanden"; else
  echo '{pub}' >> "$HOME/.ssh/authorized_keys" && echo "Schlüssel hinzugefügt"; fi
chmod 700 "$HOME/.ssh"; chmod 600 "$HOME/.ssh/authorized_keys"
"""
        if not system.password_enc:
            raise JobFailed("Für die Installation des Schlüssels wird ein hinterlegtes Passwort benötigt")
        # authenticate with the password only - the servermanager key must not be used to prove access
        pw_target = target_from_system(system)
        pw_target.pkey = None
        ctx.say(f"Verbinde mit {system.username}@{system.host}:{system.port} (Passwort-Anmeldung) ...")
        with Connection(pw_target, on_new_host_key=lambda line: inventory.store_host_key(system.id, line)) as conn:
            code = conn.run_script(script, root=False, on_output=ctx.write, timeout=60)
            if code != 0:
                raise JobFailed("Schlüssel konnte nicht installiert werden")
        ctx.say("Teste Anmeldung mit Schlüssel ...")
        target = target_from_system(system)
        target.password = ""
        target.pkey = sshkeys.default_private_key()
        with Connection(target) as test:
            test.check("true", timeout=30)
        ctx.say("Anmeldung per Schlüssel erfolgreich - stelle System auf Schlüssel-Anmeldung um.")
        with session_scope() as db:
            s = db.get(System, system_id)
            if s.sudo_mode == "password" and not s.sudo_password_enc and s.password_enc:
                s.sudo_password_enc = s.password_enc  # keep the password for sudo
            s.auth_method = AUTH_KEY
            s.private_key_enc = None
            s.key_passphrase_enc = None
            if payload.get("remove_password"):
                s.password_enc = None
            audit(db, None, "system.key_deployed", s.name)
        return "SSH-Schlüssel installiert, Anmeldung per Schlüssel aktiv"

    def job_enroll_verify(self, ctx, job_id, system_id, payload) -> str:
        system = self._system(system_id)
        deadline = time.monotonic() + 180
        conn = None
        last = None
        while time.monotonic() < deadline:
            try:
                conn = self._connect(ctx, system)
                break
            except SSHError as exc:
                last = exc
                ctx.say(f"Noch nicht erreichbar ({exc}) - neuer Versuch in 10 s")
                self.stop.wait(10)
        if conn is None:
            with session_scope() as db:
                s = db.get(System, system_id)
                s.status = STATUS_ERROR
                s.status_message = f"Nach Enrollment nicht erreichbar: {last}"
            raise JobFailed(f"System nach dem Enrollment nicht erreichbar: {last}")
        with conn:
            with session_scope() as db:
                s = db.get(System, system_id)
                inventory.deep_check(conn, db, s, ctx.write, manual=True, detect=True)
                s.status = STATUS_ONLINE
                s.enrolled_at = s.enrolled_at or utcnow()
                types = ", ".join(s.type_list)
        return f"System erreichbar, erkannte Typen: {types}"

    # ------------------------------------------------------------------ Proxmox API jobs
    def _pve_server(self, job_id: int) -> tuple[PveServer, dict]:
        with session_scope() as db:
            job = db.get(Job, job_id)
            server = db.get(PveServer, job.pve_id) if job.pve_id else None
            if server is None:
                raise JobFailed("Proxmox-Verbindung existiert nicht mehr")
            state = dict(job.remote or {})
            db.expunge(server)
            return server, state

    def _pve_task(self, ctx: JobContext, api, upid: Optional[str], state: dict, node: str = "") -> str:
        """Follow a Proxmox task (log + status) until it has finished; resumable via state['pve_task']."""
        if upid:
            if not isinstance(upid, str) or not upid.startswith("UPID:"):
                ctx.say("Aufgabe ohne Task-ID abgeschlossen.")
                return "OK"
            from .pveapi import upid_node
            state["pve_task"] = {"node": upid_node(upid) or node, "upid": upid, "n": 0}
            ctx.save_remote(state)
        task = state.get("pve_task")
        if not task:
            return "OK"
        cancel_sent = False
        errors = 0
        while True:
            if self.stop.is_set():
                raise Interrupted()
            try:
                lines = api.task_log(task["node"], task["upid"], start=task["n"], limit=500)
                for ln in lines:
                    if int(ln.get("n", 0)) > task["n"]:
                        ctx.write(str(ln.get("t", "")) + "\n")
                        task["n"] = int(ln["n"])
                if lines:
                    ctx.save_remote(state)
                st = api.task_status(task["node"], task["upid"])
                errors = 0
            except PveError as exc:
                errors += 1
                if errors > 90:
                    raise JobFailed(f"Proxmox-Task nicht mehr abfragbar: {exc}") from exc
                ctx.say(f"Abfrage fehlgeschlagen ({exc}) – neuer Versuch")
                self.stop.wait(10)
                continue
            if st.get("status") == "stopped":
                if len(lines) >= 500:
                    continue
                exit_status = st.get("exitstatus", "")
                state.pop("pve_task", None)
                ctx.save_remote(state)
                if cancel_sent:
                    raise CancelledError("Abgebrochen")
                if exit_status == "OK" or str(exit_status).startswith("WARNINGS"):
                    return exit_status
                raise JobFailed(f"Proxmox-Task fehlgeschlagen: {exit_status}")
            if not cancel_sent and ctx.cancelled():
                ctx.say("Abbruch angefordert – stoppe Proxmox-Task")
                try:
                    api.task_stop(task["node"], task["upid"])
                except PveError as exc:
                    ctx.say(f"Task konnte nicht gestoppt werden: {exc}")
                cancel_sent = True
            self.stop.wait(2)

    def job_pve(self, ctx, job_id, system_id, payload) -> str:
        server, state = self._pve_server(job_id)
        api = pve.client(server, timeout=60)
        op = payload["op"]
        node, gtype, vmid = pve.check_guest_ref(payload["node"], payload["type"], payload["vmid"])
        params = payload.get("params") or {}
        label = pve.OPS.get(op, {}).get("label", op)
        if state.get("pve_task"):
            ctx.say("Verfolge laufenden Proxmox-Task weiter ...")
            result = self._pve_task(ctx, api, None, state)
        else:
            ctx.say(f"{label}: {'CT' if gtype == 'lxc' else 'VM'} {vmid} auf {node} ({server.name})")
            upid = pve.start_op(api, op, node, gtype, vmid, params)
            result = self._pve_task(ctx, api, upid, state, node)
        if op == "destroy":
            with session_scope() as db:
                srv = db.get(PveServer, server.id)
                if srv and vmid in srv.watch_list:
                    srv.watch = [v for v in srv.watch_list if v != vmid]
                for s in db.execute(select(System).where(System.pve_server_id == server.id,
                                                         System.pve_vmid == vmid)).scalars():
                    s.pve_server_id = None
                    s.pve_vmid = None
        self._pve_refresh(server.id)
        return f"{label} erfolgreich" + (f" ({result})" if result and result != "OK" else "")

    def _pve_refresh(self, pve_id: int) -> None:
        try:
            with session_scope() as db:
                srv = db.get(PveServer, pve_id)
                if srv is not None:
                    integrations.poll(db, srv)
        except Exception:  # noqa: BLE001
            log.exception("refreshing proxmox %s failed", pve_id)

    def job_pve_create(self, ctx, job_id, system_id, payload) -> str:
        server, state = self._pve_server(job_id)
        api = pve.client(server, timeout=120)
        p = payload
        node, vmid = p["node"], int(p["vmid"])
        phase = state.get("phase") or "download"
        notes: list[str] = []

        def next_phase(name: str) -> None:
            state["phase"] = name
            ctx.save_remote(state)

        if phase == "download":
            if state.get("pve_task"):
                self._pve_task(ctx, api, None, state)
            elif p.get("download"):
                dl = p["download"]
                have = [c.get("volid") for c in api.storage_content(node, dl["storage"], "vztmpl")]
                if p["ostemplate"] in have:
                    ctx.say(f"Vorlage {dl['template']} ist bereits vorhanden.")
                else:
                    ctx.say(f"Lade Vorlage {dl['template']} nach {dl['storage']} herunter ...")
                    upid = api.post(f"nodes/{node}/aptinfo", storage=dl["storage"], template=dl["template"])
                    self._pve_task(ctx, api, upid, state, node)
            next_phase("create")
            phase = "create"
        if phase == "create":
            if state.get("pve_task"):
                self._pve_task(ctx, api, None, state)
            elif state.get("retried") and self._ct_exists(api, node, vmid, p["hostname"]):
                ctx.say(f"Container {vmid} ({p['hostname']}) existiert bereits – Anlegen wird übersprungen.")
            else:
                ctx.say(f"Lege Container {vmid} ({p['hostname']}) auf {node} an ...")
                upid = api.post(f"nodes/{node}/lxc", **pve.create_params(p))
                self._pve_task(ctx, api, upid, state, node)
            with session_scope() as db:
                job = db.get(Job, job_id)
                job.payload = {k: v for k, v in (job.payload or {}).items() if k != "password_enc"}
                if p.get("watch"):
                    srv = db.get(PveServer, server.id)
                    srv.watch = sorted(set(srv.watch_list) | {vmid})
            next_phase("start")
            phase = "start"
        if phase == "start":
            if p.get("start"):
                if state.get("pve_task"):
                    self._pve_task(ctx, api, None, state)
                elif state.get("retried") and api.guest_status(node, "lxc", vmid).get("status") == "running":
                    ctx.say("Container läuft bereits.")
                else:
                    ctx.say("Starte Container ...")
                    self._pve_task(ctx, api, api.post(f"nodes/{node}/lxc/{vmid}/status/start"), state, node)
            next_phase("network")
            phase = "network"
        ip = state.get("ip", "")
        if phase == "network":
            if p["ip_mode"] == "static":
                ip = p["ip"].split("/")[0]
            elif p.get("start"):
                ctx.say("Warte auf die DHCP-Adresse des Containers ...")
                deadline = time.monotonic() + 180
                while time.monotonic() < deadline and not ip:
                    if self.stop.is_set():
                        raise Interrupted()
                    try:
                        ip = pve.container_ipv4(api, node, vmid)
                    except PveError as exc:
                        ctx.say(f"Abfrage der Adresse fehlgeschlagen: {exc}")
                    if not ip:
                        self.stop.wait(5)
                if not ip:
                    raise JobFailed("Der Container hat innerhalb von 3 Minuten keine IPv4-Adresse erhalten "
                                    "(DHCP-Server im Netz der Bridge?)")
            if ip:
                ctx.say(f"IPv4-Adresse des Containers: {ip}")
            state["ip"] = ip
            next_phase("lease")
            phase = "lease"
        if phase == "lease":
            if p.get("static_lease") and ip:
                notes.append(self._static_lease(ctx, api, server, node, vmid, p["hostname"], ip))
            next_phase("register")
            phase = "register"
        if phase == "register":
            if p.get("register") and ip:
                notes.append(self._register_container(ctx, job_id, server, p, ip))
            next_phase("publish")
            phase = "publish"
        if phase == "publish":
            if p.get("publish") and ip:
                notes.append(self._publish(ctx, server, p, ip))
            next_phase("newt")
            phase = "newt"
        if phase == "newt" and p.get("newt"):
            with session_scope() as db:
                sys_row = db.execute(select(System).where(System.pve_server_id == server.id,
                                                          System.pve_vmid == vmid)).scalar_one_or_none()
                sid = sys_row.id if sys_row else None
            if sid is None:
                notes.append("Newt nicht eingerichtet (Container nicht als System aufgenommen)")
            else:
                notes.append(self._newt_setup(ctx, self._system(sid), p["newt"].get("pangolin_id"), p["newt"]))
                with session_scope() as db:
                    job = db.get(Job, job_id)
                    job.payload = {**(job.payload or {}), "newt": {k: v for k, v in p["newt"].items()
                                                                  if k != "secret_enc"}}
        self._pve_refresh(server.id)
        return f"Container {vmid} ({p['hostname']}) angelegt" + (f", IP {ip}" if ip else "") + \
            "".join(f"; {n}" for n in notes if n)

    @staticmethod
    def _ct_exists(api, node: str, vmid: int, hostname: str) -> bool:
        try:
            cfg = api.guest_config(node, "lxc", vmid)
        except PveError:
            return False
        if cfg.get("hostname") and cfg.get("hostname") != hostname:
            raise JobFailed(f"ID {vmid} ist bereits von einem anderen Container ({cfg.get('hostname')}) belegt")
        return True

    def _static_lease(self, ctx, api, server: PveServer, node: str, vmid: int, hostname: str, ip: str) -> str:
        if not server.router_id:
            ctx.say("Kein RouterOS für DHCP zugeordnet – Lease bleibt dynamisch.")
            return "Lease dynamisch (kein Router zugeordnet)"
        with session_scope() as db:
            router = db.get(RouterDevice, server.router_id)
            if router is None:
                return "Lease dynamisch (Router gelöscht)"
            db.expunge(router)
        mac = pve.net0_mac(api.guest_config(node, "lxc", vmid))
        mt = integrations.router_client(router)
        for _ in range(12):
            leases = [le for le in mt.get("ip/dhcp-server/lease")
                      if (mac and str(le.get("mac-address", "")).upper() == mac) or le.get("address") == ip]
            if leases:
                le = leases[0]
                if le.get("dynamic") == "true":
                    mt.command("ip/dhcp-server/lease/make-static", {".id": le[".id"]})
                mt.patch("ip/dhcp-server/lease", le[".id"], {"comment": f"servermanager: {hostname} (CT {vmid})"})
                ctx.say(f"DHCP-Lease {le.get('address')} ({mac or 'MAC ?'}) auf {router.name} statisch gesetzt.")
                return f"Lease {le.get('address')} statisch"
            self.stop.wait(5)
        ctx.say(f"Keine DHCP-Lease für {mac or ip} auf {router.name} gefunden – bitte manuell prüfen.")
        return "Lease nicht gefunden"

    def _register_container(self, ctx, job_id: int, server: PveServer, p: dict, ip: str) -> str:
        with session_scope() as db:
            job = db.get(Job, job_id)
            system = db.execute(select(System).where(System.pve_server_id == server.id,
                                                     System.pve_vmid == int(p["vmid"]))).scalar_one_or_none()
            if system is None:
                system = System(name=p["hostname"], hostname=p["hostname"], host=ip, port=22, username="root",
                                auth_method=AUTH_KEY, connection=CONN_DIRECT, types=["debian"],
                                tags=",".join(p.get("tags") or []), created_by=job.user_id,
                                pve_server_id=server.id, pve_vmid=int(p["vmid"]),
                                description=f"LXC {p['vmid']} auf {server.name}/{p['node']}")
                db.add(system)
                db.flush()
                user = db.get(User, job.user_id) if job.user_id else None
                if user is not None and not user.is_admin:
                    access.grant(db, user.id, system.id, LEVEL_FULL)
            else:
                system.host = ip
            sid = system.id
        ctx.say(f"Als System aufgenommen (#{sid}) – warte auf SSH ...")
        system = self._system(sid)
        deadline = time.monotonic() + 180
        conn = None
        while time.monotonic() < deadline:
            if self.stop.is_set():
                raise Interrupted()
            try:
                conn = inventory.connect(system, timeout=10)
                break
            except SSHError as exc:
                ctx.say(f"SSH noch nicht erreichbar ({exc}) – neuer Versuch in 10 s")
                self.stop.wait(10)
        if conn is None:
            return f"System #{sid} angelegt, SSH aber noch nicht erreichbar"
        with conn:
            with session_scope() as db:
                s = db.get(System, sid)
                inventory.deep_check(conn, db, s, ctx.write, manual=True, detect=True)
                s.status = STATUS_ONLINE
        return f"als System #{sid} aufgenommen"

    def _publish(self, ctx, server: PveServer, p: dict, ip: str) -> str:
        pub = p["publish"]
        if not server.pangolin_id:
            ctx.say("Keine Pangolin-Instanz zugeordnet – Dienst wird nicht veröffentlicht.")
            return "nicht veröffentlicht (kein Pangolin zugeordnet)"
        with session_scope() as db:
            pg = db.get(PangolinServer, server.pangolin_id)
            if pg is None:
                return "nicht veröffentlicht (Pangolin gelöscht)"
            db.expunge(pg)
        client = integrations.pangolin_client(pg)
        res = client.publish(p["hostname"], "http", pub["site_id"], ip, pub["port"], pub["method"],
                             pub.get("subdomain", ""), pub["domain_id"], sso=pub.get("sso", False))
        domain = res.get("fullDomain") or pub.get("subdomain", "")
        ctx.say(f"In Pangolin veröffentlicht: {domain} → {ip}:{pub['port']} (Resource {res.get('resourceId')})")
        with session_scope() as db:
            audit(db, None, "pangolin.publish", pg.name, f"{domain} -> {ip}:{pub['port']}")
        return f"veröffentlicht als {domain}"

    # ------------------------------------------------------------------ import of existing guests
    def _import_guest(self, ctx, server: PveServer, api, host: dict, g: dict, install_ssh: bool,
                      user_id: Optional[int]) -> str:
        """Management access for an existing guest + register it as system (host key pinned)."""
        from . import mgmt
        label = f"{'CT' if g['type'] == 'lxc' else 'VM'} {g['vmid']} ({g.get('name', '')})"
        ctx.say(f"── {label}: Management-Zugang anlegen")
        if g["type"] == "lxc":
            if host.get("conn") is None:
                if not server.system_id:
                    raise JobFailed("Für Container muss der Proxmox-Host als System (SSH) verknüpft sein")
                hs = self._system(server.system_id)
                host["conn"] = self._connect(ctx, hs)
                host["node"] = host["conn"].exec("hostname", timeout=20).stdout.strip()
            res = mgmt.inject_key_lxc(host["conn"], host["node"], g["node"], g["vmid"], install_ssh)
        else:
            res = mgmt.inject_key_vm(api, g["node"], g["vmid"], install_ssh)
        ctx.say(("Schlüssel hinterlegt" if res["added"] else "Schlüssel war bereits hinterlegt")
                + (", SSH-Server installiert" if res["sshd_installed"] else "")
                + f", {len(res['host_keys'])} Hostkey(s) übernommen")
        if res["root_login"] == "no":
            ctx.say("WARNUNG: PermitRootLogin=no – die Anmeldung als root per Schlüssel ist gesperrt.")
        ip = g.get("ip") or mgmt.pick_ip(res["ips"], prefer=lambda a: not a.startswith("172.17."))
        if not ip:
            raise JobFailed(f"{label}: keine IPv4-Adresse ermittelbar")
        with session_scope() as db:
            system = db.execute(select(System).where(System.pve_server_id == server.id,
                                                     System.pve_vmid == int(g["vmid"]))).scalar_one_or_none()
            if system is None:
                system = db.execute(select(System).where(System.host == ip)).scalars().first()
            name = (g.get("name") or f"guest-{g['vmid']}")[:120]
            if system is None:
                if db.execute(select(System.id).where(System.name == name)).first():
                    name = f"{name}-{g['vmid']}"
                system = System(name=name, hostname=g.get("name", ""), host=ip, port=22, username="root",
                                auth_method=AUTH_KEY, connection=CONN_DIRECT, types=["debian"], tags="import",
                                created_by=user_id, description=f"{label} auf {server.name}/{g['node']}")
                db.add(system)
                db.flush()
                user = db.get(User, user_id) if user_id else None
                if user is not None and not user.is_admin:
                    access.grant(db, user.id, system.id, LEVEL_FULL)
            elif system.host != ip and (g.get("ip") or (system.status != STATUS_ONLINE
                                                         and system.host not in res["ips"])):
                ctx.say(f"Adresse von {system.name}: {system.host} → {ip}")
                system.host = ip
            system.pve_server_id, system.pve_vmid = server.id, int(g["vmid"])
            if res["host_keys"]:
                system.host_keys = "\n".join(res["host_keys"])
            sid = system.id
            audit(db, None, "pve.import", system.name, f"{server.name}/{g['vmid']} {ip}")
        system = self._system(sid)
        try:
            with inventory.connect(system, timeout=15) as conn:
                with session_scope() as db:
                    s = db.get(System, sid)
                    inventory.deep_check(conn, db, s, ctx.write, manual=True, detect=True)
                    s.status = STATUS_ONLINE
        except SSHError as exc:
            raise JobFailed(f"{label}: System #{sid} angelegt, SSH-Prüfung fehlgeschlagen ({exc}) – "
                            "„Wiederholen“ richtet den Zugang erneut ein") from exc
        return f"{label}: als System #{sid} übernommen ({ip})"

    def job_pve_import(self, ctx, job_id, system_id, payload) -> str:
        server, state = self._pve_server(job_id)
        api = pve.client(server, timeout=60)
        host: dict = {}
        done, failed = [], []
        failed_items: list[dict] = []
        try:
            for g in payload.get("items", []):
                pve.check_guest_ref(g["node"], g["type"], g["vmid"])
                try:
                    done.append(self._import_guest(ctx, server, api, host, g, bool(payload.get("install_ssh")),
                                                   self._job_user(job_id)))
                    ctx.say(done[-1])
                except (JobFailed, SSHError, PveError, ValueError) as exc:
                    failed.append(f"{g.get('name', g['vmid'])}: {exc}")
                    failed_items.append(g)
                    ctx.say(f"FEHLER: {exc}")
        finally:
            if host.get("conn"):
                host["conn"].close()
            state["failed_items"] = failed_items + payload.get("items", [])[len(done) + len(failed_items):]
            ctx.save_remote(state)
        if failed and not done:
            raise JobFailed("; ".join(failed))
        return f"{len(done)} übernommen" + (f", {len(failed)} fehlgeschlagen: " + "; ".join(failed) if failed else "")

    def _job_user(self, job_id: int) -> Optional[int]:
        with session_scope() as db:
            return db.get(Job, job_id).user_id

    # ------------------------------------------------------------------ optimisation
    def job_optimize_scan(self, ctx, job_id, system_id, payload) -> str:
        from . import optimize
        with session_scope() as db:
            result = optimize.scan(db, ctx.say)
            optimize.save(db, result)
        summ = optimize.summary(result)
        for name, err in result["errors"].items():
            ctx.say(f"Nicht erreichbar – {name}: {err}")
        for p in result["proposals"]:
            ctx.write(f"  [{p['severity']}] {p['title']}\n")
        return f"{summ['total']} Vorschläge, davon {summ['actionable']} automatisch umsetzbar"

    def job_optimize(self, ctx, job_id, system_id, payload) -> str:
        ok, failed = [], []
        backed_up: set[int] = set()
        for item in payload.get("items", []):
            ctx.say(f"── {item['title']}")
            try:
                msg = self._apply_proposal(ctx, job_id, item, backed_up)
                ok.append(item["title"])
                ctx.say(f"✔ {msg or 'erledigt'}")
            except CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - one failing proposal must not stop the others
                failed.append(f"{item['title']}: {exc}")
                ctx.say(f"✘ {exc}")
            if ctx.cancelled():
                raise CancelledError("Abgebrochen")
        with session_scope() as db:
            audit(db, None, "optimize.apply", f"{len(ok)} umgesetzt", "\n".join(ok + failed)[:2000])
        if failed and not ok:
            raise JobFailed("; ".join(failed))
        return f"{len(ok)} umgesetzt" + (f", {len(failed)} fehlgeschlagen" if failed else "")

    def _apply_proposal(self, ctx, job_id: int, item: dict, backed_up: set) -> str:
        from . import routeros
        a, p = item["action"], item["params"]
        obj = item.get("obj") or {}

        def pve_server(pid: int) -> PveServer:
            with session_scope() as db:
                srv = db.get(PveServer, pid)
                if srv is None:
                    raise JobFailed("Proxmox-Verbindung existiert nicht mehr")
                db.expunge(srv)
                return srv

        if a in ("pve_set", "pve_backup_job", "pve_resize", "pve_import", "pve_vswitch"):
            srv = pve_server(obj["id"])
            api = pve.client(srv, timeout=60)
            if a == "pve_set":
                node, gtype, vmid = pve.check_guest_ref(p["node"], p["type"], p["vmid"])
                allowed = {"onboot", "agent", "net0"}
                cfg = {k: v for k, v in p["config"].items() if k in allowed}
                if "net0" in cfg:
                    current = api.guest_config(node, gtype, vmid).get("net0", "")

                    def core(net: str) -> set:
                        return {x for x in net.split(",") if not x.startswith("mtu=")}
                    if core(current) != core(cfg["net0"]):
                        raise JobFailed("Netzwerk-Konfiguration hat sich seit dem Scan geändert – bitte neu scannen")
                api.put(f"nodes/{node}/{gtype}/{vmid}/config", **cfg)
                return ", ".join(f"{k}={v}" for k, v in cfg.items())
            if a == "pve_backup_job":
                vmid = int(p["vmid"])
                jobs = api.backup_jobs()
                mine = next((j for j in jobs if "servermanager" in str(j.get("comment", ""))), None)
                if mine:
                    vmids = sorted({int(v) for v in str(mine.get("vmid", "")).split(",") if v.strip().isdigit()}
                                   | {vmid})
                    api.put(f"cluster/backup/{mine['id']}", vmid=",".join(map(str, vmids)))
                    return f"in Sicherungsjob {mine['id']} aufgenommen"
                api.post("cluster/backup", vmid=str(vmid), storage=p["storage"], schedule="02:30", mode="snapshot",
                         compress="zstd", enabled=1, comment="servermanager",
                         **{"prune-backups": "keep-daily=7,keep-weekly=4"})
                return f"Sicherungsjob angelegt (Storage {p['storage']}, täglich 02:30)"
            if a == "pve_resize":
                node, gtype, vmid = pve.check_guest_ref(p["node"], p["type"], p["vmid"])
                state: dict = {}
                self._pve_task(ctx, api, pve.start_op(api, "resize", node, gtype, vmid,
                                                      {"add_gb": int(p["add_gb"])}), state, node)
                return f"um {int(p['add_gb'])} GB vergrößert"
            if a == "pve_import":
                pve.check_guest_ref(p["node"], p["type"], p["vmid"])
                host: dict = {}
                try:
                    return self._import_guest(ctx, srv, api, host, p, bool(item.get("inputs", {}).get("install_ssh")),
                                              self._job_user(job_id))
                finally:
                    if host.get("conn"):
                        host["conn"].close()
            if a == "pve_vswitch":
                node = p["node"]
                pve.check_guest_ref(node, "lxc", 100)
                vlan = int(p["vlan"])
                if not 4000 <= vlan <= 4091:
                    raise JobFailed("VLAN-ID des vSwitch muss zwischen 4000 und 4091 liegen")
                nets = {n.get("iface") for n in api.networks(node)}
                vif = f"{p['phys']}.{vlan}"
                if vif not in nets:
                    api.post(f"nodes/{node}/network", type="vlan", iface=vif, mtu=1400, autostart=1,
                             comments="Hetzner vSwitch (servermanager)")
                if p["bridge"] not in nets:
                    api.post(f"nodes/{node}/network", type="bridge", iface=p["bridge"], bridge_ports=vif, mtu=1400,
                             autostart=1, comments="Hetzner vSwitch (servermanager)")
                upid = api.put(f"nodes/{node}/network")
                self._pve_task(ctx, api, upid, {}, node)
                return f"{vif} und {p['bridge']} auf {node} angelegt und aktiviert"
        if a == "pve_migrate":
            srv = pve_server(p["pve_id"])
            api = pve.client(srv, timeout=60)
            node, gtype, vmid = pve.check_guest_ref(p["node"], p["type"], p["vmid"])
            target = p["target"]
            pve.check_guest_ref(target, gtype, vmid)
            extra = {"restart": 1} if gtype == "lxc" else {"online": 1}
            upid = api.post(f"nodes/{node}/{gtype}/{vmid}/migrate", target=target, **extra)
            self._pve_task(ctx, api, upid, {}, node)
            self._pve_refresh(srv.id)
            return f"{p.get('name')} nach {target} migriert"
        if a == "pve_watch":
            with session_scope() as db:
                srv = db.get(PveServer, int(p["pve_id"]))
                srv.watch = sorted(set(srv.watch_list) | {int(p["vmid"])})
            return "wird überwacht"
        if a == "router_direct_ops":
            from .models import RouterDevice as _RD
            with session_scope() as db:
                router = db.get(_RD, int(p["router_id"]))
                if router is None:
                    raise JobFailed("Router existiert nicht mehr")
                db.expunge(router)
            ops = p["ops"]
            if any(op.get("m") != "add" or op.get("path") not in ("ip/address", "ip/firewall/nat") for op in ops):
                raise JobFailed("Unzulässige Router-Operation")
            mt = integrations.router_client(router, timeout=30)
            if router.id not in backed_up:
                ctx.say(f"Sicherung auf dem Router: {routeros.backup_before_change(mt)}.backup")
                backed_up.add(router.id)
            routeros.apply_ops(mt, ops, lambda line: ctx.write(f"  {line}\n"))
            return f"{len(ops)} Änderung(en) auf {router.name}"
        if a in ("router_finding", "router_nat_disable", "router_lease_static"):
            with session_scope() as db:
                router = db.get(RouterDevice, obj["id"])
                if router is None:
                    raise JobFailed("Router existiert nicht mehr")
                db.expunge(router)
            mt = integrations.router_client(router, timeout=30)
            if a == "router_finding":
                snap = routeros.snapshot_from_api(mt)
                target, _e = routeros.validate_target(router.target_cfg or routeros.detect_target(snap))
                f = next((x for x in routeros.analyze(snap, target) if x["id"] == p["finding"]), None)
                if f is None or f["status"] in ("ok", "check"):
                    return "bereits erledigt"
                if not f["applicable"]:
                    raise JobFailed("nicht automatisch umsetzbar")
                if router.id not in backed_up:
                    name = routeros.backup_before_change(mt)
                    backed_up.add(router.id)
                    ctx.say(f"Sicherung auf dem Router: {name}.backup")
                routeros.apply_ops(mt, f["ops"], lambda line: ctx.write(f"  {line}\n"))
                return f"{len(f['ops'])} Änderung(en)"
            if a == "router_lease_static":
                lease = next((le for le in mt.get("ip/dhcp-server/lease") if le.get(".id") == p["lease_id"]), None)
                if lease is None or lease.get("mac-address") != p.get("mac"):
                    raise JobFailed("Lease hat sich geändert – bitte neu scannen")
                if lease.get("dynamic") == "true":
                    mt.command("ip/dhcp-server/lease/make-static", {".id": lease[".id"]})
                return f"{lease.get('address')} statisch"
            # router_nat_disable: only if the service is (still) reachable through Pangolin
            with session_scope() as db:
                from . import discovery
                published = {(t["ip"], int(t["port"] or 0)) for t in discovery.services_map(db)["targets"]}
            if (p["ip"], int(p["port"])) not in published:
                raise JobFailed("Der Dienst ist nicht (mehr) über Pangolin veröffentlicht – Portfreigabe bleibt aktiv")
            mt.patch("ip/firewall/nat", p["nat_id"], {"disabled": "yes",
                                                      "comment": "servermanager: durch Pangolin ersetzt"})
            return "Portfreigabe deaktiviert"
        if a in ("publish_forward", "pangolin_mirror", "pangolin_sso"):
            with session_scope() as db:
                pg = db.get(PangolinServer, int(p["pangolin_id"]))
                if pg is None:
                    raise JobFailed("Pangolin-Verbindung existiert nicht mehr")
                db.expunge(pg)
            client = integrations.pangolin_client(pg)
            if a == "pangolin_sso":
                client.update_resource(int(p["resource_id"]), sso=True)
                return "Pangolin-Anmeldung aktiviert"
            domain_id = p.get("domain_id") or pg.default_domain_id
            if not pg.default_site_id or (p["protocol"] == "http" and not domain_id):
                raise JobFailed(f"Für {pg.name} Standard-Site und -Domain festlegen")
            sub = (item.get("inputs", {}).get("subdomain") or p.get("subdomain") or "").strip().lower()
            if p["protocol"] == "http":
                full = f"{sub}." if sub else ""
                taken = {r.get("fullDomain") for r in client.resources()}
                base = {d.get("domainId"): d.get("baseDomain") for d in client.domains()}.get(domain_id, "")
                if f"{full}{base}" in taken:
                    raise JobFailed(f"{full}{base} ist auf {pg.name} bereits vergeben")
            res = client.publish(p["name"], p["protocol"], pg.default_site_id, p["ip"], int(p["port"]),
                                 p.get("method") or "http", sub, domain_id,
                                 p.get("proxy_port"), sso=bool(p.get("sso", a == "publish_forward")))
            return f"veröffentlicht: {res.get('fullDomain') or p['name']} über {pg.name}"
        if a == "newt_restart":
            system = self._system(int(p["system_id"]))
            from .modules import get_module
            mod = get_module("newt")
            body, env = mod.script_for(mod.action("restart"), system, {})
            with self._connect(ctx, system) as conn:
                code = conn.run_script(body, env=env, root=True, on_output=ctx.write, timeout=300)
            if code != 0:
                raise JobFailed(f"Neustart fehlgeschlagen ({code})")
            return "Newt neu gestartet"
        raise JobFailed(f"Unbekannte Aktion {a}")

    # ------------------------------------------------------------------ newt tunnel
    def _newt_setup(self, ctx, system: System, pangolin_id: Optional[int], newt: dict) -> str:
        env = {"SM_TASK": "setup", "SM_NEWT_ID": newt["id"], "SM_NEWT_SECRET": security.decrypt(newt["secret_enc"]),
               "SM_NEWT_ENDPOINT": newt["endpoint"]}
        from .modules.base import load_script
        body = load_script("lib.sh") + "\n" + load_script("newt.sh")
        ctx.say(f"Richte Newt auf {system.name} ein (Endpoint {newt['endpoint']}) ...")
        with self._connect(ctx, system) as conn:
            code = conn.run_script(body, env=env, root=True, on_output=ctx.write, cancel=ctx.cancelled, timeout=900)
            if code != 0:
                raise JobFailed(f"Newt-Einrichtung fehlgeschlagen ({code})")
            with session_scope() as db:
                s = db.get(System, system.id)
                facts, apt = inventory.run_facts(conn, s)
                inventory.apply_facts(s, facts, apt)
                if "newt" not in s.type_list:
                    s.types = s.type_list + ["newt"]
                if pangolin_id:
                    pg = db.get(PangolinServer, pangolin_id)
                    if pg is not None:
                        pg.tunnel_system_id = s.id
                audit(db, None, "newt.setup", s.name, newt["endpoint"])
        return f"Newt auf {system.name} eingerichtet"

    def job_newt_setup(self, ctx, job_id, system_id, payload) -> str:
        system = self._system(system_id)
        msg = self._newt_setup(ctx, system, payload.get("pangolin_id"), payload["newt"])
        with session_scope() as db:
            job = db.get(Job, job_id)
            job.payload = {**(job.payload or {}), "newt": {k: v for k, v in payload["newt"].items()
                                                          if k != "secret_enc"}}
        return msg

    # ------------------------------------------------------------------ SSO
    def _sso_env(self, ctx, kind: str, target_id: int):
        """Callables to configure the target (occ via SSH for Nextcloud, API for Mailcow)."""
        from .models import MailcowServer
        from .modules.nextcloud import occ_task
        if kind == "nextcloud":
            system = self._system(target_id)
            holder: dict = {}

            def occ(task: str, env: dict) -> str:
                if "conn" not in holder:
                    holder["conn"] = self._connect(ctx, system)
                return occ_task(holder["conn"], system, task, env, timeout=600)
            return system, occ, None, holder
        with session_scope() as db:
            mc = db.get(MailcowServer, target_id)
            if mc is None:
                raise JobFailed("Mailcow-Verbindung existiert nicht mehr")
            db.expunge(mc)
        return mc, None, integrations.mailcow_client(mc), {}

    def job_sso_connect(self, ctx, job_id, system_id, payload) -> str:
        from . import sso
        from .models import SsoClient, SsoServer
        with session_scope() as db:
            srv = db.get(SsoServer, int(payload["sso_id"]))
            if srv is None:
                raise JobFailed("SSO-Verbindung existiert nicht mehr")
            db.expunge(srv)
        kind, target_id = payload["kind"], int(payload["target_id"])
        target, occ, mc, holder = self._sso_env(ctx, kind, target_id)
        try:
            data = sso.connect(integrations.sso_client(srv), srv, kind, target, payload["app_url"], ctx.say,
                               nextcloud_occ=occ, mailcow=mc)
        finally:
            if holder.get("conn"):
                holder["conn"].close()
        with session_scope() as db:
            db.add(SsoClient(sso_id=srv.id, target_kind=kind, target_id=target_id, status="active", **data))
            audit(db, None, "sso.connect", srv.name, f"{kind} {target.name}")
        return f"{target.name} ist mit {srv.name} verbunden (Anmeldung über {data['app_url']})"

    def job_sso_disconnect(self, ctx, job_id, system_id, payload) -> str:
        from . import sso
        from .models import SsoClient, SsoServer
        with session_scope() as db:
            client = db.get(SsoClient, int(payload["client_id"]))
            if client is None:
                return "bereits entfernt"
            srv = db.get(SsoServer, client.sso_id)
            db.expunge(client)
            db.expunge(srv)
        target, occ, mc, holder = self._sso_env(ctx, client.target_kind, client.target_id)
        try:
            sso.disconnect(integrations.sso_client(srv), srv, client, ctx.say, nextcloud_occ=occ, mailcow=mc)
        finally:
            if holder.get("conn"):
                holder["conn"].close()
        with session_scope() as db:
            row = db.get(SsoClient, client.id)
            if row is not None:
                db.delete(row)
            audit(db, None, "sso.disconnect", srv.name, f"{client.target_kind} {client.target_id}")
        return "SSO-Anbindung entfernt"

    def job_pve_token(self, ctx, job_id, system_id, payload) -> str:
        """Create an API token for the servermanager on a Proxmox host via SSH."""
        server, _state = self._pve_server(job_id)
        system = self._system(system_id)
        role = payload.get("role") or "PVEAdmin"
        if role not in ("PVEAdmin", "Administrator"):
            raise JobFailed("Ungültige Rolle")
        token_name = "sm" + time.strftime("%Y%m%d%H%M%S")
        with self._connect(ctx, system) as conn:
            ctx.say("Lege Benutzer servermanager@pve und API-Token an ...")
            script = (
                "set -e\n"
                "pveum user list --output-format json | grep -q '\"userid\":\"servermanager@pve\"' || "
                "pveum user add servermanager@pve --comment 'Servermanager API' >/dev/null\n"
                f"pveum acl modify / --users servermanager@pve --roles {role} >/dev/null\n"
                f"pveum user token add servermanager@pve {token_name} --privsep 0 --comment Servermanager "
                "--output-format json\n")
            res = conn.exec(f"bash -c {sshquote(script)}", root=True, timeout=60)
            if not res.ok:
                raise JobFailed("pveum fehlgeschlagen: " + (res.stderr or res.stdout).strip()[:500])
            import json as _json
            try:
                data = _json.loads(res.stdout.strip().splitlines()[-1])
            except (ValueError, IndexError) as exc:
                raise JobFailed("Unerwartete Ausgabe von pveum") from exc
            token_id, secret = data.get("full-tokenid", ""), data.get("value", "")
            if not token_id or not secret:
                raise JobFailed("pveum hat kein Token zurückgegeben")
            fp = conn.exec("for f in /etc/pve/local/pveproxy-ssl.pem /etc/pve/local/pve-ssl.pem; do "
                           "[ -f $f ] && { openssl x509 -in $f -noout -fingerprint -sha256; break; }; done",
                           root=True, timeout=30).stdout.strip()
        fingerprint = fp.split("=", 1)[-1].strip().upper() if "=" in fp else ""
        with session_scope() as db:
            srv = db.get(PveServer, server.id)
            srv.token_id = token_id
            srv.token_secret_enc = security.encrypt(secret)
            if fingerprint:
                srv.fingerprint = fingerprint
            if not srv.api_url:
                srv.api_url = f"https://{system.host}:8006"
            audit(db, None, "pve.token_created", srv.name, token_id)
        ctx.say(f"Token {token_id} gespeichert" + (f", Zertifikat {fingerprint[:23]}… gepinnt" if fingerprint else ""))
        self._pve_refresh(server.id)
        return f"API-Token {token_id} eingerichtet"

    # ------------------------------------------------------------------ periodic
    def periodic(self) -> None:
        with session_scope() as db:
            settings.set(db, "state.worker_heartbeat", utcnow().isoformat())
            schedules.tick(db)
            db.commit()
            schedules.finalize_runs(db)
            db.commit()
            status_min = int(settings.get(db, "checks.status_interval_min") or 15)
            deep_h = int(settings.get(db, "checks.deep_interval_hours") or 6)
            now = utcnow()
            with self.lock:
                busy = {s for s in self.running.values() if s} | set(self.checking)
            systems = db.execute(select(System).where(System.status != STATUS_PENDING)).scalars().all()
            for s in systems:
                if s.id in busy or s.maintenance_mode:
                    continue
                if status_min > 0 and (s.last_deep_check is None or now - s.last_deep_check > timedelta(hours=deep_h)):
                    self._submit_check(s.id, deep=True)
                elif status_min > 0 and (s.last_check is None or now - s.last_check > timedelta(minutes=status_min)):
                    self._submit_check(s.id, deep=False)
        self._poll_integrations()
        if time.monotonic() - self._last_ispc > 6 * 3600:
            self._last_ispc = time.monotonic()
            self._fetch_ispconfig_latest()
        self._daily_tasks()

    def _submit_check(self, system_id: int, deep: bool) -> None:
        with self.lock:
            if system_id in self.checking:
                return
            self.checking.add(system_id)
        self.check_pool.submit(self._check, system_id, deep)

    def _check(self, system_id: int, deep: bool) -> None:
        try:
            if not deep:
                inventory.quick_check(system_id)
                return
            with session_scope() as db:
                system = db.get(System, system_id)
                if system is None:
                    return
                try:
                    with inventory.connect(system) as conn:
                        inventory.deep_check(conn, db, system)
                except Exception as exc:  # noqa: BLE001
                    inventory.mark_unreachable(system, exc)
                    system.last_deep_check = utcnow()  # retry after the next deep interval
        except Exception:  # noqa: BLE001
            log.exception("check of system %s failed", system_id)
        finally:
            with self.lock:
                self.checking.discard(system_id)

    def _poll_integrations(self) -> None:
        with session_scope() as db:
            interval = int(settings.get(db, "integrations.poll_min") or 0)
            due = []
            for kind, model in integrations.MODELS.items():
                for obj in db.execute(select(model)).scalars():
                    if integrations.due(obj, interval):
                        due.append((kind, obj.id))
        for key in due:
            with self.lock:
                if key in self.polling:
                    continue
                self.polling.add(key)
            self.check_pool.submit(self._poll_one, key)

    def _poll_one(self, key: tuple[str, int]) -> None:
        try:
            with session_scope() as db:
                obj = integrations.get(db, *key)
                if obj is not None:
                    integrations.poll(db, obj)
        except Exception:  # noqa: BLE001
            log.exception("polling %s failed", key)
        finally:
            with self.lock:
                self.polling.discard(key)

    def _fetch_ispconfig_latest(self) -> None:
        with session_scope() as db:
            if not db.execute(select(System.id).where(System.types.like('%ispconfig%'))).first():
                return
        try:
            r = requests.get("https://www.ispconfig.org/downloads/ispconfig3_version.txt", timeout=15)
            r.raise_for_status()
            latest = r.text.strip()[:32]
            if latest and latest[0].isdigit():
                with session_scope() as db:
                    settings.set(db, "state.ispconfig_latest", latest)
                    settings.set(db, "state.ispconfig_checked", utcnow().isoformat())
        except requests.RequestException as exc:
            log.warning("ISPConfig version check failed: %s", exc)

    def _daily_tasks(self) -> None:
        from . import backup
        with session_scope() as db:
            tz = schedules.get_tz(db)
            local_now = datetime.now(tz)
            today = local_now.strftime("%Y-%m-%d")
            if settings.get(db, "backup.auto_enabled"):
                hour = int(settings.get(db, "backup.hour") or 2)
                last = settings.get(db, "state.last_auto_backup") or ""
                if local_now.hour >= hour and last != today:
                    settings.set(db, "state.last_auto_backup", today)
                    db.commit()
                    try:
                        path = backup.create_backup(db, note="automatisch", auto=True)
                        audit(db, None, "backup.auto", path.name)
                        backup.prune_backups(int(settings.get(db, "backup.keep") or 14))
                    except Exception as exc:  # noqa: BLE001
                        log.exception("automatic backup failed")
                        audit(db, None, "backup.auto_failed", "", str(exc))
            if self._last_daily != today:
                self._last_daily = today
                self._cleanup(db)

    def _cleanup(self, db) -> None:
        days = int(settings.get(db, "jobs.log_retention_days") or 90)
        cutoff = utcnow() - timedelta(days=days)
        old = db.execute(select(Job).where(Job.created_at < cutoff, Job.status.in_(JOB_FINAL))).scalars().all()
        for job in old:
            log_path(job.id).unlink(missing_ok=True)
            db.delete(job)
        if old:
            log.info("removed %s old jobs", len(old))


def main() -> None:
    setup_logging()
    bootstrap()
    worker = Worker()

    def _stop(signum, _frame):
        log.info("signal %s received", signum)
        worker.stop.set()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    worker.run_forever()


if __name__ == "__main__":
    main()
