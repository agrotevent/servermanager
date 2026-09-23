"""Self update from the git repository."""
from __future__ import annotations

import subprocess
from pathlib import Path

from . import __version__
from .config import get_config
from .helper import HelperError, run_helper


def _git(*args: str, timeout: int = 60) -> str:
    cfg = get_config()
    res = subprocess.run(["git", "-C", cfg.repo_dir, *args], capture_output=True, text=True, timeout=timeout)
    if res.returncode != 0:
        raise HelperError(res.stderr.strip() or f"git {' '.join(args)} fehlgeschlagen")
    return res.stdout.strip()


def current() -> dict:
    cfg = get_config()
    info = {"version": __version__, "branch": cfg.branch, "commit": "", "date": "", "subject": "", "remote": ""}
    try:
        info["commit"] = _git("rev-parse", "--short=12", "HEAD")
        info["date"] = _git("log", "-1", "--format=%ci")
        info["subject"] = _git("log", "-1", "--format=%s")
        info["remote"] = _git("config", "--get", "remote.origin.url")
        if "@" in info["remote"] and "://" in info["remote"]:
            scheme, rest = info["remote"].split("://", 1)
            info["remote"] = f"{scheme}://***@{rest.split('@', 1)[1]}"   # hide tokens
    except (HelperError, OSError, subprocess.SubprocessError) as exc:
        info["error"] = str(exc)
    return info


def check() -> dict:
    """Fetch the remote branch and list pending commits."""
    cfg = get_config()
    if cfg.use_sudo:
        run_helper("git-fetch", timeout=120)
    else:
        _git("fetch", "--quiet", "origin", cfg.branch, timeout=120)
    ref = f"origin/{cfg.branch}"
    head = _git("rev-parse", "HEAD")
    remote = _git("rev-parse", ref)
    commits = []
    if head != remote:
        out = _git("log", "--format=%h%x09%ci%x09%s", f"HEAD..{ref}")
        for line in out.splitlines():
            parts = line.split("\t", 2)
            if len(parts) == 3:
                commits.append({"sha": parts[0], "date": parts[1], "subject": parts[2]})
    return {"head": head[:12], "remote": remote[:12], "available": bool(commits), "commits": commits}


def start() -> str:
    """Start the update detached (systemd-run) - the services get restarted."""
    return run_helper("self-update", timeout=60)


UPDATE_LOG = Path("/var/log/servermanager/update.log")


def log_text(max_bytes: int = 200_000) -> str:
    p = UPDATE_LOG if UPDATE_LOG.exists() else Path(get_config().data_dir) / "update.log"
    if not p.exists():
        return ""
    data = p.read_bytes()[-max_bytes:]
    return data.decode("utf-8", "replace")
