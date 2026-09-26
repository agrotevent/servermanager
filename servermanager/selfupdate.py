"""Self update from the git repository."""
from __future__ import annotations

import re
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


class BranchMissing(HelperError):
    """The configured update branch does not exist in the repository."""


def check() -> dict:
    """Fetch the remote branch and list pending commits."""
    cfg = get_config()
    try:
        if cfg.use_sudo:
            run_helper("git-fetch", timeout=120)
        else:
            _git("fetch", "--quiet", "origin", cfg.branch, timeout=120)
    except HelperError as exc:
        if "couldn't find remote ref" in str(exc) or "Couldn't find remote ref" in str(exc):
            raise BranchMissing(f"Der eingestellte Update-Branch „{cfg.branch}“ existiert im Repository nicht. "
                                "Bitte unten unter „Update-Branch“ einen vorhandenen Branch wählen.") from exc
        raise
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


TOKEN_RE = re.compile(r"^[A-Za-z0-9_.~-]{8,255}$")
TOKEN_USER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def token_status() -> dict:
    """State of the stored repository access token (never the token itself)."""
    cfg = get_config()
    if not cfg.use_sudo:
        return {"available": False}
    try:
        out = run_helper("git-token-status", timeout=15).strip()
    except HelperError as exc:
        return {"available": False, "error": str(exc)}
    parts = out.split()
    if not parts or parts[0] != "set":
        return {"available": True, "set": False}
    return {"available": True, "set": True, "user": parts[1] if len(parts) > 1 else "",
            "host": parts[2] if len(parts) > 2 else "", "hint": parts[3] if len(parts) > 3 else ""}


def set_token(token: str, user: str = "x-access-token") -> str:
    """Store (and verify) a new access token; an empty token removes it."""
    token = token.strip()
    user = user.strip() or "x-access-token"
    if token and not TOKEN_RE.match(token):
        raise HelperError("Ungültiges Token (erlaubt: A-Z a-z 0-9 _ . ~ -, mind. 8 Zeichen)")
    if not TOKEN_USER_RE.match(user):
        raise HelperError("Ungültiger Token-Benutzer")
    return run_helper("set-git-token", user, stdin=token + "\n", timeout=60).strip()


BRANCH_RE = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")


def branches() -> dict:
    """Remote branches, the repository's default branch and the configured branch."""
    cfg = get_config()
    out = {"branches": [], "default": "", "current": cfg.branch, "error": ""}
    try:
        if cfg.use_sudo:
            text = run_helper("git-branches", timeout=60)
        else:
            heads = _git("ls-remote", "--heads", "origin", timeout=60)
            text = "\n".join("branch=" + line.split("refs/heads/", 1)[1] for line in heads.splitlines()
                             if "refs/heads/" in line)
            sym = _git("ls-remote", "--symref", "origin", "HEAD", timeout=60)
            m = re.search(r"ref: refs/heads/(\S+)\s+HEAD", sym)
            if m:
                text += f"\ndefault={m.group(1)}"
    except HelperError as exc:
        out["error"] = str(exc)
        return out
    for line in text.splitlines():
        key, _, val = line.partition("=")
        if key == "branch" and BRANCH_RE.match(val):
            out["branches"].append(val)
        elif key == "default" and BRANCH_RE.match(val):
            out["default"] = val
    out["branches"].sort(key=lambda b: (b != out["default"], b))
    out["missing"] = bool(out["branches"]) and cfg.branch not in out["branches"]
    return out


def set_branch(name: str) -> str:
    """Switch the update branch (as root in servermanager.conf) and reload the configuration."""
    from . import config as config_mod
    if not BRANCH_RE.match(name or ""):
        raise HelperError("Ungültiger Branch-Name")
    cfg = get_config()
    if not cfg.use_sudo:
        raise HelperError("Ohne sudo-Hilfsdienst bitte den Branch in der Konfigurationsdatei ändern")
    msg = run_helper("set-branch", name, timeout=120).strip()
    config_mod.set_config(config_mod.load_config())
    return msg


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
