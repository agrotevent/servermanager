"""Calls into the privileged helper script (bin/sm-helper) via sudo."""
from __future__ import annotations

import subprocess

from .config import get_config


class HelperError(Exception):
    pass


def run_helper(*args: str, timeout: int = 120, check: bool = True) -> str:
    cfg = get_config()
    cmd = [cfg.helper, *args]
    if cfg.use_sudo:
        cmd = ["sudo", "-n", *cmd]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        raise HelperError(f"Hilfsprogramm nicht gefunden: {cfg.helper}") from exc
    except subprocess.TimeoutExpired as exc:
        raise HelperError(f"Zeitüberschreitung bei sm-helper {' '.join(args)}") from exc
    if check and res.returncode != 0:
        raise HelperError((res.stderr or res.stdout).strip() or f"sm-helper {args[0]} fehlgeschlagen")
    return res.stdout
