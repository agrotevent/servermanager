"""Calls into the privileged helper script (bin/sm-helper) via sudo."""
from __future__ import annotations

import subprocess

from .config import get_config


class HelperError(Exception):
    def __init__(self, message: str, returncode: int = 1):
        super().__init__(message)
        self.returncode = returncode


def run_helper(*args: str, timeout: int = 120, check: bool = True, stdin: str | None = None) -> str:
    cfg = get_config()
    cmd = [cfg.helper, *args]
    if cfg.use_sudo:
        cmd = ["sudo", "-n", *cmd]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=stdin)
    except FileNotFoundError as exc:
        raise HelperError(f"Hilfsprogramm nicht gefunden: {cfg.helper}") from exc
    except subprocess.TimeoutExpired as exc:
        raise HelperError(f"Zeitüberschreitung bei sm-helper {' '.join(args)}") from exc
    if check and res.returncode != 0:
        if res.returncode < 0:
            raise HelperError(f"sm-helper {args[0]} wurde durch Signal {-res.returncode} beendet", res.returncode)
        raise HelperError((res.stderr or res.stdout).strip() or f"sm-helper {args[0]} fehlgeschlagen "
                          f"(Exit-Code {res.returncode})", res.returncode)
    return res.stdout
