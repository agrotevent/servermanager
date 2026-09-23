"""Module framework: every managed software type (Debian, Docker, ...) is a Module
with a list of Actions (remote scripts) plus optional live panel data and
update detection."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from ..models import LEVEL_OPERATE, System

if TYPE_CHECKING:  # pragma: no cover
    from ..ssh import Connection

SCRIPTS_DIR = Path(__file__).parent / "scripts"
NAME_RE = r"^[A-Za-z0-9][A-Za-z0-9@._:+-]{0,127}$"


@lru_cache(maxsize=None)
def load_script(name: str) -> str:
    return (SCRIPTS_DIR / name).read_text()


class ParamError(ValueError):
    pass


@dataclass
class Param:
    name: str
    label: str
    kind: str = "text"            # text | select | bool
    pattern: str = NAME_RE
    choices: list[tuple[str, str]] = field(default_factory=list)
    default: str = ""
    required: bool = True
    help: str = ""

    def clean(self, raw: Any) -> str:
        if self.kind == "bool":
            return "1" if str(raw).lower() in ("1", "true", "on", "yes") else "0"
        value = "" if raw is None else str(raw).strip()
        if not value:
            if self.required and not self.default:
                raise ParamError(f"{self.label} ist erforderlich")
            return self.default
        if self.kind == "select":
            if value not in {c[0] for c in self.choices}:
                raise ParamError(f"Ungültiger Wert für {self.label}")
            return value
        if self.pattern and not re.match(self.pattern, value):
            raise ParamError(f"Ungültiger Wert für {self.label}")
        return value


@dataclass
class Action:
    key: str
    label: str
    script: str
    env: dict = field(default_factory=dict)
    params: list[Param] = field(default_factory=list)
    level: str = LEVEL_OPERATE
    description: str = ""
    confirm: str = ""
    detached: bool = False
    timeout: int = 3 * 3600
    schedulable: bool = True
    danger: bool = False
    hidden: bool = False          # not offered as a button (used from panels)
    group: str = ""
    special: str = ""             # handled by the job runner (reboot, ...)

    def clean_params(self, raw: dict) -> dict:
        return {p.name: p.clean(raw.get(p.name)) for p in self.params}

    def describe(self, params: dict) -> str:
        if not params:
            return self.label
        extras = ", ".join(f"{v}" for k, v in params.items() if v and v not in ("0", "1"))
        return f"{self.label} ({extras})" if extras else self.label


class Module:
    key: str = ""
    label: str = ""
    description: str = ""
    panel_template: Optional[str] = None
    always: bool = False

    def __init__(self) -> None:
        self.actions: list[Action] = self.build_actions()
        self._by_key = {a.key: a for a in self.actions}

    # ---- to be overridden ------------------------------------------------
    def build_actions(self) -> list[Action]:
        return []

    def detect(self, facts: dict) -> bool:
        return False

    def env(self, system: System) -> dict:
        return {}

    def panel(self, conn: "Connection", system: System) -> dict:
        return {}

    def check(self, conn: "Connection", system: System, ctx: dict) -> Optional[dict]:
        """Deep update check. Returns data stored in system.updates[self.key]."""
        return None

    def summary(self, system: System) -> Optional[dict]:
        """Short pending-update summary for the update overview:
        ``{"count": int, "text": str, "severity": "info|warn|danger"}``"""
        return None

    # ---- helpers -----------------------------------------------------------
    def applies(self, system: System) -> bool:
        return self.always or system.has_type(self.key)

    def action(self, key: str) -> Action:
        try:
            return self._by_key[key]
        except KeyError as exc:
            raise ParamError(f"Unbekannte Aktion {self.key}.{key}") from exc

    def visible_actions(self) -> list[Action]:
        return [a for a in self.actions if not a.hidden]

    def script_for(self, action: Action, system: System, params: dict) -> tuple[str, dict]:
        env = dict(self.env(system))
        env.update(action.env)
        for p in action.params:
            env[f"SM_{p.name.upper()}"] = params.get(p.name, p.default)
        body = load_script("lib.sh") + "\n" + load_script(action.script)
        return body, env


def run_module_script(conn: "Connection", module: Module, script: str, env: dict, timeout: int = 120) -> str:
    """Run a helper script synchronously (used by panels / checks)."""
    from ..ssh import SSHError
    body = load_script("lib.sh") + "\n" + load_script(script)
    out: list[str] = []
    code = conn.run_script(body, env=env, root=True, on_output=out.append, timeout=timeout)
    text = "".join(out)
    if code != 0:
        raise SSHError(f"{module.label}: Skript fehlgeschlagen ({code}): {text.strip()[-400:]}")
    return text


def parse_kv(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        if re.match(r"^[a-z_][a-z0-9_]*$", k):
            out.setdefault(k, []).append(v.strip())
    return out

