"""Registry of all system modules."""
from __future__ import annotations

from .asterisk import AsteriskModule
from .base import Action, Module, Param, ParamError  # noqa: F401
from .cloudpanel import CloudPanelModule
from .debian import DebianModule
from .docker import DockerModule
from .ispconfig import ISPConfigModule
from .mailcow import MailcowModule
from .newt import NewtModule
from .nextcloud import NextcloudModule
from .proxmox import ProxmoxModule

MODULES: dict[str, Module] = {m.key: m for m in (
    DebianModule(), NextcloudModule(), DockerModule(), ISPConfigModule(), ProxmoxModule(), NewtModule(),
    AsteriskModule(), CloudPanelModule(), MailcowModule())}

TYPE_LABELS = {k: m.label for k, m in MODULES.items()}
TYPE_LABELS["debian"] = "Debian"


def get_module(key: str) -> Module:
    try:
        return MODULES[key]
    except KeyError as exc:
        raise ParamError(f"Unbekanntes Modul {key}") from exc


def modules_for(system) -> list[Module]:
    return [m for m in MODULES.values() if m.applies(system)]


def resolve_action(module_key: str, action_key: str) -> tuple[Module, Action]:
    mod = get_module(module_key)
    return mod, mod.action(action_key)


def schedulable_actions() -> list[tuple[Module, Action]]:
    out = []
    for m in MODULES.values():
        for a in m.actions:
            if a.schedulable and not a.hidden and not a.special.startswith("reboot"):
                out.append((m, a))
    return out
