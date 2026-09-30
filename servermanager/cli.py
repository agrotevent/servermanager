"""Command line interface: ``servermanager-cli <command>``."""
from __future__ import annotations

import argparse
import getpass
import os
import sys

from sqlalchemy import func, select

from . import security, settings, sshkeys
from .core import audit, bootstrap, setup_logging
from .db import get_engine, session_scope
from .models import ROLE_ADMIN, User


def _password(args) -> tuple[str, bool]:
    if getattr(args, "password_env", None):
        pw = os.environ.get(args.password_env, "")
        if not pw:
            raise SystemExit(f"Umgebungsvariable {args.password_env} ist leer")
        return pw, False
    if getattr(args, "password", None):
        return args.password, False
    if getattr(args, "generate", False) or not sys.stdin.isatty():
        return security.random_password(), True
    while True:
        pw = getpass.getpass("Passwort: ")
        if pw != getpass.getpass("Wiederholen: "):
            print("Die Passwörter stimmen nicht überein.")
            continue
        problems = security.password_problems(pw)
        if problems:
            print("\n".join(problems))
            continue
        return pw, False


def cmd_create_admin(args) -> int:
    with session_scope() as db:
        existing = db.execute(select(User).where(func.lower(User.username) == args.username.lower())).scalar_one_or_none()
        if existing and not args.update:
            print(f"Benutzer '{args.username}' existiert bereits (--update zum Zurücksetzen).", file=sys.stderr)
            return 1
        pw, generated = _password(args)
        user = existing or User(username=args.username)
        user.password_hash = security.hash_password(pw)
        user.role = ROLE_ADMIN
        user.active = True
        user.email = args.email or user.email or ""
        user.must_change_password = generated or bool(args.must_change)
        user.auth_version = (user.auth_version or 0) + 1
        user.locked_until = None
        user.failed_logins = 0
        if existing is None:
            db.add(user)
        audit(db, None, "cli.create_admin", args.username)
    print(f"Administrator '{args.username}' eingerichtet.")
    if generated:
        print(f"Initiales Passwort: {pw}")
        print("(Muss bei der ersten Anmeldung geändert werden.)")
    return 0


def cmd_reset_password(args) -> int:
    with session_scope() as db:
        user = db.execute(select(User).where(func.lower(User.username) == args.username.lower())).scalar_one_or_none()
        if user is None:
            print("Benutzer nicht gefunden.", file=sys.stderr)
            return 1
        pw, generated = _password(args)
        user.password_hash = security.hash_password(pw)
        user.must_change_password = True
        user.auth_version += 1
        user.locked_until = None
        user.failed_logins = 0
        audit(db, None, "cli.reset_password", user.username)
    print(f"Passwort für '{args.username}' zurückgesetzt." + (f" Neues Passwort: {pw}" if generated else ""))
    return 0


def cmd_disable_2fa(args) -> int:
    with session_scope() as db:
        user = db.execute(select(User).where(func.lower(User.username) == args.username.lower())).scalar_one_or_none()
        if user is None:
            print("Benutzer nicht gefunden.", file=sys.stderr)
            return 1
        user.totp_enabled = False
        user.totp_secret_enc = None
        user.auth_version += 1
        audit(db, None, "cli.disable_2fa", user.username)
    print(f"2FA für '{args.username}' deaktiviert.")
    return 0


def cmd_list_users(_args) -> int:
    with session_scope() as db:
        for u in db.execute(select(User).order_by(User.username)).scalars():
            print(f"{u.username:24} {u.role:8} {'aktiv' if u.active else 'inaktiv':8} 2FA={'ja' if u.totp_enabled else 'nein'}")
    return 0


def cmd_set(args) -> int:
    if args.key not in settings.DEFAULTS:
        print(f"Unbekannte Einstellung: {args.key}", file=sys.stderr)
        return 1
    with session_scope() as db:
        settings.set(db, args.key, settings.coerce(args.key, args.value))
    print(f"{args.key} gesetzt.")
    return 0


def cmd_get(args) -> int:
    with session_scope() as db:
        keys = [args.key] if args.key else sorted(settings.DEFAULTS)
        for k in keys:
            val = settings.get(db, k)
            if k in settings.SECRET_KEYS and val:
                val = "********"
            print(f"{k} = {val}")
    return 0


def cmd_migrate(_args) -> int:
    from .migrations import migrate
    print(f"Schema-Version: {migrate(get_engine())}")
    return 0


def cmd_pubkey(_args) -> int:
    print(sshkeys.public_key())
    return 0


def cmd_backup(args) -> int:
    from . import backup
    with session_scope() as db:
        path = backup.create_backup(db, note=args.note or "CLI", passphrase=args.passphrase)
    print(path)
    return 0


def cmd_restore(args) -> int:
    from pathlib import Path

    from . import backup
    from .helper import run_helper
    path = Path(args.file).resolve()
    if not path.exists():
        print("Datei nicht gefunden.", file=sys.stderr)
        return 1
    manifest = backup.inspect_backup(path, args.passphrase or "")
    print(f"Backup vom {manifest.get('created')} (Version {manifest.get('version')}, Host {manifest.get('hostname')})")
    if not args.yes and input("Aktuellen Stand ersetzen? [ja/NEIN] ").strip().lower() != "ja":
        return 1
    backup.stage_restore(path, args.passphrase or "")
    print(run_helper("restore", timeout=60).strip() or "Wiederherstellung gestartet.")
    return 0


def main(argv: list[str] | None = None) -> int:
    setup_logging()
    p = argparse.ArgumentParser(prog="servermanager-cli", description="Servermanager Verwaltung")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("create-admin", help="Administrator anlegen")
    s.add_argument("username")
    s.add_argument("--password", help="besser --password-env verwenden (sonst in der Prozessliste sichtbar)")
    s.add_argument("--password-env", metavar="VAR", help="Passwort aus dieser Umgebungsvariablen lesen")
    s.add_argument("--generate", action="store_true", help="Zufallspasswort erzeugen")
    s.add_argument("--email", default="")
    s.add_argument("--update", action="store_true", help="bestehenden Benutzer zurücksetzen")
    s.add_argument("--must-change", action="store_true")
    s.set_defaults(func=cmd_create_admin)

    s = sub.add_parser("reset-password", help="Passwort zurücksetzen")
    s.add_argument("username")
    s.add_argument("--password")
    s.add_argument("--generate", action="store_true")
    s.set_defaults(func=cmd_reset_password)

    s = sub.add_parser("disable-2fa", help="Zwei-Faktor-Anmeldung eines Benutzers deaktivieren")
    s.add_argument("username")
    s.set_defaults(func=cmd_disable_2fa)

    sub.add_parser("users", help="Benutzer auflisten").set_defaults(func=cmd_list_users)
    sub.add_parser("migrate", help="Datenbank migrieren").set_defaults(func=cmd_migrate)
    sub.add_parser("pubkey", help="SSH-Public-Key des Servermanagers ausgeben").set_defaults(func=cmd_pubkey)

    s = sub.add_parser("set", help="Einstellung setzen, z. B. general.base_url")
    s.add_argument("key")
    s.add_argument("value")
    s.set_defaults(func=cmd_set)
    s = sub.add_parser("get", help="Einstellungen anzeigen")
    s.add_argument("key", nargs="?")
    s.set_defaults(func=cmd_get)

    s = sub.add_parser("backup", help="Backup erstellen")
    s.add_argument("--passphrase")
    s.add_argument("--note")
    s.set_defaults(func=cmd_backup)
    s = sub.add_parser("restore", help="Backup wiederherstellen")
    s.add_argument("file")
    s.add_argument("--passphrase")
    s.add_argument("--yes", action="store_true")
    s.set_defaults(func=cmd_restore)

    args = p.parse_args(argv)
    bootstrap()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
