"""Very small schema migration mechanism.

A fresh database is created with ``create_all`` and stamped with the latest
schema version. Existing databases get the ordered migration steps applied.
New tables are always created by ``create_all``; migration steps only need
to handle changes to existing tables (new columns, data fixes, ...).
"""
from __future__ import annotations

import logging
from typing import Callable

from sqlalchemy import inspect, text
from sqlalchemy.engine import Connection, Engine

from . import models  # noqa: F401 - registers the ORM models
from .db import Base

log = logging.getLogger(__name__)


def add_column_if_missing(conn: Connection, table: str, column: str, ddl: str) -> None:
    cols = {c["name"] for c in inspect(conn).get_columns(table)}
    if column not in cols:
        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))


# version -> migration function. Append new steps, never change old ones.
def _v2(conn: Connection) -> None:
    # Proxmox/RouterOS/Pangolin integrations (new tables are created by create_all)
    add_column_if_missing(conn, "systems", "pve_server_id", "INTEGER")
    add_column_if_missing(conn, "systems", "pve_vmid", "INTEGER")
    add_column_if_missing(conn, "jobs", "pve_id", "INTEGER REFERENCES pve_servers(id) ON DELETE CASCADE")


def _v3(conn: Connection) -> None:
    # redundant Pangolin paths, Newt tunnel systems, hosting of Proxmox servers
    add_column_if_missing(conn, "pangolin_servers", "role", "VARCHAR(16) NOT NULL DEFAULT 'primary'")
    add_column_if_missing(conn, "pangolin_servers", "tunnel_system_id", "INTEGER")
    add_column_if_missing(conn, "pve_servers", "hosting", "VARCHAR(16) NOT NULL DEFAULT 'local'")
    add_column_if_missing(conn, "pve_servers", "vswitch_vlan", "INTEGER")


def _v4(conn: Connection) -> None:
    # domain mapping primary -> backup Pangolin
    add_column_if_missing(conn, "pangolin_servers", "domain_map", "TEXT")


def _v5(conn: Connection) -> None:
    # Zammad: link of tickets and target of a Zabbix connection (tables of 1.8-1.10 exist via create_all)
    insp = inspect(conn)
    if "tickets" in insp.get_table_names():
        add_column_if_missing(conn, "tickets", "zammad_server_id", "INTEGER")
        add_column_if_missing(conn, "tickets", "zammad_ticket_id", "INTEGER")
        add_column_if_missing(conn, "tickets", "zammad_number", "VARCHAR(32) NOT NULL DEFAULT ''")
        add_column_if_missing(conn, "tickets", "zammad_error", "TEXT NOT NULL DEFAULT ''")
    if "zabbix_servers" in insp.get_table_names():
        add_column_if_missing(conn, "zabbix_servers", "zammad_id", "INTEGER")


def _v6(conn: Connection) -> None:
    # TOTP codes can be used only once
    add_column_if_missing(conn, "users", "totp_last_step", "INTEGER")


def _v7(conn: Connection) -> None:
    # Pangolin SSO: id of the identity provider inside Pangolin
    if "sso_clients" in inspect(conn).get_table_names():
        add_column_if_missing(conn, "sso_clients", "target_ref", "VARCHAR(64) NOT NULL DEFAULT ''")


def _v8(conn: Connection) -> None:
    # login to the servermanager through authentik: encrypted client secret
    if "sso_clients" in inspect(conn).get_table_names():
        add_column_if_missing(conn, "sso_clients", "secret_enc", "TEXT NOT NULL DEFAULT ''")


def _v9(conn: Connection) -> None:
    # easybell: AMI over TLS (port 5039) or plain
    if "easybell_accounts" in inspect(conn).get_table_names():
        add_column_if_missing(conn, "easybell_accounts", "transport", "VARCHAR(8) NOT NULL DEFAULT 'auto'")


def _v10(conn: Connection) -> None:
    # rights via authentik groups: groups of the last SSO login
    add_column_if_missing(conn, "users", "sso_groups", "TEXT")
    add_column_if_missing(conn, "users", "sso_groups_at", "DATETIME")


def _v11(conn: Connection) -> None:
    # DNS for Pangolin publications: target of the records (host name or IP)
    if "pangolin_servers" in inspect(conn).get_table_names():
        add_column_if_missing(conn, "pangolin_servers", "dns_target", "VARCHAR(255) NOT NULL DEFAULT ''")


def _v12(conn: Connection) -> None:
    # user groups: the rights of authentik groups from 1.21 (table group_access) become groups
    if "group_access" not in inspect(conn).get_table_names():
        return
    rows = conn.execute(text("SELECT group_name, kind, obj_id, level FROM group_access")).fetchall()
    ids: dict[str, int] = {}
    for name, kind, obj_id, level in rows:
        key = str(name).lower()
        if key not in ids:
            found = conn.execute(text("SELECT id FROM user_groups WHERE lower(name) = :n"), {"n": key}).fetchone()
            if found is None:
                conn.execute(text("INSERT INTO user_groups (name, description, sso_group, created_at) "
                                  "VALUES (:n, :d, :s, CURRENT_TIMESTAMP)"),
                             {"n": str(name)[:128], "d": "aus den Hetzner-Rechten übernommen", "s": str(name)[:150]})
                found = conn.execute(text("SELECT id FROM user_groups WHERE name = :n"), {"n": str(name)[:128]}).fetchone()
            ids[key] = found[0]
        exists = conn.execute(text("SELECT 1 FROM group_rights WHERE group_id = :g AND kind = :k AND obj_id = :o"),
                              {"g": ids[key], "k": kind, "o": obj_id}).fetchone()
        if exists is None:
            conn.execute(text("INSERT INTO group_rights (group_id, kind, obj_id, level) VALUES (:g, :k, :o, :l)"),
                         {"g": ids[key], "k": kind, "o": obj_id, "l": level})
    conn.execute(text("DELETE FROM group_access"))


MIGRATIONS: dict[int, Callable[[Connection], None]] = {
    1: lambda conn: None,  # initial schema
    2: _v2,
    3: _v3,
    4: _v4,
    5: _v5,
    6: _v6,
    7: _v7,
    8: _v8,
    9: _v9,
    10: _v10,
    11: _v11,
    12: _v12,
}
SCHEMA_VERSION = max(MIGRATIONS)


def current_version(engine: Engine) -> int | None:
    insp = inspect(engine)
    if "meta" not in insp.get_table_names():
        return None
    with engine.connect() as conn:
        row = conn.execute(text("SELECT value FROM meta WHERE key='schema_version'")).fetchone()
        return int(row[0]) if row else None


def migrate(engine: Engine) -> int:
    version = current_version(engine)
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        if version is None:
            conn.execute(text("INSERT INTO meta(key, value) VALUES ('schema_version', :v)"),
                         {"v": str(SCHEMA_VERSION)})
            log.info("database created with schema version %s", SCHEMA_VERSION)
            return SCHEMA_VERSION
        for v in range(version + 1, SCHEMA_VERSION + 1):
            log.info("applying migration %s", v)
            MIGRATIONS[v](conn)
            conn.execute(text("UPDATE meta SET value=:v WHERE key='schema_version'"), {"v": str(v)})
    return SCHEMA_VERSION
