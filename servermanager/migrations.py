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


MIGRATIONS: dict[int, Callable[[Connection], None]] = {
    1: lambda conn: None,  # initial schema
    2: _v2,
    3: _v3,
    4: _v4,
    5: _v5,
    6: _v6,
    7: _v7,
    8: _v8,
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
