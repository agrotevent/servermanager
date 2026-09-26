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


MIGRATIONS: dict[int, Callable[[Connection], None]] = {
    1: lambda conn: None,  # initial schema
    2: _v2,
    3: _v3,
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
