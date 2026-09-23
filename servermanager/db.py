"""Database engine / session handling (SQLAlchemy 2.x)."""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


_engine: Engine | None = None
_session_factory: sessionmaker | None = None


def _sqlite_pragmas(dbapi_conn, _record):
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA foreign_keys=ON")
    cur.execute("PRAGMA busy_timeout=15000")
    cur.execute("PRAGMA synchronous=NORMAL")
    cur.close()


def init_engine(url: str) -> Engine:
    global _engine, _session_factory
    kwargs: dict = {"future": True, "pool_pre_ping": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
    _engine = create_engine(url, **kwargs)
    if url.startswith("sqlite"):
        event.listen(_engine, "connect", _sqlite_pragmas)
    # autoflush disabled: flushes only happen on commit, so no write lock is taken implicitly
    # (SQLite) while long running SSH operations are in progress.
    _session_factory = sessionmaker(bind=_engine, expire_on_commit=False, autoflush=False, future=True)
    return _engine


def get_engine() -> Engine:
    if _engine is None:
        raise RuntimeError("database not initialised")
    return _engine


def new_session() -> Session:
    if _session_factory is None:
        raise RuntimeError("database not initialised")
    return _session_factory()


@contextmanager
def session_scope() -> Iterator[Session]:
    db = new_session()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
