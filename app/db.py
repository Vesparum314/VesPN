"""SQLAlchemy engine/session + Base. SQLite by default (one file in a volume)."""

from __future__ import annotations

import os
from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session

from .config import settings

_connect_args = {}
if settings.database_url.startswith("sqlite"):
    _connect_args = {"check_same_thread": False}
    # ensure the sqlite directory exists
    path = settings.database_url.split("sqlite:///", 1)[-1]
    if path and path not in (":memory:",):
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)

engine = create_engine(settings.database_url, connect_args=_connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from . import models  # noqa: F401  (register mappers)

    # Model A migration: `routes` and `issued_configs` changed shape (exit→pool,
    # pool-wide configs). Rebuild those BEFORE create_all so they come back with
    # the new schema; everything else migrates additively.
    _rebuild_changed_tables()
    Base.metadata.create_all(bind=engine)
    _add_columns()
    _seed_default_group()


def _rebuild_changed_tables() -> None:
    """Drop tables whose shape changed on an OLD install so create_all recreates
    them fresh (pool-based). Destructive by design and agreed with the user:
      * issued_configs — regenerated on next device view (new pool identity makes
        old configs invalid anyway);
      * routes — recreated as gate+pool; existing devices are unlinked (route_id
        NULLed) so users re-pick a route.
    A fresh DB has neither table yet, so this is a no-op there."""
    with engine.begin() as conn:
        def table_exists(name: str) -> bool:
            row = conn.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=:n", {"n": name}
            ).fetchone()
            return row is not None

        def cols(table: str) -> list[str]:
            return [row[1] for row in conn.exec_driver_sql(f"PRAGMA table_info({table})")]

        if table_exists("routes") and "pool_id" not in cols("routes"):
            if table_exists("devices") and "route_id" in cols("devices"):
                conn.exec_driver_sql("UPDATE devices SET route_id = NULL")
            conn.exec_driver_sql("DROP TABLE routes")
        if table_exists("issued_configs") and "uuid" not in cols("issued_configs"):
            conn.exec_driver_sql("DROP TABLE issued_configs")


def _add_columns() -> None:
    """Additive column migrations for surviving tables (no Alembic)."""
    with engine.begin() as conn:
        def cols(table: str) -> list[str]:
            return [row[1] for row in conn.exec_driver_sql(f"PRAGMA table_info({table})")]

        if "must_change_password" not in cols("users"):
            conn.exec_driver_sql(
                "ALTER TABLE users ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT 0"
            )
        node_cols = cols("nodes")
        if "role" not in node_cols:
            conn.exec_driver_sql("ALTER TABLE nodes ADD COLUMN role VARCHAR(16) NOT NULL DEFAULT 'exit'")
        if "status" not in node_cols:
            conn.exec_driver_sql("ALTER TABLE nodes ADD COLUMN status VARCHAR(16) NOT NULL DEFAULT 'ok'")
        if "pool_id" not in node_cols:
            conn.exec_driver_sql("ALTER TABLE nodes ADD COLUMN pool_id INTEGER")
        if "sync_state" not in node_cols:
            conn.exec_driver_sql(
                "ALTER TABLE nodes ADD COLUMN sync_state VARCHAR(16) NOT NULL DEFAULT 'pending'"
            )
        if "last_reconcile_at" not in node_cols:
            conn.exec_driver_sql("ALTER TABLE nodes ADD COLUMN last_reconcile_at DATETIME")
        if "priority" not in node_cols:
            conn.exec_driver_sql("ALTER TABLE nodes ADD COLUMN priority INTEGER NOT NULL DEFAULT 100")
        if "route_id" not in cols("devices"):
            conn.exec_driver_sql("ALTER TABLE devices ADD COLUMN route_id INTEGER")
        # users.role (Этап 2): roles admin|operator|client; carry over old is_admin.
        ucols = cols("users")
        if "role" not in ucols:
            conn.exec_driver_sql("ALTER TABLE users ADD COLUMN role VARCHAR(16) NOT NULL DEFAULT 'client'")
            if "is_admin" in ucols:
                conn.exec_driver_sql(
                    "UPDATE users SET role = CASE WHEN is_admin=1 THEN 'admin' ELSE 'client' END"
                )
        if "created_by" not in cols("users"):
            conn.exec_driver_sql("ALTER TABLE users ADD COLUMN created_by INTEGER")


def _seed_default_group() -> None:
    """One-time (Этап 2): put every existing client + every enabled route into a
    single «Общая» group so access carries over when groups are introduced. Guarded
    by a settings flag so it never re-creates the group after an admin removes it."""
    with engine.begin() as conn:
        def table_exists(name: str) -> bool:
            row = conn.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=:n", {"n": name}
            ).fetchone()
            return row is not None

        if not (table_exists("groups") and table_exists("settings")):
            return
        done = conn.exec_driver_sql("SELECT value FROM settings WHERE key='grp_seed_done'").fetchone()
        if done:
            return
        conn.exec_driver_sql("INSERT INTO groups (name) VALUES ('Общая')")
        gid = conn.exec_driver_sql("SELECT id FROM groups WHERE name='Общая'").fetchone()[0]
        for (uid,) in conn.exec_driver_sql("SELECT id FROM users WHERE role='client'").fetchall():
            conn.exec_driver_sql(
                "INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES (:u, :g)",
                {"u": uid, "g": gid},
            )
        for (rid,) in conn.exec_driver_sql("SELECT id FROM routes WHERE enabled=1").fetchall():
            conn.exec_driver_sql(
                "INSERT OR IGNORE INTO route_groups (route_id, group_id) VALUES (:r, :g)",
                {"r": rid, "g": gid},
            )
        conn.exec_driver_sql("INSERT INTO settings (key, value) VALUES ('grp_seed_done', '1')")
