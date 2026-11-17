"""SQLAlchemy engine/session + Base. SQLite by default (one file in a volume)."""

from __future__ import annotations

import os
from collections.abc import Iterator

from sqlalchemy import create_engine, event
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


if settings.database_url.startswith("sqlite"):

    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _record):  # noqa: ANN001
        """WAL + a busy timeout so the background job worker (app/jobs.py) and the
        request threads share the one SQLite file cleanly: WAL lets reads run while
        a writer is active, and the timeout makes a brief write collision wait
        instead of raising 'database is locked'."""
        cur = dbapi_conn.cursor()
        try:
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA busy_timeout=30000")
        finally:
            cur.close()


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
    _migrate_route_gates()
    _reset_orphaned_jobs()
    _seed_default_group()
    _migrate_announcement()
    _ensure_fleet_key()


def _ensure_fleet_key() -> None:
    """Mint the fleet SSH key on first startup (stored encrypted in the DB) so it
    exists before any node connect. Best-effort — provisioning would create it on
    demand otherwise."""
    from . import fleetkey

    db = SessionLocal()
    try:
        fleetkey.get_pem(db, create=True)
    except Exception:  # pragma: no cover - never block startup on this
        import logging
        logging.getLogger("vpnpanel.db").warning("fleet key init deferred", exc_info=True)
    finally:
        db.close()


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
        if "key_installed" not in node_cols:
            conn.exec_driver_sql("ALTER TABLE nodes ADD COLUMN key_installed BOOLEAN NOT NULL DEFAULT 0")
        # Background-job tracking for long node ops (provisioning / gate relay).
        if "job_state" not in node_cols:
            conn.exec_driver_sql("ALTER TABLE nodes ADD COLUMN job_state VARCHAR(16) NOT NULL DEFAULT 'idle'")
        if "job_kind" not in node_cols:
            conn.exec_driver_sql("ALTER TABLE nodes ADD COLUMN job_kind VARCHAR(32)")
        if "job_message" not in node_cols:
            conn.exec_driver_sql("ALTER TABLE nodes ADD COLUMN job_message TEXT NOT NULL DEFAULT ''")
        if "job_started_at" not in node_cols:
            conn.exec_driver_sql("ALTER TABLE nodes ADD COLUMN job_started_at DATETIME")
        if "job_finished_at" not in node_cols:
            conn.exec_driver_sql("ALTER TABLE nodes ADD COLUMN job_finished_at DATETIME")
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
        # Gate pools, per-protocol routes, client host/port per route, subscriptions.
        if "gate_pool_id" not in cols("nodes"):
            conn.exec_driver_sql("ALTER TABLE nodes ADD COLUMN gate_pool_id INTEGER")
        rcols = cols("routes")
        if "protocol" not in rcols:
            # '' = legacy route serving VLESS + AmneziaWG, which is what existing ones do.
            conn.exec_driver_sql("ALTER TABLE routes ADD COLUMN protocol VARCHAR(16) NOT NULL DEFAULT ''")
        if "gate_pool_id" not in rcols:
            conn.exec_driver_sql("ALTER TABLE routes ADD COLUMN gate_pool_id INTEGER")
        if "client_host" not in rcols:
            conn.exec_driver_sql("ALTER TABLE routes ADD COLUMN client_host VARCHAR(255) NOT NULL DEFAULT ''")
        if "client_port" not in rcols:
            conn.exec_driver_sql("ALTER TABLE routes ADD COLUMN client_port INTEGER")
        if "dns_provider_id" not in rcols:
            conn.exec_driver_sql("ALTER TABLE routes ADD COLUMN dns_provider_id INTEGER")
        if "sub_token" not in cols("devices"):
            # SQLite can't ADD a UNIQUE column — add it, then the same unique index
            # create_all builds on a fresh DB (NULLs don't collide).
            conn.exec_driver_sql("ALTER TABLE devices ADD COLUMN sub_token VARCHAR(64)")
            conn.exec_driver_sql(
                "CREATE UNIQUE INDEX IF NOT EXISTS ix_devices_sub_token ON devices (sub_token)"
            )
        if "secret_enc" not in cols("issued_configs"):
            conn.exec_driver_sql("ALTER TABLE issued_configs ADD COLUMN secret_enc VARCHAR(512)")
        # VLESS transport + Reality masquerade per server pool. Existing pools keep
        # TCP+Vision (their issued configs say so); new pools get XHTTP.
        pcols = cols("exit_pools")
        if "vless_transport" not in pcols:
            conn.exec_driver_sql("ALTER TABLE exit_pools ADD COLUMN vless_transport VARCHAR(16) NOT NULL DEFAULT 'tcp'")
        if "xhttp_path" not in pcols:
            conn.exec_driver_sql("ALTER TABLE exit_pools ADD COLUMN xhttp_path VARCHAR(64) NOT NULL DEFAULT ''")
        if "reality_target" not in pcols:
            conn.exec_driver_sql("ALTER TABLE exit_pools ADD COLUMN reality_target VARCHAR(255) NOT NULL DEFAULT ''")
        if "reality_names_json" not in pcols:
            conn.exec_driver_sql("ALTER TABLE exit_pools ADD COLUMN reality_names_json TEXT NOT NULL DEFAULT '[]'")


def _migrate_route_gates() -> None:
    """One-time: routes used to point at ONE gate node (`routes.gate_id`). Move each
    such gate into a gate pool (reusing the pool if the gate is already in one) and
    point the route at that pool. `gate_id` stays in old tables, unused."""
    with engine.begin() as conn:
        rcols = [r[1] for r in conn.exec_driver_sql("PRAGMA table_info(routes)")]
        if "gate_id" not in rcols:
            return  # fresh DB: never had single-gate routes
        rows = conn.exec_driver_sql(
            "SELECT r.id, r.gate_id, n.name, n.gate_pool_id FROM routes r "
            "JOIN nodes n ON n.id = r.gate_id "
            "WHERE r.gate_id IS NOT NULL AND r.gate_pool_id IS NULL"
        ).fetchall()
        for route_id, gate_id, gate_name, gate_pool_id in rows:
            if gate_pool_id is None:
                # The gate may have been pooled by an earlier row of this loop.
                gate_pool_id = conn.exec_driver_sql(
                    "SELECT gate_pool_id FROM nodes WHERE id = :g", {"g": gate_id}
                ).fetchone()[0]
            if gate_pool_id is None:
                name, n = gate_name, 1
                while conn.exec_driver_sql(
                    "SELECT 1 FROM gate_pools WHERE name = :n", {"n": name}
                ).fetchone():
                    n += 1
                    name = f"{gate_name}-{n}"
                conn.exec_driver_sql("INSERT INTO gate_pools (name) VALUES (:n)", {"n": name})
                gate_pool_id = conn.exec_driver_sql(
                    "SELECT id FROM gate_pools WHERE name = :n", {"n": name}
                ).fetchone()[0]
                conn.exec_driver_sql(
                    "UPDATE nodes SET gate_pool_id = :p WHERE id = :g", {"p": gate_pool_id, "g": gate_id}
                )
            conn.exec_driver_sql(
                "UPDATE routes SET gate_pool_id = :p WHERE id = :r", {"p": gate_pool_id, "r": route_id}
            )


def _reset_orphaned_jobs() -> None:
    """A node job left in `running` can't survive a panel restart — its worker
    thread is gone with the process — so flip any leftover `running` to `error` on
    startup, otherwise the «Парк» would show a spinner forever and block re-runs."""
    with engine.begin() as conn:
        row = conn.exec_driver_sql(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='nodes'"
        ).fetchone()
        if not row:
            return
        cols = [r[1] for r in conn.exec_driver_sql("PRAGMA table_info(nodes)")]
        if "job_state" not in cols:
            return
        conn.exec_driver_sql(
            "UPDATE nodes SET job_state='error', "
            "job_message='прервано перезапуском панели', "
            "job_finished_at=CURRENT_TIMESTAMP WHERE job_state='running'"
        )


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


def _migrate_announcement() -> None:
    """One-time: move the legacy single-banner Setting('announcement') into an
    Announcement row, then blank the setting so this runs exactly once."""
    with engine.begin() as conn:
        def table_exists(name: str) -> bool:
            return conn.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=:n", {"n": name}
            ).fetchone() is not None

        if not (table_exists("announcements") and table_exists("settings")):
            return
        row = conn.exec_driver_sql("SELECT value FROM settings WHERE key='announcement'").fetchone()
        if not row or not (row[0] or "").strip():
            return
        cnt = conn.exec_driver_sql("SELECT count(*) FROM announcements").fetchone()[0]
        if cnt == 0:
            conn.exec_driver_sql(
                "INSERT INTO announcements (text, active) VALUES (:t, 1)", {"t": row[0].strip()}
            )
        conn.exec_driver_sql("UPDATE settings SET value='' WHERE key='announcement'")
