"""Background jobs: run a long node operation off the HTTP request thread.

Provisioning an exit or raising a gate relay is minutes of blocking SSH. Doing it
inside the request means a reverse proxy (Cloudflare, free tier) times the response
out at 100 s (524) — the work actually finishes, but the admin never sees the result
and tends to click again, firing a second rollout. So the handler only marks the
node `running` and hands the work to a daemon thread here; the thread owns its own DB
session and writes the outcome back onto the node (job_state/job_message), which the
«Парк» page polls and shows.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy.orm import Session

from .db import SessionLocal
from .models import JOB_DONE, JOB_ERROR, JOB_RUNNING, Node

log = logging.getLogger("vpnpanel.jobs")

# A job does its work given a fresh (db, node) and returns the success message to
# show. It may commit through `db` itself (provisioning does); it should raise on
# failure — the error text is captured and shown, never propagated as a crash.
JobFn = Callable[[Session, Node], str]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def start_node_job(db: Session, node: Node, kind: str, fn: JobFn) -> bool:
    """Mark `node` busy and run `fn(db, node)` in a background daemon thread.

    Returns False (and does nothing) when a job is already running for this node, so
    the caller can tell the admin instead of launching a duplicate rollout.
    """
    if node.job_running:
        return False
    node.job_state = JOB_RUNNING
    node.job_kind = kind
    node.job_message = ""
    node.job_started_at = _now()
    node.job_finished_at = None
    db.commit()
    threading.Thread(
        target=_run, args=(node.id, kind, fn), name=f"node-job-{node.id}", daemon=True
    ).start()
    return True


def _run(node_id: int, kind: str, fn: JobFn) -> None:
    db = SessionLocal()
    try:
        node = db.get(Node, node_id)
        if node is None:
            return
        try:
            message = fn(db, node) or "Готово"
            state = JOB_DONE
        except Exception as exc:  # any failure becomes a shown error, never a crash
            log.exception("node job %r failed for node %s", kind, node_id)
            db.rollback()
            message, state = f"{type(exc).__name__}: {exc}", JOB_ERROR
        node = db.get(Node, node_id)  # fn may have committed/expired the instance
        if node is not None:
            node.job_state = state
            node.job_message = message[:1000]
            node.job_finished_at = _now()
            db.commit()
    finally:
        db.close()
