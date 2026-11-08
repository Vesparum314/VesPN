"""Per-device traffic accounting.

Counters are read from each pool member — VLESS via the 3x-ui client API, AmneziaWG
via `awg show <iface> transfer` — and ALWAYS through the member's gate (the same
gate-only rule as the rest of the panel: never a direct Hub→exit). Node counters are
cumulative and reset on a node/container restart, so we keep the last value seen per
(device, node) and accumulate only positive deltas into a total and a per-day (UTC)
bucket. A pooled config lives on every clone with the same identity, so a device's
traffic is the sum of deltas across the pool's members.

Collection is periodic (the bot scheduler) or on demand (admin button); pages read
the stored `TrafficStat`, never probe live.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .awg import AWGManager
from .models import PROTO_AWG, PROTO_VLESS, ExitPool, IssuedConfig, TrafficStat
from .nodes import connect
from .xui import XUIClient

log = logging.getLogger("vpnpanel.traffic")


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _apply_delta(db: Session, device_id: int, node_id: int, cur_up: int, cur_down: int) -> None:
    """Fold one member's current (cumulative) counters for a device into its stat,
    counting only the positive change since we last saw this (device, node)."""
    stat = db.get(TrafficStat, device_id)
    if stat is None:
        stat = TrafficStat(device_id=device_id, day=_today())
        db.add(stat)
        db.flush()
    today = _today()
    if stat.day != today:
        stat.day = today
        stat.up_today = 0
        stat.down_today = 0

    seen = stat.seen
    key = str(node_id)
    prev = seen.get(key)
    if prev is None:
        # First observation on this node: adopt its current cumulative into the TOTAL
        # (so "всего" reflects real usage at once) but NOT into "today" — pre-tracking
        # history can't be attributed to the current day.
        d_up = d_down = 0                       # today
        d_up_total, d_down_total = cur_up, cur_down
    else:
        d_up = cur_up - int(prev[0]) if cur_up >= int(prev[0]) else cur_up  # reset -> current is the delta
        d_down = cur_down - int(prev[1]) if cur_down >= int(prev[1]) else cur_down
        d_up_total, d_down_total = d_up, d_down
    seen[key] = [cur_up, cur_down]
    stat.seen = seen

    stat.up_total += d_up_total
    stat.down_total += d_down_total
    stat.up_today += d_up
    stat.down_today += d_down
    stat.updated_at = datetime.now(timezone.utc)


def collect_traffic(db: Session) -> dict:
    """Sample counters from every pool member (through its gate) and update stats.
    Never raises; returns a small summary. Unreachable members are just skipped."""
    pools = db.query(ExitPool).all()
    members_ok = 0
    members_fail = 0
    for pool in pools:
        cfgs = (
            db.query(IssuedConfig)
            .filter(IssuedConfig.pool_id == pool.id)
            .all()
        )
        vless = {c.identifier: c for c in cfgs if c.protocol == PROTO_VLESS and c.identifier}
        awg = {c.identifier: c for c in cfgs if c.protocol == PROTO_AWG and c.identifier}
        if not vless and not awg:
            continue
        for m in pool.members:
            try:
                with connect(m) as n:  # gate-only (ProxyJump); no direct Hub→exit
                    if vless and m.has_xui:
                        with n.tunnel(m.xui_port) as lport:
                            xui = XUIClient(f"http://127.0.0.1:{lport}/{m.xui_path}", m.xui_token)
                            for ident, cfg in vless.items():
                                up, down = xui.get_client_traffic(ident)
                                _apply_delta(db, cfg.device_id, m.id, up, down)
                    if awg:
                        mgr = AWGManager(n)
                        mgr.discover_container()
                        tr = mgr.peer_transfer()  # pub -> (up, down)
                        for ident, cfg in awg.items():
                            if ident in tr:
                                up, down = tr[ident]
                                _apply_delta(db, cfg.device_id, m.id, up, down)
                members_ok += 1
            except Exception as e:
                members_fail += 1
                log.warning("traffic collect from %s failed: %s", m.name, e)
    db.commit()
    return {"members_ok": members_ok, "members_fail": members_fail, "at": datetime.now(timezone.utc)}


def device_stat(db: Session, device_id: int) -> TrafficStat | None:
    return db.get(TrafficStat, device_id)


def last_updated(db: Session) -> datetime | None:
    row = (
        db.query(TrafficStat)
        .filter(TrafficStat.updated_at.isnot(None))
        .order_by(TrafficStat.updated_at.desc())
        .first()
    )
    return row.updated_at if row else None
