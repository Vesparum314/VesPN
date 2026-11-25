"""Traffic accounting: how much went through each server, and whose it was.

Counters are read from each pool member, ALWAYS through its gate (the same gate-only
rule as the rest of the panel: never a direct Hub→exit):

  * VLESS — the 3x-ui client API (cumulative per client);
  * AmneziaWG — `awg show <iface> transfer` (cumulative per peer);
  * NaiveProxy — Caddy's access log, which records each proxy tunnel when it closes
    (login + bytes; app/naive.py keeps only that). Read incrementally from an offset.

Cumulative counters reset on a node/container restart, so the last value seen per
(device, node) is kept in TrafficStat.seen and only positive changes are counted.
Every change lands in TrafficDay (device × server × Moscow day), which the «Трафик»
page sums over any period; TrafficStat keeps the device's running total (shown to apps
in the subscription headers). Gates carry the whole route, so their traffic comes from
the gate journal's interface counters (GateSample), not from per-device counters.

Collection is hourly (the bot scheduler) or on demand (button); pages never probe live.
"""

from __future__ import annotations

import json
import logging
from datetime import date, datetime, timedelta, timezone

from sqlalchemy.orm import Session

from .awg import AWGManager
from .models import (
    PROTO_AWG,
    PROTO_NAIVE,
    PROTO_VLESS,
    TRAFFIC_KEEP_DAYS,
    Device,
    ExitPool,
    GateSample,
    IssuedConfig,
    Node,
    ProbeSample,
    Route,
    Setting,
    TrafficDay,
    TrafficStat,
    User,
)
from .nodes import connect
from .xui import XUIClient

log = logging.getLogger("vpnpanel.traffic")

MSK = timezone(timedelta(hours=3))  # Moscow has no DST: a fixed offset is exact
_K_NODES = "traffic_nodes"          # {node id: {"at", "ok", "err"}} — last collection per server
_K_NAIVE = "traffic_naive_{}"       # per node: {"inode", "off"} — how far its log was read
_K_LAST = "traffic_collected_at"


def msk_today() -> date:
    return datetime.now(MSK).date()


def _today() -> str:
    return msk_today().isoformat()


def _setting(db: Session, key: str, default):
    s = db.get(Setting, key)
    if s is None or not s.value:
        return default
    try:
        return json.loads(s.value)
    except ValueError:
        return default


def _put(db: Session, key: str, value) -> None:
    s = db.get(Setting, key)
    v = json.dumps(value)
    if s is None:
        db.add(Setting(key=key, value=v))
        db.flush()
    else:
        s.value = v


# --- recording ------------------------------------------------------------
def _stat(db: Session, device_id: int) -> TrafficStat:
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
    return stat


def _add(db: Session, device: Device, node: Node, d_up: int, d_down: int) -> None:
    """Count a change of traffic for (device, node) into today's row and the totals."""
    if d_up <= 0 and d_down <= 0:
        return
    d_up, d_down = max(d_up, 0), max(d_down, 0)
    day = _today()
    row = (db.query(TrafficDay)
           .filter_by(day=day, device_id=device.id, node_id=node.id).one_or_none())
    if row is None:
        row = TrafficDay(day=day, device_id=device.id, node_id=node.id, user_id=device.user_id,
                         protocol=device.protocol, username=device.user.username,
                         device_name=device.name, node_name=node.name, up=0, down=0)
        db.add(row)
        db.flush()
    row.up += d_up
    row.down += d_down
    stat = _stat(db, device.id)
    stat.up_total += d_up
    stat.down_total += d_down
    stat.up_today += d_up
    stat.down_today += d_down
    stat.updated_at = datetime.now(timezone.utc)


def _apply_delta(db: Session, device: Device, node: Node, cur_up: int, cur_down: int) -> None:
    """Fold a member's cumulative counters for a device in: only the change since we
    last saw this (device, node). The first sight only sets the baseline — traffic from
    before tracking can't be put on any day."""
    stat = _stat(db, device.id)
    seen = stat.seen
    key = str(node.id)
    prev = seen.get(key)
    seen[key] = [cur_up, cur_down]
    stat.seen = seen
    if prev is None:
        return
    d_up = cur_up - int(prev[0]) if cur_up >= int(prev[0]) else cur_up   # reset: current is the change
    d_down = cur_down - int(prev[1]) if cur_down >= int(prev[1]) else cur_down
    _add(db, device, node, d_up, d_down)


# --- collection -----------------------------------------------------------
def collect_traffic(db: Session) -> dict:
    """Read every pool member (through its gate) and record the changes. Never raises;
    a member that doesn't answer is marked in the per-server status (the page says so)."""
    from . import naive
    from .pool import _pool_configs, pool_vless_configs

    status = _setting(db, _K_NODES, {})
    ok = fail = 0
    now = datetime.now(timezone.utc).isoformat()
    for pool in db.query(ExitPool).all():
        protos = pool.protocols
        vless = {c.identifier: c for c in pool_vless_configs(db, pool) if c.identifier and c.device}
        awg = {c.identifier: c for c in _pool_configs(db, pool, PROTO_AWG) if c.identifier and c.device}
        nv = ({c.identifier: c for c in db.query(IssuedConfig).filter_by(protocol=PROTO_NAIVE).all()
               if c.identifier and c.device} if PROTO_NAIVE in protos else {})
        if not (vless or awg or PROTO_NAIVE in protos):
            continue
        for m in pool.members:
            try:
                with connect(m) as n:  # gate-only (ProxyJump); no direct Hub→exit
                    if vless and m.has_xui:
                        with n.tunnel(m.xui_port) as lport:
                            xui = XUIClient(f"http://127.0.0.1:{lport}/{m.xui_path}", m.xui_token)
                            for ident, cfg in vless.items():
                                up, down = xui.get_client_traffic(ident)
                                _apply_delta(db, cfg.device, m, up, down)
                    if awg and PROTO_AWG in protos:
                        mgr = AWGManager(n)
                        mgr.discover_container()
                        tr = mgr.peer_transfer()  # pub -> (up, down)
                        for ident, cfg in awg.items():
                            if ident in tr:
                                _apply_delta(db, cfg.device, m, *tr[ident])
                    if PROTO_NAIVE in protos:
                        key = _K_NAIVE.format(m.id)
                        pos = _setting(db, key, {})
                        users, inode, off = naive.read_traffic(n, pos.get("inode", ""), int(pos.get("off", 0)))
                        for login, (down, up) in users.items():
                            cfg = nv.get(login)
                            if cfg is not None:  # others: the speed probes' account, removed devices
                                _add(db, cfg.device, m, up, down)
                        _put(db, key, {"inode": inode, "off": off})
                db.commit()
                status[str(m.id)] = {"at": now, "ok": True, "err": ""}
                ok += 1
            except Exception as e:
                db.rollback()
                fail += 1
                prev = status.get(str(m.id), {})
                last_ok = prev.get("at") if prev.get("ok") else prev.get("ok_at")
                status[str(m.id)] = {"ok": False, "ok_at": last_ok, "tried": now, "err": str(e)[:200]}
                log.warning("traffic collect from %s failed: %s", m.name, e)
    _put(db, _K_NODES, status)
    _put(db, _K_LAST, now)
    cut = (msk_today() - timedelta(days=TRAFFIC_KEEP_DAYS)).isoformat()
    db.query(TrafficDay).filter(TrafficDay.day < cut).delete(synchronize_session=False)
    db.commit()
    return {"members_ok": ok, "members_fail": fail, "at": datetime.now(timezone.utc)}


def _traffic_for_day(db: Session, day: str) -> tuple[int, list[tuple[str, int]]]:
    """(total, [(server, bytes)] busiest first) through the exits on one Moscow day."""
    per: dict[str, int] = {}
    for r in db.query(TrafficDay).filter_by(day=day).all():
        per[r.node_name] = per.get(r.node_name, 0) + r.up + r.down
    return sum(per.values()), sorted(per.items(), key=lambda x: -x[1])


def device_stat(db: Session, device_id: int) -> TrafficStat | None:
    return db.get(TrafficStat, device_id)


def last_updated(db: Session) -> datetime | None:
    v = _setting(db, _K_LAST, None)
    try:
        return datetime.fromisoformat(v) if v else None
    except ValueError:
        return None


# --- the page -------------------------------------------------------------
def months_back(n: int = 3) -> list[str]:
    """«YYYY-MM» of the current and previous months (within the kept history)."""
    d = msk_today().replace(day=1)
    out = []
    for _ in range(n + 1):
        out.append(d.strftime("%Y-%m"))
        d = (d - timedelta(days=1)).replace(day=1)
    return out


def period_days(period: str) -> tuple[list[str], str]:
    """(days in the period, label). today | 7 | 30 | m:YYYY-MM (calendar month, to today)."""
    today = msk_today()
    if period.startswith("m:"):
        try:
            first = datetime.strptime(period[2:], "%Y-%m").date().replace(day=1)
        except ValueError:
            first = today.replace(day=1)
        nxt = (first + timedelta(days=32)).replace(day=1)
        last = min(nxt - timedelta(days=1), today)
        n = (last - first).days + 1
        days = [(first + timedelta(days=i)).isoformat() for i in range(max(n, 0))]
        return days, _MONTHS[first.month - 1] + f" {first.year}"
    n = {"today": 1, "7": 7, "30": 30}.get(period, 7)
    days = [(today - timedelta(days=n - 1 - i)).isoformat() for i in range(n)]
    return days, {"today": "сегодня", "7": "7 дней", "30": "30 дней"}.get(period, "7 дней")


_MONTHS = ["январь", "февраль", "март", "апрель", "май", "июнь", "июль", "август",
           "сентябрь", "октябрь", "ноябрь", "декабрь"]


def _gate_series(db: Session, gate: Node, days: list[str]) -> list[int]:
    """Per-day bytes through a gate from its interface counters (journal samples).
    Both directions cross a relay twice (in from one side, out to the other), so the
    received counter alone is the route's traffic."""
    if not days:
        return []
    start = datetime.fromisoformat(days[0]).replace(tzinfo=MSK) - timedelta(hours=1)
    end = datetime.fromisoformat(days[-1]).replace(tzinfo=MSK) + timedelta(days=1)
    rows = (db.query(GateSample)
            .filter(GateSample.node_id == gate.id, GateSample.at >= start.astimezone(timezone.utc),
                    GateSample.at < end.astimezone(timezone.utc), GateSample.rx_bytes.isnot(None))
            .order_by(GateSample.at).all())
    idx = {d: i for i, d in enumerate(days)}
    out = [0] * len(days)
    prev = None
    for r in rows:
        at = r.at if r.at.tzinfo else r.at.replace(tzinfo=timezone.utc)
        if prev is not None:
            delta = r.rx_bytes - prev if r.rx_bytes >= prev else r.rx_bytes
            i = idx.get(at.astimezone(MSK).date().isoformat())
            if i is not None:
                out[i] += delta
        prev = r.rx_bytes
    return out


def overview(db: Session, period: str) -> dict:
    days, label = period_days(period)
    idx = {d: i for i, d in enumerate(days)}
    rows = db.query(TrafficDay).filter(TrafficDay.day.in_(days)).all() if days else []
    zero = lambda: [0] * len(days)  # noqa: E731
    # The ids of a deleted device / user / server may still be in the rows (SQLite
    # doesn't enforce ON DELETE SET NULL without the foreign_keys pragma): what isn't
    # in the DB any more counts as gone, its copied name stands in.
    users = {u.id: u for u in db.query(User).all()}
    devs = {d.id: d for d in db.query(Device).all()}
    nodes = {n.id: n for n in db.query(Node).all()}

    # --- servers: exits from device counters, by protocol
    per_node: dict = {}
    for r in rows:
        key = r.node_id if r.node_id in nodes else f"gone:{r.node_name}"
        e = per_node.setdefault(key, {"down": 0, "up": 0, "series": zero(), "proto": {}, "name": r.node_name})
        e["down"] += r.down
        e["up"] += r.up
        e["series"][idx[r.day]] += r.down + r.up
        e["proto"][r.protocol] = e["proto"].get(r.protocol, 0) + r.down + r.up
    status = _setting(db, _K_NODES, {})

    def exit_row(n: Node) -> dict:
        e = per_node.get(n.id, {"down": 0, "up": 0, "series": zero(), "proto": {}})
        st = status.get(str(n.id), {})
        return {"node": n, "kind": "exit", "down": e["down"], "up": e["up"], "total": e["down"] + e["up"],
                "series": e["series"], "proto": e["proto"], "stale": st if st and not st.get("ok") else None}

    def gate_row(n: Node, shared: list[str]) -> dict:
        ser = _gate_series(db, n, days)
        return {"node": n, "kind": "gate", "total": sum(ser), "series": ser, "shared": shared}

    groups = []
    placed: set = set()
    gate_routes: dict[int, list[str]] = {}
    routes = db.query(Route).order_by(Route.name).all()
    for r in routes:
        for g in r.gates:
            gate_routes.setdefault(g.id, []).append(r.name)
    for r in routes:
        exits = [exit_row(n) for n in sorted(r.pool.members, key=lambda m: (m.priority, m.id))] if r.pool else []
        gates = [gate_row(g, [x for x in gate_routes.get(g.id, []) if x != r.name]) for g in r.gates]
        placed.update(e["node"].id for e in exits)
        groups.append({"name": r.name, "route": r, "gates": gates, "exits": exits,
                       "total": sum(e["total"] for e in exits)})
    loose = [exit_row(n) for n in sorted(nodes.values(), key=lambda n: n.name)
             if n.id in per_node and n.id not in placed]
    gone = [{"node": None, "name": v["name"], "kind": "exit", "down": v["down"], "up": v["up"],
             "total": v["down"] + v["up"], "series": v["series"], "proto": v["proto"], "stale": None}
            for k, v in per_node.items() if isinstance(k, str)]
    if loose or gone:
        groups.append({"name": "Без маршрута", "route": None, "gates": [], "exits": loose + gone,
                       "total": sum(e["total"] for e in loose + gone)})
    all_rows = [e for g in groups for e in g["exits"] + g["gates"]]
    top_load = max([e["total"] for e in all_rows] + [1])

    # --- people
    people: dict = {}
    for r in rows:
        pk = r.user_id if r.user_id in users else f"gone:{r.username}"
        p = people.setdefault(pk, {"total": 0, "series": zero(), "devices": {}, "username": r.username})
        p["total"] += r.down + r.up
        p["series"][idx[r.day]] += r.down + r.up
        alive = r.device_id in devs
        dk = r.device_id if alive else f"gone:{r.device_name}:{r.protocol}"
        d = p["devices"].setdefault(dk, {"total": 0, "series": zero(), "name": r.device_name,
                                         "protocol": r.protocol, "gone": not alive})
        d["total"] += r.down + r.up
        d["series"][idx[r.day]] += r.down + r.up
    plist = []
    for u in users.values():
        p = people.get(u.id, {"total": 0, "series": zero(), "devices": {}, "username": u.username})
        for d in u.devices:
            p["devices"].setdefault(d.id, {"total": 0, "series": zero(), "name": d.name,
                                           "protocol": d.protocol, "gone": False})
        plist.append({"user": u, **p})
    for k, p in people.items():
        if isinstance(k, str):
            plist.append({"user": None, **p})
    for p in plist:
        p["devices"] = sorted(
            [{**v, "device": devs.get(k) if isinstance(k, int) else None} for k, v in p["devices"].items()],
            key=lambda x: (x["gone"], -x["total"], x["name"]))
    plist.sort(key=lambda p: (-p["total"], p["username"]))
    top_person = max([p["total"] for p in plist] + [1])

    exits_total = sum(r.down + r.up for r in rows)
    down_total = sum(r.down for r in rows)
    busiest = max((e for e in all_rows if e["kind"] == "exit"), key=lambda e: e["total"], default=None)
    active = {r.device_id for r in rows if r.device_id in devs and r.down + r.up > 0}
    p0 = datetime.fromisoformat(days[0]).replace(tzinfo=MSK) if days else datetime.now(MSK)
    probe = sum(s.bytes or 0 for s in db.query(ProbeSample).filter(ProbeSample.at >= p0.astimezone(timezone.utc)).all())
    stale = [{"node": nodes[int(k)], **v} for k, v in status.items() if not v.get("ok") and int(k) in nodes]
    return {
        "days": days, "label": label, "groups": groups, "top_load": top_load,
        "people": plist, "top_person": top_person,
        "exits_total": exits_total, "down_share": round(down_total * 100 / exits_total) if exits_total else None,
        "busiest": busiest if busiest and busiest["total"] else None,
        "active": len(active), "devices_total": len(devs), "probe": probe, "stale": stale,
    }
