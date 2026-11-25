"""Monitoring — the two views the admin cares about, with NO direct Hub→exit link:

  (а) Management reachability — can the panel manage each node over its real path?
      Gates: Hub → gate directly (SSH). Exits: Hub → gate → exit (the exit's SSH
      port, probed FROM the gate). The panel never connects to an exit directly.
  (б) Client path — gate → its pool's exits on the TRAFFIC ports (VLESS/AWG),
      probed from the gate, plus the relay daemon's live state (which exits it sees
      healthy, which is active, and how much the active one flapped in the last hour).

Client connectivity goes client → gate → exit, so (а) is for ops only and never
reflects what clients experience. Results are a JSON snapshot in
Setting('monitor_state'); the admin page and the Telegram bot both render it.
`problems` holds only client-impacting, alert-worthy issues.

Checks run hourly (bot scheduler), on demand (page button / Telegram /check).
"""

from __future__ import annotations

import json
import re
from contextlib import ExitStack
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .models import (
    ExitPool,
    HIST_CLIENT,
    HIST_MGMT,
    Node,
    NodeStatusHistory,
    ROLE_EXIT,
    ROLE_GATE,
    Route,
    Setting,
)
from .nodes import connect

MONITOR_KEY = "monitor_state"
FLAP_ALERT = 4  # active-exit changes/hour at or above which we call it flapping


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _probe_tcp(g, host: str, port: int, timeout: int = 4) -> bool:
    """TCP-connect probe to (host, port) FROM the gate (bash /dev/tcp). The gate is
    the only vantage point that reaches the exits — the panel never probes an exit
    directly from the Hub. A bare connect (no auth) trips nothing."""
    cmd = f"timeout {timeout} bash -c '</dev/tcp/{host}/{int(port)}' 2>/dev/null && echo OPEN || echo DOWN"
    try:
        _rc, out, _ = g.run(cmd, timeout=timeout + 8)
        return out.strip().endswith("OPEN")
    except Exception:
        return False


def _probe_udp(g, host: str, port: int, timeout: int = 3) -> str:
    """Best-effort UDP reachability FROM the gate. UDP has no handshake, so this is
    advisory: `nc -u -z` if present, else 'NA'. The daemon's real health signal is
    the TCP VLESS probe, so AWG health is inferred from that + a live tunnel."""
    cmd = (
        f"if command -v nc >/dev/null 2>&1; then "
        f"nc -u -z -w{timeout} {host} {int(port)} >/dev/null 2>&1 && echo OPEN || echo DOWN; "
        f"else echo NA; fi"
    )
    try:
        _rc, out, _ = g.run(cmd, timeout=timeout + 8)
        return out.strip() or "NA"
    except Exception:
        return "NA"


_ACTIVE_RE = re.compile(r"active=\[([^\]]*)\]\s*\(healthy=\[([^\]]*)\]")


def _ips(s: str) -> list[str]:
    return [x.strip().strip("'\"") for x in s.split(",") if x.strip()]


def _for_pool(line: str, pool_name: str | None) -> bool:
    """A relay-daemon log line about `pool_name`. The v2 daemon logs one line per
    server pool («pool=<name> active=…»); a v1 daemon (one pool) has no pool= tag."""
    if "pool=" not in line:
        return True
    return pool_name is not None and f"pool={pool_name} active=" in line


def _daemon_view(g, pool_name: str | None = None) -> dict:
    """Read the relay daemon's live state for one server pool from an already-open
    gate session (the running client-path truth: which exits it sees healthy, which
    is active, and the number of active-exit changes in the last hour)."""
    view: dict = {"daemon": None, "active": [], "healthy": [], "flaps_1h": None}
    if g is None:
        return view
    try:
        _rc, act, _ = g.run(
            "journalctl -u vespn-relay --no-pager 2>/dev/null | grep active= | tail -300", timeout=15
        )
        mine = [l for l in (act or "").splitlines() if _for_pool(l, pool_name)]
        m = _ACTIVE_RE.search(mine[-1]) if mine else None
        if m:
            view["active"] = _ips(m.group(1))
            view["healthy"] = _ips(m.group(2))
        _rc, flaps, _ = g.run(
            "journalctl -u vespn-relay --no-pager --since '-1 hour' 2>/dev/null | grep active=",
            timeout=15,
        )
        # The v2 daemon re-logs EVERY pool on any change, so count only the lines
        # where this pool's active member actually changed.
        changes, prev = 0, None
        for l in (flaps or "").splitlines():
            if not _for_pool(l, pool_name):
                continue
            mm = _ACTIVE_RE.search(l)
            cur = mm.group(1) if mm else None
            if prev is not None and cur != prev:
                changes += 1
            prev = cur
        view["flaps_1h"] = changes
        _rc, st, _ = g.run("systemctl is-active vespn-relay 2>&1", timeout=10)
        view["daemon"] = (st or "").strip()
    except Exception as e:
        view["error"] = str(e)[:100]
    return view


def run_checks(db: Session) -> dict:
    """Probe everything, store + return the snapshot. Opens ONE direct SSH session
    per gate (Hub→gate — the only direct connection the panel makes) and reaches
    every exit from its gate, so no direct Hub→exit link is ever created."""
    snap: dict = {"at": _now_iso(), "nodes": [], "routes": [], "problems": []}
    routes = db.query(Route).order_by(Route.name).all()
    all_nodes = db.query(Node).order_by(Node.id).all()
    pools = {p.id: p for p in db.query(ExitPool).all()}  # Node has pool_id, no .pool rel

    def _pool_name(node: Node) -> str | None:
        p = pools.get(node.pool_id)
        return p.name if p else None

    # Which gate fronts a given pooled exit — the first gate of its route's gate
    # pool (the one management goes through first).
    gate_for_exit: dict[int, Node] = {}
    for r in routes:
        if r.primary_gate and r.pool:
            for m in r.pool.members:
                gate_for_exit.setdefault(m.id, r.primary_gate)

    mgmt_state: dict[int, bool] = {}    # node_id -> Hub→node management reachable
    client_state: dict[int, bool] = {}  # exit node_id -> gate→exit (VLESS) reachable

    with ExitStack() as stack:
        gsess: dict[int, object | None] = {}  # gate.id -> open session (reused) or None

        def gate_g(gate: Node):
            if gate.id not in gsess:
                try:
                    gsess[gate.id] = stack.enter_context(connect(gate))
                except Exception:
                    gsess[gate.id] = None
            return gsess[gate.id]

        # --- view (а): management reachability -----------------------------
        for n in all_nodes:
            if n.role == ROLE_GATE:
                g_ok = gate_g(n) is not None
                mgmt_state[n.id] = g_ok
                snap["nodes"].append({
                    "name": n.name, "role": "gate",
                    "mgmt_ok": g_ok, "via": "Хаб→гейт напрямую",
                })
            else:
                gate = gate_for_exit.get(n.id)
                if gate is None:
                    snap["nodes"].append({
                        "name": n.name, "role": "exit",
                        "pool": _pool_name(n), "sync": n.sync_state,
                        "gate": None, "mgmt_ok": None, "via": "нет гейта",
                    })
                    if n.pool_id:
                        snap["problems"].append(
                            f"выход «{n.name}»: нет гейта — управление невозможно (только через гейт)"
                        )
                else:
                    g = gate_g(gate)
                    mgmt = bool((g is not None) and _probe_tcp(g, n.ssh_host, n.ssh_port or 22))
                    mgmt_state[n.id] = mgmt
                    snap["nodes"].append({
                        "name": n.name, "role": "exit",
                        "pool": _pool_name(n), "sync": n.sync_state,
                        "gate": gate.name, "mgmt_ok": mgmt, "via": f"через {gate.name}",
                    })

        # --- view (б): client path (gate → pool exits on traffic ports) ----
        # Every gate of the route's gate pool is a separate entry point, so each one
        # is checked on its own: one dead gate is an alert (it's a ban signal) even
        # while the others keep the route alive.
        for r in routes:
            pool = r.pool
            if not pool or not r.gates or not r.enabled:
                continue  # a route switched off on purpose is no alarm
            working = 0
            for gate in r.gates:
                g = gate_g(gate)
                view = _daemon_view(g, pool.name)
                names = {m.public_host: m.name for m in pool.members}
                exits = []
                # TCP traffic ports of the pool: VLESS and/or NaiveProxy (443) — each
                # checked; AWG-only pools: SSH (whether the host is up at all).
                tports = ([("VLESS", pool.vless_port)] if "vless" in pool.protocols else []) + \
                         ([("Naive", 443)] if "naive" in pool.protocols else [])
                for m in pool.members:
                    ports = tports or [("SSH", m.ssh_port or 22)]
                    if g is not None:
                        tcp = {f"{lbl} :{port}": _probe_tcp(g, m.public_host, port) for lbl, port in ports}
                        vless_ok: bool | None = all(tcp.values())
                        awg = _probe_udp(g, m.public_host, pool.awg_port) if "awg" in pool.protocols else "NA"
                        client_state[m.id] = client_state.get(m.id, False) or bool(vless_ok)
                    else:
                        tcp, vless_ok, awg = {}, None, None
                    exits.append({
                        "name": m.name, "tcp": tcp,
                        "vless_port": ports[0][1], "vless_ok": vless_ok,
                        "awg_port": pool.awg_port, "awg": awg,
                    })
                active = [names.get(ip, ip) for ip in view.get("active", [])]
                # (б): "down" = the gate can't reach the exit's traffic port right
                # now (fresh probe), independent of the daemon's hysteretic list.
                down = [e["name"] + "".join(f" ({k} ✗)" for k, ok in e["tcp"].items() if not ok)
                        for e in exits if e["vless_ok"] is False]
                gate_up = (g is not None) and view.get("daemon") == "active"
                if gate_up and view.get("active"):
                    working += 1
                snap["routes"].append({
                    "route": r.name, "gate": gate.name,
                    "gate_up": gate_up, "daemon": view.get("daemon"),
                    "active": active,
                    "healthy": [names.get(ip, ip) for ip in view.get("healthy", [])],
                    "down": down, "exits": exits,
                    "flaps_1h": view.get("flaps_1h"), "error": view.get("error"),
                })
                # alert-worthy (client-impacting) only:
                where = f"маршрут «{r.name}», гейт {gate.name}"
                if g is None:
                    snap["problems"].append(f"{where}: гейт недоступен с Hub")
                elif view.get("daemon") != "active":
                    snap["problems"].append(f"{where}: релей-демон не работает ({view.get('daemon')})")
                elif not view.get("active"):
                    snap["problems"].append(f"{where}: НЕТ активного выхода — все упали!")
                elif (view.get("flaps_1h") or 0) >= FLAP_ALERT:
                    snap["problems"].append(
                        f"{where}: флаппинг выхода ({view['flaps_1h']} переключений/час)"
                    )
            if working == 0:
                snap["problems"].append(f"маршрут «{r.name}»: НИ ОДНОГО рабочего гейта — маршрут лежит")

    _record_transitions(db, mgmt_state, HIST_MGMT)
    _record_transitions(db, client_state, HIST_CLIENT)

    s = db.get(Setting, MONITOR_KEY)
    if s is None:
        db.add(Setting(key=MONITOR_KEY, value=json.dumps(snap)))
    else:
        s.value = json.dumps(snap)
    db.commit()
    return snap


def _record_transitions(db: Session, states: dict[int, bool], kind: str) -> None:
    """Append a history row only when a node's reachability FLIPPED since the last
    recorded value for this kind (keeps the log compact — transitions, not samples)."""
    for nid, up in states.items():
        last = (
            db.query(NodeStatusHistory)
            .filter_by(node_id=nid, kind=kind)
            .order_by(NodeStatusHistory.at.desc(), NodeStatusHistory.id.desc())
            .first()
        )
        if last is None or bool(last.up) != bool(up):
            db.add(NodeStatusHistory(node_id=nid, kind=kind, up=bool(up)))


def node_history(db: Session, node_id: int, limit: int = 20) -> list[NodeStatusHistory]:
    """Recent reachability transitions for a node (newest first), for the UI."""
    return (
        db.query(NodeStatusHistory)
        .filter_by(node_id=node_id)
        .order_by(NodeStatusHistory.at.desc(), NodeStatusHistory.id.desc())
        .limit(limit)
        .all()
    )


def get_state(db: Session) -> dict | None:
    s = db.get(Setting, MONITOR_KEY)
    if not s or not s.value:
        return None
    try:
        return json.loads(s.value)
    except ValueError:
        return None


def _mgmt_mark(n: dict) -> str:
    if n.get("mgmt_ok") is True:
        return "✅"
    if n.get("mgmt_ok") is None:
        return "❔"
    return "⛔"


def summarize(snap: dict | None) -> str:
    """Compact text block for Telegram / logs — two clearly separated sections:
    (б) client path (gate→exits) and (а) management reachability (Hub→nodes)."""
    if not snap:
        return "Мониторинг ещё не запускался."
    from .config import settings

    lines = [f"🩺 {settings.brand_name} · {snap.get('at','?')} UTC"]

    # --- (б) client path: gate → exits ---
    lines.append("\n📡 Клиентский путь (гейт → выходы):")
    routes = snap.get("routes", [])
    if routes:
        for r in routes:
            mark = "✅" if (r.get("gate_up") and r.get("active")) else "⛔"
            act = ", ".join(r.get("active") or []) or "—"
            flaps = r.get("flaps_1h")
            extra = f" · флаппинг {flaps}/ч" if (flaps or 0) >= FLAP_ALERT else ""
            down = r.get("down") or []
            downs = f" · не видны гейту: {', '.join(down)}" if down else ""
            lines.append(f"{mark} {r['route']} · {r.get('gate', '?')}: активен {act}{extra}{downs}")
    else:
        lines.append("— маршрутов нет")

    # --- (а) management reachability: Hub → nodes ---
    lines.append("\n🛠 Управляемость (Хаб → ноды):")
    nodes = snap.get("nodes", [])
    gates = [n for n in nodes if n.get("role") == "gate"]
    exits = [n for n in nodes if n.get("role") == "exit"]
    for n in gates:
        lines.append(f"{_mgmt_mark(n)} {n['name']} — гейт, напрямую")
    for n in exits:
        lines.append(f"{_mgmt_mark(n)} {n['name']} — {n.get('via') or 'выход'}")
    if not nodes:
        lines.append("— нод нет")

    probs = snap.get("problems") or []
    if probs:
        lines.append("\n⚠️ Проблемы:\n" + "\n".join("• " + p for p in probs))
    else:
        lines.append("\nПроблем нет.")
    return "\n".join(lines)
