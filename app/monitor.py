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

from .models import ExitPool, Node, ROLE_EXIT, ROLE_GATE, Route, Setting
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


def _daemon_view(g) -> dict:
    """Read the relay daemon's live state from an already-open gate session (the
    running client-path truth: which exits it sees healthy, which is active, and the
    number of active-exit changes in the last hour)."""
    view: dict = {"daemon": None, "active": [], "healthy": [], "flaps_1h": None}
    if g is None:
        return view
    try:
        _rc, act, _ = g.run(
            "journalctl -u vespn-relay --no-pager 2>/dev/null | grep active= | tail -1", timeout=15
        )
        m = _ACTIVE_RE.search(act or "")
        if m:
            view["active"] = _ips(m.group(1))
            view["healthy"] = _ips(m.group(2))
        _rc, flaps, _ = g.run(
            "journalctl -u vespn-relay --no-pager --since '-1 hour' 2>/dev/null | grep -c active=",
            timeout=15,
        )
        try:
            view["flaps_1h"] = int((flaps or "0").strip())
        except ValueError:
            pass
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

    # Which gate fronts a given pooled exit — its pool's route gate.
    gate_for_exit: dict[int, Node] = {}
    for r in routes:
        if r.gate_node and r.pool:
            for m in r.pool.members:
                gate_for_exit.setdefault(m.id, r.gate_node)

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
                snap["nodes"].append({
                    "name": n.name, "role": "gate",
                    "mgmt_ok": gate_g(n) is not None, "via": "Хаб→гейт напрямую",
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
                    mgmt = (g is not None) and _probe_tcp(g, n.ssh_host, n.ssh_port or 22)
                    snap["nodes"].append({
                        "name": n.name, "role": "exit",
                        "pool": _pool_name(n), "sync": n.sync_state,
                        "gate": gate.name, "mgmt_ok": bool(mgmt), "via": f"через {gate.name}",
                    })

        # --- view (б): client path (gate → pool exits on traffic ports) ----
        for r in routes:
            gate, pool = r.gate_node, r.pool
            if not gate or not pool:
                continue
            g = gate_g(gate)
            view = _daemon_view(g)
            names = {m.public_host: m.name for m in pool.members}
            exits = []
            for m in pool.members:
                if g is not None:
                    vless_ok: bool | None = _probe_tcp(g, m.public_host, pool.vless_port)
                    awg = _probe_udp(g, m.public_host, pool.awg_port)
                else:
                    vless_ok, awg = None, None
                exits.append({
                    "name": m.name,
                    "vless_port": pool.vless_port, "vless_ok": vless_ok,
                    "awg_port": pool.awg_port, "awg": awg,
                })
            active = [names.get(ip, ip) for ip in view.get("active", [])]
            # (б): "down" = the gate can't reach the exit's traffic port right now
            # (fresh probe), independent of the daemon's hysteretic healthy list.
            down = [e["name"] for e in exits if e["vless_ok"] is False]
            gate_up = (g is not None) and view.get("daemon") == "active"
            snap["routes"].append({
                "route": r.name, "gate": gate.name,
                "gate_up": gate_up, "daemon": view.get("daemon"),
                "active": active,
                "healthy": [names.get(ip, ip) for ip in view.get("healthy", [])],
                "down": down, "exits": exits,
                "flaps_1h": view.get("flaps_1h"), "error": view.get("error"),
            })
            # alert-worthy (client-impacting) only:
            if g is None:
                snap["problems"].append(f"маршрут «{r.name}»: гейт {gate.name} недоступен с Hub")
            elif view.get("daemon") != "active":
                snap["problems"].append(
                    f"маршрут «{r.name}»: релей-демон на {gate.name} не работает ({view.get('daemon')})"
                )
            elif not view.get("active"):
                snap["problems"].append(f"маршрут «{r.name}»: НЕТ активного выхода — все упали!")
            elif (view.get("flaps_1h") or 0) >= FLAP_ALERT:
                snap["problems"].append(
                    f"маршрут «{r.name}»: флаппинг выхода ({view['flaps_1h']} переключений/час)"
                )

    s = db.get(Setting, MONITOR_KEY)
    if s is None:
        db.add(Setting(key=MONITOR_KEY, value=json.dumps(snap)))
    else:
        s.value = json.dumps(snap)
    db.commit()
    return snap


def get_state(db: Session) -> dict | None:
    s = db.get(Setting, MONITOR_KEY)
    if not s or not s.value:
        return None
    try:
        return json.loads(s.value)
    except ValueError:
        return None


def summarize(snap: dict | None) -> str:
    """One compact text block (for Telegram / logs)."""
    if not snap:
        return "Мониторинг ещё не запускался."
    lines = [f"🩺 Статус на {snap.get('at','?')} UTC"]
    # client path (б)
    for r in snap.get("routes", []):
        mark = "✅" if (r.get("gate_up") and r.get("active")) else "⛔"
        act = ", ".join(r.get("active") or []) or "—"
        flaps = r.get("flaps_1h")
        extra = f" · флаппинг {flaps}/ч" if (flaps or 0) >= FLAP_ALERT else ""
        down = r.get("down") or []
        downs = f" · не видны гейту: {', '.join(down)}" if down else ""
        lines.append(f"{mark} {r['route']}: активен {act}{extra}{downs}")
    # management reachability (а)
    mgmt_bad = [n["name"] for n in snap.get("nodes", []) if n.get("mgmt_ok") is False]
    if mgmt_bad:
        lines.append("Управление недоступно: " + ", ".join(mgmt_bad))
    probs = snap.get("problems") or []
    if probs:
        lines.append("\n⚠️ Проблемы:\n" + "\n".join("• " + p for p in probs))
    else:
        lines.append("\nПроблем нет.")
    return "\n".join(lines)
