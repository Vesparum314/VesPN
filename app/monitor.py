"""Monitoring — two views the admin cares about:

  1. Hub -> every server (management-plane reachability from the panel host).
  2. Each gate -> its pool's exits (the path CLIENTS actually use), read from the
     gate's relay daemon: which exits it sees healthy, which is active, and how
     much the active exit has flapped in the last hour.

Reachability from the Hub matters for ops but NOT for client connectivity (that
goes client -> gate -> exit), so the two views are kept separate. Results are a
JSON snapshot stored in Setting('monitor_state'); the admin page and the Telegram
bot both render it. `problems` holds only client-impacting, alert-worthy issues.

Checks run hourly (bot scheduler), on demand (page button / Telegram /check).
"""

from __future__ import annotations

import json
import re
import socket
import time
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .models import ExitPool, Node, ROLE_EXIT, Route, Setting
from .nodes import connect

MONITOR_KEY = "monitor_state"
FLAP_ALERT = 4  # active-exit changes/hour at or above which we call it flapping


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _tcp(host: str, port: int, timeout: float = 4.0) -> tuple[bool, int | None]:
    """TCP-connect probe (no SSH/auth, so it never trips fail2ban). -> (ok, ms)."""
    t0 = time.monotonic()
    try:
        s = socket.create_connection((host, int(port)), timeout=timeout)
        s.close()
        return True, int((time.monotonic() - t0) * 1000)
    except Exception:
        return False, None


_ACTIVE_RE = re.compile(r"active=\[([^\]]*)\]\s*\(healthy=\[([^\]]*)\]")


def _ips(s: str) -> list[str]:
    return [x.strip().strip("'\"") for x in s.split(",") if x.strip()]


def _gate_view(gate: Node) -> dict:
    """Read the relay daemon's live state from the gate (the real client-path view)."""
    view: dict = {"gate_ssh": False, "daemon": None, "active": [], "healthy": [], "flaps_1h": None}
    try:
        with connect(gate) as g:
            view["gate_ssh"] = True
            rc, act, _ = g.run(
                "journalctl -u vespn-relay --no-pager 2>/dev/null | grep active= | tail -1", timeout=15
            )
            m = _ACTIVE_RE.search(act or "")
            if m:
                view["active"] = _ips(m.group(1))
                view["healthy"] = _ips(m.group(2))
            rc, flaps, _ = g.run(
                "journalctl -u vespn-relay --no-pager --since '-1 hour' 2>/dev/null | grep -c active=",
                timeout=15,
            )
            try:
                view["flaps_1h"] = int((flaps or "0").strip())
            except ValueError:
                pass
            rc, st, _ = g.run("systemctl is-active vespn-relay 2>&1", timeout=10)
            view["daemon"] = (st or "").strip()
    except Exception as e:
        view["error"] = str(e)[:100]
    return view


def run_checks(db: Session) -> dict:
    """Probe everything, store + return the snapshot."""
    pools = {p.id: p for p in db.query(ExitPool).all()}
    snap: dict = {"at": _now_iso(), "nodes": [], "routes": [], "problems": []}

    # --- view 1: Hub -> every node ---
    for n in db.query(Node).order_by(Node.id).all():
        pool = pools.get(n.pool_id)
        svc = pool.vless_port if pool else 17771
        ssh_ok, ssh_ms = _tcp(n.public_host, n.ssh_port or 22)
        svc_ok, svc_ms = _tcp(n.public_host, svc)
        snap["nodes"].append({
            "id": n.id, "name": n.name, "role": n.role,
            "pool": pool.name if pool else None,
            "sync": n.sync_state if n.role == ROLE_EXIT else None,
            "hub_ssh": ssh_ok, "hub_service": svc_ok,
            "service_port": svc, "latency_ms": svc_ms if svc_ms is not None else ssh_ms,
        })

    # --- view 2: each gate -> its pool's exits (from the daemon) ---
    for r in db.query(Route).order_by(Route.name).all():
        gate, pool = r.gate_node, r.pool
        if not gate or not pool:
            continue
        view = _gate_view(gate)
        names = {m.public_host: m.name for m in pool.members}
        active = [names.get(ip, ip) for ip in view.get("active", [])]
        healthy_ips = set(view.get("healthy", []))
        down = [m.name for m in pool.members if m.public_host not in healthy_ips]
        gate_up = bool(view.get("gate_ssh")) and view.get("daemon") == "active"
        snap["routes"].append({
            "route": r.name, "gate": gate.name, "default": r.is_default,
            "gate_up": gate_up, "active": active,
            "healthy": [names.get(ip, ip) for ip in view.get("healthy", [])],
            "down": down, "pool_exits": [m.name for m in pool.members],
            "flaps_1h": view.get("flaps_1h"), "error": view.get("error"),
        })
        # alert-worthy (client-impacting) only:
        if not view.get("gate_ssh"):
            snap["problems"].append(f"маршрут «{r.name}»: гейт {gate.name} недоступен")
        elif view.get("daemon") != "active":
            snap["problems"].append(f"маршрут «{r.name}»: релей-демон на {gate.name} не работает ({view.get('daemon')})")
        elif not view.get("active"):
            snap["problems"].append(f"маршрут «{r.name}»: НЕТ активного выхода — все упали!")
        elif (view.get("flaps_1h") or 0) >= FLAP_ALERT:
            snap["problems"].append(f"маршрут «{r.name}»: флаппинг выхода ({view['flaps_1h']} переключений/час)")

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
    for r in snap.get("routes", []):
        mark = "✅" if (r.get("gate_up") and r.get("active")) else "⛔"
        act = ", ".join(r.get("active") or []) or "—"
        flaps = r.get("flaps_1h")
        extra = f" · флаппинг {flaps}/ч" if (flaps or 0) >= FLAP_ALERT else ""
        down = r.get("down") or []
        downs = f" · резерв вне доступа: {', '.join(down)}" if down else ""
        lines.append(f"{mark} {r['route']}: активен {act}{extra}{downs}")
    hub_bad = [n["name"] for n in snap.get("nodes", []) if not n["hub_ssh"] and not n["hub_service"]]
    if hub_bad:
        lines.append("С Hub не достучаться: " + ", ".join(hub_bad))
    probs = snap.get("problems") or []
    if probs:
        lines.append("\n⚠️ Проблемы:\n" + "\n".join("• " + p for p in probs))
    else:
        lines.append("\nПроблем нет.")
    return "\n".join(lines)
