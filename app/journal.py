"""Gate journal: a timeline per gate, sampled every few minutes.

Gates are expendable and get banned; when one goes, the questions are *when*,
*from which side* and *under what load*. So every cycle, for every gate:

  * from the Hub (inside the censored region, roughly the clients' view): can we
    open a TCP connection to the gate's SSH port? A gate blocked at its hoster or
    upstream (an IP-level ban) fails this;
  * from a server abroad (any server the panel can reach this cycle): the same
    probe. «Reachable from abroad but not from the Hub» = blocked for the region,
    «unreachable from both» = cut off at the hoster/upstream;
  * over SSH (when the Hub reaches it): interface byte counters and how many
    distinct client IPs are connected to the relay right now.

Each sample is a GateSample row; up/down flips are also recorded in
NodeStatusHistory (kinds `hub` / `abroad`) for a compact transitions list. The
same cycle then keeps managed DNS names pointed at the live entry points.
"""

from __future__ import annotations

import json
import logging
import socket
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from .models import (
    HIST_ABROAD,
    HIST_HUB,
    ROLE_EXIT,
    ROLE_GATE,
    GateSample,
    Node,
    NodeStatusHistory,
)
from .nodes import connect

log = logging.getLogger("vpnpanel.journal")

KEEP_DAYS = 90
DOWN_AFTER = 2  # consecutive failed Hub probes before a gate counts as down (for DNS)

# Runs on the gate (python3 is there for the relay daemon): interface counters of
# the default route + distinct client source IPs in conntrack towards relay ports.
_GATE_METRICS = r'''
import json, subprocess
out = {"rx": None, "tx": None, "clients": None}
try:
    r = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True).stdout.split()
    ifc = r[r.index("dev") + 1]
    out["rx"] = int(open("/sys/class/net/%s/statistics/rx_bytes" % ifc).read())
    out["tx"] = int(open("/sys/class/net/%s/statistics/tx_bytes" % ifc).read())
except Exception:
    pass
try:
    cfg = json.load(open("/etc/vespn-relay/members.json"))
    if cfg.get("version") == 2:
        ports = {int(d["port"]) for d in cfg.get("dnat", [])} | {int(s["port"]) for s in cfg.get("sni", [])}
    else:
        ports = {int(p) for p in cfg.get("tcp_ports", []) + cfg.get("udp_ports", [])}
    ct = subprocess.run(["conntrack", "-L"], capture_output=True, text=True)
    if ct.returncode == 0:
        srcs = set()
        for line in ct.stdout.splitlines():
            src = dport = None
            for f in line.split():
                if src is None and f.startswith("src="):
                    src = f[4:]
                elif dport is None and f.startswith("dport="):
                    dport = int(f[6:])
            if src and dport in ports:
                srcs.add(src)
        out["clients"] = len(srcs)
except Exception:
    pass
print(json.dumps(out))
'''


def _tcp_from_hub(host: str, port: int, timeout: float = 4.0) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def _gate_metrics(gate: Node) -> dict:
    try:
        with connect(gate) as g:
            rc, out, _ = g.run(f"python3 - <<'PYEOF'\n{_GATE_METRICS}\nPYEOF", timeout=60)
        return json.loads(out.strip().splitlines()[-1]) if rc == 0 and out.strip() else {}
    except Exception as e:
        log.info("journal: metrics from %s failed: %s", gate.name, e)
        return {}


def _probe_from_abroad(db: Session, gates: list[Node]) -> tuple[str, dict[int, bool]]:
    """TCP-probe every gate's SSH port from the first server abroad we can reach
    (through any live gate, or directly for direct-only pools)."""
    servers = (
        db.query(Node)
        .filter(Node.role == ROLE_EXIT, Node.pool_id.isnot(None))
        .order_by(Node.priority, Node.id)
        .all()
    )
    for s in servers:
        try:
            with connect(s) as n:
                res: dict[int, bool] = {}
                for g in gates:
                    host = g.ssh_host or g.public_host
                    cmd = (f"timeout 4 bash -c '</dev/tcp/{host}/{int(g.ssh_port or 22)}' "
                           f"2>/dev/null && echo OPEN || echo DOWN")
                    _rc, out, _ = n.run(cmd, timeout=15)
                    res[g.id] = out.strip().endswith("OPEN")
                return s.name, res
        except Exception as e:
            log.info("journal: vantage %s unavailable: %s", s.name, e)
    return "", {}


def _record_flip(db: Session, node_id: int, kind: str, up: bool) -> None:
    last = (
        db.query(NodeStatusHistory)
        .filter_by(node_id=node_id, kind=kind)
        .order_by(NodeStatusHistory.at.desc(), NodeStatusHistory.id.desc())
        .first()
    )
    if last is None or bool(last.up) != bool(up):
        db.add(NodeStatusHistory(node_id=node_id, kind=kind, up=bool(up)))


def run_cycle(db: Session) -> list[GateSample]:
    """Sample every gate once, record flips, prune old samples, sync DNS."""
    gates = db.query(Node).filter(Node.role == ROLE_GATE).order_by(Node.id).all()
    samples: list[GateSample] = []
    if gates:
        vantage, abroad = _probe_from_abroad(db, gates)
        for g in gates:
            host = g.ssh_host or g.public_host
            hub_ok = _tcp_from_hub(host, g.ssh_port or 22)
            m = _gate_metrics(g) if hub_ok else {}
            s = GateSample(
                node_id=g.id, hub_ok=hub_ok,
                abroad_ok=abroad.get(g.id) if vantage else None, vantage=vantage,
                rx_bytes=m.get("rx"), tx_bytes=m.get("tx"), clients=m.get("clients"),
            )
            db.add(s)
            samples.append(s)
            _record_flip(db, g.id, HIST_HUB, hub_ok)
            if vantage:
                _record_flip(db, g.id, HIST_ABROAD, abroad.get(g.id, False))
        cutoff = datetime.now(timezone.utc) - timedelta(days=KEEP_DAYS)
        db.query(GateSample).filter(GateSample.at < cutoff).delete(synchronize_session=False)
        db.commit()
    try:
        from . import dns
        dns.sync_routes(db, live_gate_ids(db))
    except Exception as e:  # DNS trouble must never break the journal
        log.warning("journal: DNS sync failed: %s", e)
    return samples


def live_gate_ids(db: Session) -> set[int]:
    """Gates that count as alive for DNS: not failing the Hub probe DOWN_AFTER
    times in a row (one lost probe doesn't pull a gate out of DNS)."""
    alive: set[int] = set()
    for g in db.query(Node).filter(Node.role == ROLE_GATE).all():
        last = (
            db.query(GateSample)
            .filter(GateSample.node_id == g.id)
            .order_by(GateSample.at.desc(), GateSample.id.desc())
            .limit(DOWN_AFTER)
            .all()
        )
        if not last or any(s.hub_ok for s in last):
            alive.add(g.id)
    return alive


def _fmt_bytes(n: int | None) -> str:
    if n is None:
        return "—"
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if abs(n) < 1024 or unit == "ТБ":
            return f"{n:.0f} {unit}" if unit == "Б" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def gate_report(db: Session, gate: Node, days: int = 30) -> dict:
    """Summary of one gate's journal for the page: current state, when it first
    failed from each side, traffic and clients while it lived, recent flips."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    rows = (
        db.query(GateSample)
        .filter(GateSample.node_id == gate.id, GateSample.at >= since)
        .order_by(GateSample.at, GateSample.id)
        .all()
    )
    flips = (
        db.query(NodeStatusHistory)
        .filter(NodeStatusHistory.node_id == gate.id,
                NodeStatusHistory.kind.in_((HIST_HUB, HIST_ABROAD)))
        .order_by(NodeStatusHistory.at.desc(), NodeStatusHistory.id.desc())
        .limit(20)
        .all()
    )
    traffic = 0
    prev = None
    for r in rows:
        cur = (r.rx_bytes or 0) + (r.tx_bytes or 0) if r.rx_bytes is not None else None
        if cur is not None and prev is not None and cur >= prev:
            traffic += cur - prev  # a drop = counter reset (reboot): skip that step
        if cur is not None:
            prev = cur
    clients = [r.clients for r in rows if r.clients is not None]
    first_hub_down = next((r.at for r in rows if not r.hub_ok), None)
    first_abroad_down = next((r.at for r in rows if r.abroad_ok is False), None)
    last = rows[-1] if rows else None
    return {
        "gate": gate,
        "samples": len(rows),
        "first_at": rows[0].at if rows else None,
        "last": last,
        "first_hub_down": first_hub_down,
        "first_abroad_down": first_abroad_down,
        "traffic": _fmt_bytes(traffic) if rows else "—",
        "clients_max": max(clients) if clients else None,
        "clients_avg": round(sum(clients) / len(clients), 1) if clients else None,
        "flips": flips,
    }
