"""Speed monitoring: how fast each route really is, and why it isn't when it isn't.

Reachability checks (monitor.py, journal.py) say whether a path is up; a route can be
up and still crawl. This module measures throughput the way a client gets it and
records, at the same moments, what the servers were going through — a slowdown that
comes and goes can't be investigated afterwards, so the evidence is taken live.

Every cycle (CYCLE_SEC, jittered so it never locks onto hourly jobs):

  * server vitals (NodeSample) for every gate and exit in use, over the SSH the panel
    already has: CPU taken by the hoster's other tenants (steal), load, link usage,
    interface drops/errors, the connection table, and the quality of LIVE TCP
    connections from `ss -ti` — RTT and retransmissions for clients, for each
    neighbouring server, and for the server's own traffic to the internet. Gates
    also time a TCP connect to each exit behind them;
  * a light probe (LIGHT_BYTES) through every route × protocol × entry point, from
    the Hub, the way a client goes: Hub → gate → exit → internet. It catches
    freezes, failures, latency jumps and gross drops at a tiny traffic cost;
  * a heavy probe — a timed download (HEAVY_SEC, the first HEAVY_RAMP seconds of TCP
    slow start discarded, HEAVY_CAP bytes at most) — once per `heavy_minutes`, and
    at once when a light probe looks off. Each heavy round also downloads from the
    Hub directly (control: is the Hub's own link slow?) and on every exit directly
    (is the exit's uplink slow?).

A heavy result far below the target's norm is a ProbeIncident: the reason, hints at
the cause drawn from the vitals, and a snapshot taken on the gate and exits right
then (top processes, socket summary, a TCP trace towards the next hop).

Probes go through the pool's own service account (one VLESS client and one
NaiveProxy user per pool, `probe-<pool id>`), not a user's device: it exists on the
servers only while monitoring is on (pool.reconcile_exit / naive.pool_users add it).
VLESS is dialled with a local xray client (the Hub's image ships it), NaiveProxy as
the HTTPS proxy it is. AmneziaWG (UDP, a tunnel the panel can't raise in its
container) is not probed end to end — its servers' vitals still are.

Everything is off by default and switched in the UI («Скорость»): the probes are
real traffic through the fleet (README → «Скорость маршрутов»).
"""

from __future__ import annotations

import base64
import json
import logging
import os
import random
import re
import secrets
import shutil
import socket
import ssl
import statistics
import subprocess
import tempfile
import threading
import time
import uuid as uuidlib
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from sqlalchemy.orm import Session

from .crypto import decrypt, encrypt
from .models import (
    PROBE_CONTROL,
    PROBE_HEAVY,
    PROBE_LIGHT,
    PROTO_NAIVE,
    PROTO_VLESS,
    ROLE_GATE,
    ExitPool,
    Node,
    NodeSample,
    ProbeIncident,
    ProbeSample,
    Route,
    Setting,
)

log = logging.getLogger("vpnpanel.speed")

# --- tuning -----------------------------------------------------------------
CYCLE_SEC = 300               # light probes + vitals
CYCLE_JITTER = 60
LIGHT_BYTES = 256 * 1024      # enough to pass the first-KB freezes DPI is known for
HEAVY_SEC = 4.0               # measured window after the ramp
HEAVY_RAMP = 1.0              # TCP slow start, not counted
HEAVY_CAP = 25_000_000        # bytes; reached only above ~70 Mbit/s
HEAVY_CHOICES = (0, 60, 120, 180)  # minutes between planned heavy rounds; 0 = only when a light probe looks off
TRIGGER_GAP = 600             # s: at most one triggered heavy probe per target per this
INCIDENT_GAP = 1800           # s: at most one incident per target per this
KEEP_DAYS = 30
SOURCE_HOST = "speed.cloudflare.com"  # anycast: near any exit
SOURCE_PORT = 80              # plain HTTP inside the tunnel: the tunnel itself is the encryption
TIMEOUT = 15

_K_ON = "speed_enabled"
_K_HEAVY = "speed_heavy_minutes"
_K_ALERTS = "speed_alerts"    # "1" = incidents also go to the Telegram bot
_K_ACCT = "speed_probe_{}"    # per pool: encrypted {"uuid", "user", "password", "ready"}

_cycle_lock = threading.Lock()
_started = False


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(t: datetime | None) -> datetime | None:
    if t is not None and t.tzinfo is None:
        return t.replace(tzinfo=timezone.utc)
    return t


# --- settings ---------------------------------------------------------------
def _get(db: Session, key: str) -> str | None:
    s = db.get(Setting, key)
    return s.value if s and s.value not in (None, "") else None


def _put(db: Session, key: str, value: str) -> None:
    s = db.get(Setting, key)
    if s is None:
        db.add(Setting(key=key, value=value))
        db.flush()  # sessions don't autoflush: a second _put of the key must find this row
    else:
        s.value = value


def config(db: Session) -> dict:
    try:
        heavy = int(_get(db, _K_HEAVY) or 60)
    except ValueError:
        heavy = 60
    return {"enabled": _get(db, _K_ON) == "1", "heavy_minutes": heavy if heavy in HEAVY_CHOICES else 60,
            "alerts": _get(db, _K_ALERTS) == "1"}


def enabled(db: Session) -> bool:
    return _get(db, _K_ON) == "1"


def set_config(db: Session, on: bool, heavy_minutes: int, alerts: bool | None = None) -> None:
    """Persist the switch. Turning it on or off brings the service accounts onto /
    off the servers in the background (a reconcile of the pools that carry VLESS or
    NaiveProxy); probes through a pool wait until its account is there."""
    was = enabled(db)
    _put(db, _K_ON, "1" if on else "0")
    _put(db, _K_HEAVY, str(heavy_minutes if heavy_minutes in HEAVY_CHOICES else 60))
    if alerts is not None:
        _put(db, _K_ALERTS, "1" if alerts else "0")
    if was != on:
        for pool in _probe_pools(db):
            acct = probe_account(db, pool, create=on)
            if acct is not None:
                acct["ready"] = False
                _save_account(db, pool, acct)
    db.commit()
    if was != on:
        _sync_pools_async([p.id for p in _probe_pools(db)])


# --- the service account ----------------------------------------------------
def _probe_pools(db: Session) -> list[ExitPool]:
    return [p for p in db.query(ExitPool).order_by(ExitPool.id).all()
            if PROTO_VLESS in p.protocols or PROTO_NAIVE in p.protocols]


def _save_account(db: Session, pool: ExitPool, acct: dict) -> None:
    _put(db, _K_ACCT.format(pool.id), encrypt(json.dumps(acct)))


def probe_account(db: Session, pool: ExitPool, create: bool = False) -> dict | None:
    raw = _get(db, _K_ACCT.format(pool.id))
    if raw:
        try:
            return json.loads(decrypt(raw) or "")
        except ValueError:
            pass
    if not create:
        return None
    from . import naive

    acct = {"uuid": str(uuidlib.uuid4()), "user": f"p{secrets.token_hex(6)}",
            "password": naive.new_password(), "ready": False}
    _save_account(db, pool, acct)
    return acct


def probe_email(pool: ExitPool) -> str:
    return f"probe-{pool.id}"


def vless_probe_config(db: Session, pool: ExitPool):
    """The pool's service VLESS client, shaped like an IssuedConfig for reconcile —
    or None when monitoring is off (reconcile then removes it from the servers)."""
    if not enabled(db):
        return None
    acct = probe_account(db, pool)
    if not acct:
        return None
    return SimpleNamespace(identifier=probe_email(pool), uuid=acct["uuid"], payload="", sub_id="")


def naive_probe_user(db: Session, pool: ExitPool) -> tuple[str, str] | None:
    if not enabled(db):
        return None
    acct = probe_account(db, pool)
    return (acct["user"], acct["password"]) if acct else None


def _sync_pools_async(pool_ids: list[int]) -> None:
    def run() -> None:
        from .db import SessionLocal
        from .pool import reconcile_pool

        db = SessionLocal()
        try:
            for pid in pool_ids:
                pool = db.get(ExitPool, pid)
                if pool is None:
                    continue
                try:
                    reconcile_pool(db, pool)
                finally:
                    acct = probe_account(db, pool)
                    if acct is not None:
                        acct["ready"] = enabled(db)
                        _save_account(db, pool, acct)
                        db.commit()
        except Exception as e:
            log.warning("probe account sync failed: %s", e)
        finally:
            db.close()

    threading.Thread(target=run, name="speed-accounts", daemon=True).start()


# --- tunnels ----------------------------------------------------------------
def xray_binary() -> str | None:
    return shutil.which("xray") or (
        "/usr/local/bin/xray" if os.path.exists("/usr/local/bin/xray") else None
    )


def xray_client_config(pool: ExitPool, uuid: str, host: str, port: int, socks_port: int) -> dict:
    """A one-outbound xray client with a local SOCKS inbound — the same parameters
    as the pool's vless:// link (pool.vless_link)."""
    from .models import VLESS_XHTTP, reality_template

    user = {"id": uuid, "encryption": "none"}
    stream: dict = {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
            "serverName": pool.reality_sni,
            "fingerprint": reality_template()["fp"],
            "publicKey": pool.reality_public,
            "shortId": (pool.short_ids or [""])[0],
            "spiderX": pool.spider_x or "/",
        },
    }
    if pool.vless_transport == VLESS_XHTTP:
        stream["network"] = "xhttp"
        stream["xhttpSettings"] = {"path": pool.xhttp_path or "/", "mode": "auto"}
    else:
        user["flow"] = pool.vless_flow
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks",
                      "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": [{"protocol": "vless",
                       "settings": {"vnext": [{"address": host, "port": int(port), "users": [user]}]},
                       "streamSettings": stream}],
    }


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@contextmanager
def _xray(conf_for_port):
    """Run a throwaway xray client; yield its local SOCKS port."""
    binary = xray_binary()
    if not binary:
        raise RuntimeError("на Хабе нет xray — пересоберите образ панели")
    port = _free_port()
    fd, path = tempfile.mkstemp(suffix=".json", prefix="probe-")
    with os.fdopen(fd, "w") as f:
        json.dump(conf_for_port(port), f)
    proc = subprocess.Popen([binary, "run", "-c", path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 5
        while True:
            if proc.poll() is not None:
                err = (proc.stderr.read() or b"").decode("utf-8", "replace").strip().splitlines()
                raise RuntimeError(f"xray не запустился: {err[-1] if err else proc.returncode}")
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise RuntimeError("xray не открыл SOCKS-порт")
                time.sleep(0.05)
        yield port
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        try:
            os.unlink(path)
        except OSError:
            pass


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("соединение закрыто")
        buf += chunk
    return buf


def _socks_connect(port: int, host: str, dport: int) -> socket.socket:
    s = socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT)
    s.sendall(b"\x05\x01\x00")
    if _recv_exact(s, 2) != b"\x05\x00":
        raise ConnectionError("SOCKS: отказ")
    hb = host.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + dport.to_bytes(2, "big"))
    head = _recv_exact(s, 4)
    if head[1] != 0:
        raise ConnectionError(f"SOCKS: код {head[1]}")
    atyp = head[3]  # bound address: IPv4, IPv6 or a length-prefixed name — skip it
    alen = 4 if atyp == 1 else 16 if atyp == 4 else _recv_exact(s, 1)[0]
    _recv_exact(s, alen + 2)
    return s


def _read_headers(sock) -> tuple[int, bytes]:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("соединение закрыто до ответа")
        buf += chunk
        if len(buf) > 65536:
            raise ConnectionError("слишком длинный заголовок")
    head, rest = buf.split(b"\r\n\r\n", 1)
    m = re.match(rb"HTTP/\d(?:\.\d)? (\d{3})", head)
    return (int(m.group(1)) if m else 0), rest


def _naive_connect(host: str, port: int, sni: str, user: str, password: str) -> socket.socket:
    """NaiveProxy servers are HTTPS proxies: TLS (the route's name as SNI — the gate
    routes by it), then CONNECT with basic auth."""
    raw = socket.create_connection((host, int(port)), timeout=TIMEOUT)
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    s = ctx.wrap_socket(raw, server_hostname=sni)
    auth = base64.b64encode(f"{user}:{password}".encode()).decode()
    s.sendall(f"CONNECT {SOURCE_HOST}:{SOURCE_PORT} HTTP/1.1\r\nHost: {SOURCE_HOST}:{SOURCE_PORT}\r\n"
              f"Proxy-Authorization: Basic {auth}\r\n\r\n".encode())
    code, rest = _read_headers(s)
    if code != 200:
        raise ConnectionError(f"прокси ответил {code or 'не HTTP'}")
    if rest:
        raise ConnectionError("лишние данные после CONNECT")
    return s


# --- the download ------------------------------------------------------------
def measure(sock, heavy: bool, started: float) -> dict:
    """GET a file from SOURCE_HOST over an open stream. Light: LIGHT_BYTES, speed over
    the whole body. Heavy: HEAVY_CAP bytes for at most HEAVY_RAMP + HEAVY_SEC seconds
    after the first byte, speed over the part after the ramp."""
    nbytes = HEAVY_CAP if heavy else LIGHT_BYTES
    connect_ms = int((time.monotonic() - started) * 1000)
    sock.settimeout(TIMEOUT)
    sock.sendall((f"GET /__down?bytes={nbytes} HTTP/1.1\r\nHost: {SOURCE_HOST}\r\n"
                  "User-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n").encode())
    t_req = time.monotonic()
    code, body = _read_headers(sock)
    t_first = time.monotonic()
    if code != 200:
        raise ConnectionError(f"источник ответил {code}")
    got = len(body)
    ramp_at = ramp_bytes = None
    stop_at = t_first + HEAVY_RAMP + HEAVY_SEC
    while got < nbytes:
        now = time.monotonic()
        if heavy:
            if ramp_at is None and now - t_first >= HEAVY_RAMP:
                ramp_at, ramp_bytes = now, got
            if now >= stop_at:
                break
        chunk = sock.recv(65536)
        if not chunk:
            break
        got += len(chunk)
    t_end = time.monotonic()
    if not heavy and got < nbytes:
        raise ConnectionError(f"оборвалось на {got // 1024} КБ из {nbytes // 1024}")
    if heavy and ramp_at is not None and t_end - ramp_at >= 0.5:
        mbps = (got - ramp_bytes) * 8 / (t_end - ramp_at) / 1e6
    else:
        mbps = got * 8 / max(t_end - t_first, 0.001) / 1e6
    return {"ok": True, "bytes": got, "connect_ms": connect_ms,
            "ttfb_ms": int((t_first - t_req) * 1000), "mbps": round(mbps, 2)}


def _probe_route(db: Session, route: Route, proto: str, entry: Node, heavy: bool) -> dict:
    pool = route.pool
    acct = probe_account(db, pool)
    if not acct:
        raise RuntimeError("нет служебной учётки пула")
    host, port = entry.public_host, route.port_for(proto)
    started = time.monotonic()
    if proto == PROTO_VLESS:
        with _xray(lambda p: xray_client_config(pool, acct["uuid"], host, port, p)) as sp:
            started = time.monotonic()
            s = _socks_connect(sp, SOURCE_HOST, SOURCE_PORT)
            try:
                return measure(s, heavy, started)
            finally:
                s.close()
    sni = route.proto(proto).client_host if route.proto(proto) else ""
    if not sni:
        raise RuntimeError("у маршрута нет имени для NaiveProxy")
    s = _naive_connect(host, port, sni, acct["user"], acct["password"])
    try:
        return measure(s, heavy, started)
    finally:
        s.close()


def _probe_direct() -> dict:
    started = time.monotonic()
    s = socket.create_connection((SOURCE_HOST, SOURCE_PORT), timeout=TIMEOUT)
    try:
        return measure(s, True, started)
    finally:
        s.close()


def _record(db: Session, kind: str, fn, route: Route | None = None, proto: str = "",
            entry: Node | None = None) -> ProbeSample:
    try:
        res = fn()
    except Exception as e:
        res = {"ok": False, "error": (str(e) or type(e).__name__)[:250]}
    row = ProbeSample(kind=kind, route_id=route.id if route else None, protocol=proto,
                      entry_id=entry.id if entry else None, ok=res.get("ok", False),
                      bytes=res.get("bytes", 0), connect_ms=res.get("connect_ms"),
                      ttfb_ms=res.get("ttfb_ms"), mbps=res.get("mbps"), error=res.get("error", ""))
    db.add(row)
    db.commit()
    return row


# --- targets ----------------------------------------------------------------
def targets(db: Session) -> list[tuple[Route, str, Node]]:
    """(route, protocol, entry point) for every way a client can come in that the
    probes can follow (VLESS and NaiveProxy, routes that serve them now)."""
    out = []
    for r in db.query(Route).order_by(Route.id).all():
        if not r.enabled or r.pool is None:
            continue
        for proto in (PROTO_VLESS, PROTO_NAIVE):
            if not r.serves(proto) or r.proto_block_reason(proto):
                continue
            for e in r.entry_points:
                if e.public_host:
                    out.append((r, proto, e))
    return out


def _monitored_nodes(db: Session) -> list[Node]:
    seen: dict[int, Node] = {}
    for r in db.query(Route).order_by(Route.id).all():
        if not r.enabled or r.pool is None:
            continue
        for n in list(r.gates) + sorted(r.pool.members, key=lambda m: (m.priority, m.id)):
            seen.setdefault(n.id, n)
    return list(seen.values())


# --- server vitals ----------------------------------------------------------
_VITALS = r"""
head -1 /proc/stat
cat /proc/loadavg
echo "NCPU $(nproc 2>/dev/null)"
IF=$(ip -o route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1);exit}}')
echo "NET $(grep "^ *$IF:" /proc/net/dev | sed 's/^ *[^:]*://')"
echo "CT $(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo -) $(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo -)"
echo "LISTEN"
ss -Htln 2>/dev/null | awk '{print $4}'
echo "SS"
ss -Htin state established 2>/dev/null | head -6000
echo "ENDSS"
"""

_TCP = r"""
for t in __TARGETS__; do
  set -- $(echo "$t" | tr ',' ' ')
  best=-
  for k in 1 2 3; do
    s=$(date +%s%N)
    if timeout 3 bash -c "exec 3<>/dev/tcp/$2/$3" 2>/dev/null; then
      e=$(date +%s%N); ms=$(( (e - s) / 1000000 ))
      if [ "$best" = - ] || [ "$ms" -lt "$best" ]; then best=$ms; fi
    fi
  done
  echo "TCP $1 $best"
done
"""

_DIRECT = (
    "echo \"DIRECT $(curl -s -o /dev/null -m 6 -w '%{size_download} %{time_starttransfer} %{time_total}' "
    f"'http://{SOURCE_HOST}/__down?bytes={HEAVY_CAP}' 2>/dev/null)\"\n"
)


def _run_script(n, script: str, timeout: int = 60) -> str:
    b64 = base64.b64encode(script.encode()).decode()
    _rc, out, _err = n.run(f"echo {b64} | base64 -d | bash", timeout=timeout)
    return out


def _ip(addr: str) -> str:
    host = addr.rsplit(":", 1)[0].strip("[]")
    return host[7:] if host.startswith("::ffff:") else host


def _port(addr: str) -> int:
    try:
        return int(addr.rsplit(":", 1)[1])
    except (IndexError, ValueError):
        return 0


def parse_ss(lines: list[str], listen: set[int], node_ips: dict[str, int]) -> dict:
    """Aggregate `ss -Htin state established` into groups: a known server's id, "cli"
    (unknown peers that connected to us) and "net" (our own connections out to the
    internet). Per group: sockets, median RTT (ms), retransmitted share of segments (%)."""
    groups: dict[str, dict] = {}
    cur = None
    for line in lines:
        if not line.strip():
            continue
        if not line[0].isspace():
            parts = line.split()
            if len(parts) < 4:
                cur = None
                continue
            local, peer = parts[-2], parts[-1]
            if _port(local) == 22 or _port(peer) == 22:
                cur = None  # management SSH, ours
                continue
            nid = node_ips.get(_ip(peer))
            key = str(nid) if nid is not None else ("cli" if _port(local) in listen else "net")
            cur = groups.setdefault(key, {"n": 0, "rtts": [], "retr": 0, "segs": 0})
            cur["n"] += 1
            continue
        if cur is None:
            continue
        m = re.search(r"\brtt:([\d.]+)/", line)
        if m:
            cur["rtts"].append(float(m.group(1)))
        m = re.search(r"\bretrans:\d+/(\d+)", line)
        if m:
            cur["retr"] += int(m.group(1))
        m = re.search(r"\bsegs_out:(\d+)", line)
        if m:
            cur["segs"] += int(m.group(1))
    out = {}
    for k, g in groups.items():
        out[k] = {
            "n": g["n"],
            "rtt": round(statistics.median(g["rtts"]), 1) if g["rtts"] else None,
            "retr": round(g["retr"] * 100 / g["segs"], 2) if g["segs"] else None,
        }
    return out


def parse_vitals(out: str, prev_raw: dict | None, node_ips: dict[str, int]) -> dict:
    """Parse the vitals script's output into NodeSample fields (+ raw counters)."""
    lines = out.splitlines()
    res: dict = {"raw": {"t": time.time()}}
    listen: set[int] = set()
    ss_lines: list[str] = []
    mode = None
    tcp: dict[str, int | None] = {}
    for line in lines:
        if mode == "listen":
            if line == "SS":
                mode = "ss"
            else:
                p = _port(line.strip())
                if p:
                    listen.add(p)
            continue
        if mode == "ss":
            if line == "ENDSS":
                mode = None
            else:
                ss_lines.append(line)
            continue
        if line.startswith("cpu "):
            res["raw"]["cpu"] = [int(x) for x in line.split()[1:9]]
        elif re.match(r"^[\d.]+ [\d.]+ [\d.]+ ", line):
            res["load1"] = float(line.split()[0])
        elif line.startswith("NCPU "):
            v = line[5:].strip()
            res["ncpu"] = int(v) if v.isdigit() else None
        elif line.startswith("NET "):
            f = line[4:].split()
            if len(f) >= 12:
                res["raw"]["net"] = [int(f[0]), int(f[8]), int(f[2]) + int(f[10]), int(f[3]) + int(f[11])]
        elif line.startswith("CT "):
            c, m = (line[3:].split() + ["-", "-"])[:2]
            if c.isdigit() and m.isdigit() and int(m):
                res["conntrack_pct"] = round(int(c) * 100 / int(m), 1)
        elif line == "LISTEN":
            mode = "listen"
        elif line.startswith("TCP "):
            _, nid, ms = (line.split() + ["-"])[:3]
            tcp[nid] = int(ms) if ms.isdigit() else None
        elif line.startswith("DIRECT "):
            f = line[7:].split()
            try:
                size, ttfb, total = int(float(f[0])), float(f[1]), float(f[2])
                if size and total > ttfb:
                    res.setdefault("extra", {})["direct"] = round(size * 8 / (total - ttfb) / 1e6, 1)
            except (IndexError, ValueError):
                pass
    res["peers"] = parse_ss(ss_lines, listen, node_ips)
    res["conns"] = sum(1 for l in ss_lines if l.strip() and not l[0].isspace())
    if tcp:
        res.setdefault("extra", {})["tcp"] = tcp
    # deltas against the previous sample
    p = prev_raw or {}
    dt = res["raw"]["t"] - p.get("t", 0)
    cpu, pcpu = res["raw"].get("cpu"), p.get("cpu")
    if cpu and pcpu and len(cpu) == len(pcpu) == 8:
        d = [a - b for a, b in zip(cpu, pcpu)]
        total = sum(d)
        if total > 0:
            user, nice, system, idle, iowait, irq, softirq, steal = d
            res["steal"] = round(steal * 100 / total, 1)
            res["cpu"] = round((user + nice + system + irq + softirq) * 100 / total, 1)
    net, pnet = res["raw"].get("net"), p.get("net")
    if net and pnet and 0 < dt < 3600 and all(a >= b for a, b in zip(net, pnet)):
        res["rx_mbps"] = round((net[0] - pnet[0]) * 8 / dt / 1e6, 2)
        res["tx_mbps"] = round((net[1] - pnet[1]) * 8 / dt / 1e6, 2)
        res["errors"] = net[2] - pnet[2]
        res["drops"] = net[3] - pnet[3]
    return res


def _node_ips(db: Session) -> dict[str, int]:
    ips: dict[str, int] = {}
    for n in db.query(Node).all():
        for h in (n.public_host, n.ssh_host, n.awg_endpoint_host):
            if h and re.match(r"^[\d.]+$|^[0-9a-fA-F:]+$", h):
                ips.setdefault(h, n.id)
    return ips


def _gate_tcp_targets(db: Session, gate: Node) -> list[tuple[int, str, int]]:
    out: dict[int, tuple[int, str, int]] = {}
    for r in db.query(Route).filter(Route.gate_pool_id == gate.gate_pool_id).all() if gate.gate_pool_id else []:
        if r.pool is None:
            continue
        protos = r.pool.protocols
        port = r.pool.vless_port if PROTO_VLESS in protos else (443 if PROTO_NAIVE in protos else None)
        if not port:
            continue
        for x in r.pool.members:
            if x.public_host and re.match(r"^[\w.:-]+$", x.public_host):
                out.setdefault(x.id, (x.id, x.public_host, port))
    return list(out.values())


def collect_vitals(db: Session, node: Node, with_direct: bool) -> NodeSample:
    from .nodes import connect

    prev = (db.query(NodeSample).filter(NodeSample.node_id == node.id, NodeSample.ok.is_(True))
            .order_by(NodeSample.id.desc()).first())
    prev_raw = None
    if prev is not None and _aware(prev.at) and _now() - _aware(prev.at) < timedelta(minutes=20):
        try:
            prev_raw = json.loads(prev.raw_json or "{}")
        except ValueError:
            prev_raw = None
    script = _VITALS
    if node.role == ROLE_GATE:
        tg = _gate_tcp_targets(db, node)
        if tg:
            script += _TCP.replace("__TARGETS__", " ".join(f"{i},{h},{p}" for i, h, p in tg))
    elif with_direct:
        script += _DIRECT
    try:
        with connect(node) as n:
            out = _run_script(n, script, timeout=90)
        v = parse_vitals(out, prev_raw, _node_ips(db))
        row = NodeSample(
            node_id=node.id, ok=True, steal=v.get("steal"), cpu=v.get("cpu"), load1=v.get("load1"),
            ncpu=v.get("ncpu"), rx_mbps=v.get("rx_mbps"), tx_mbps=v.get("tx_mbps"),
            drops=v.get("drops"), errors=v.get("errors"), conntrack_pct=v.get("conntrack_pct"),
            conns=v.get("conns"), peers_json=json.dumps(v.get("peers", {})),
            extra_json=json.dumps(v.get("extra", {})), raw_json=json.dumps(v["raw"]),
        )
    except Exception as e:
        row = NodeSample(node_id=node.id, ok=False, error=(str(e) or type(e).__name__)[:250])
    db.add(row)
    db.commit()
    return row


# --- judging ----------------------------------------------------------------
def _target_q(db: Session, kind: str, route: Route, proto: str, entry: Node, since: datetime):
    return (db.query(ProbeSample)
            .filter(ProbeSample.kind == kind, ProbeSample.route_id == route.id,
                    ProbeSample.protocol == proto, ProbeSample.entry_id == entry.id,
                    ProbeSample.at >= since))


def _median(vals: list[float]) -> float | None:
    vals = [v for v in vals if v is not None]
    return statistics.median(vals) if vals else None


def light_off(db: Session, s: ProbeSample, route: Route, proto: str, entry: Node) -> str | None:
    """Why this light probe looks off against the target's last day, or None."""
    if not s.ok:
        return f"замер не прошёл: {s.error}"
    hist = [x for x in _target_q(db, PROBE_LIGHT, route, proto, entry, _now() - timedelta(days=1))
            .filter(ProbeSample.ok.is_(True), ProbeSample.id != s.id).all()]
    if len(hist) < 6:
        return None
    ttfb = _median([x.ttfb_ms for x in hist])
    mbps = _median([x.mbps for x in hist])
    if ttfb and s.ttfb_ms is not None and s.ttfb_ms > max(3 * ttfb, ttfb + 300):
        return f"задержка {s.ttfb_ms} мс при обычных {int(ttfb)}"
    if mbps and s.mbps is not None and s.mbps < 0.4 * mbps:
        return f"короткая загрузка {s.mbps:g} Мбит/с при обычных {mbps:.1f}"
    return None


def heavy_norm(db: Session, route: Route, proto: str, entry: Node, exclude_id: int | None = None) -> float | None:
    hist = (_target_q(db, PROBE_HEAVY, route, proto, entry, _now() - timedelta(days=7))
            .filter(ProbeSample.ok.is_(True)).all())
    vals = [x.mbps for x in hist if x.id != exclude_id]
    return _median(vals) if len(vals) >= 5 else None


def heavy_low(db: Session, s: ProbeSample, route: Route, proto: str, entry: Node) -> str | None:
    if not s.ok:
        return f"замер не прошёл: {s.error}"
    norm = heavy_norm(db, route, proto, entry, exclude_id=s.id)
    if norm and s.mbps is not None and s.mbps < 0.5 * norm:
        ratio = norm / s.mbps if s.mbps > 0 else float("inf")
        drop = f"в {ratio:.0f} раз ниже" if ratio >= 3 else f"−{100 - s.mbps * 100 / norm:.0f}%"
        return f"скорость {s.mbps:g} Мбит/с при обычных {norm:.0f} ({drop})"
    return None


def hints(db: Session, route: Route, proto: str, entry: Node, vitals: dict[int, NodeSample],
          control: ProbeSample | None, others_ok: list[str]) -> list[str]:
    """Likely causes, from the vitals taken in this same cycle."""
    out: list[str] = []
    if control is not None:
        norm = _median([x.mbps for x in db.query(ProbeSample).filter(
            ProbeSample.kind == PROBE_CONTROL, ProbeSample.ok.is_(True),
            ProbeSample.at >= _now() - timedelta(days=7), ProbeSample.id != control.id).all()])
        if not control.ok or (norm and control.mbps is not None and control.mbps < 0.5 * norm):
            out.append("у самого Хаба просел канал (контрольный замер напрямую тоже медленный) — "
                       "замеры этого цикла могут быть занижены")
    if others_ok:
        out.append(f"на том же входе в норме {', '.join(others_ok)} — медленно только этот протокол: "
                   "похоже на фильтрацию протокола (ТСПУ) или на сам сервис протокола")
    exits = sorted(route.pool.members, key=lambda m: (m.priority, m.id)) if route.pool else []
    for node in ([entry] if not route.is_direct else []) + exits:
        v = vitals.get(node.id)
        if v is None:
            continue
        name = node.name
        if not v.ok:
            out.append(f"{name}: не удалось снять показатели ({v.error})")
            continue
        if v.steal is not None and v.steal >= 10:
            out.append(f"{name}: steal {v.steal:g}% — процессор забирают соседи по железу у хостера")
        if v.cpu is not None and v.cpu >= 85:
            out.append(f"{name}: процессор загружен на {v.cpu:g}%")
        if v.conntrack_pct is not None and v.conntrack_pct >= 80:
            out.append(f"{name}: таблица соединений заполнена на {v.conntrack_pct:g}%")
        if (v.drops or 0) + (v.errors or 0) >= 100:
            out.append(f"{name}: на сетевом интерфейсе {v.drops or 0} отброшенных и {v.errors or 0} ошибочных пакетов за цикл")
        peers = v.peers
        cli = peers.get("cli") or {}
        if node.role == ROLE_GATE and (cli.get("retr") or 0) >= 5 and cli.get("n", 0) >= 3:
            out.append(f"{name}: у клиентов {cli['retr']:g}% повторных отправок — потери на участке клиенты → гейт")
        net = peers.get("net") or {}
        if node.role != ROLE_GATE and (net.get("retr") or 0) >= 3 and net.get("n", 0) >= 3:
            out.append(f"{name}: {net['retr']:g}% повторных отправок в интернет — проблема в канале выхода")
        for x in exits if node.role == ROLE_GATE else []:
            leg = peers.get(str(x.id)) or {}
            if (leg.get("retr") or 0) >= 3 and leg.get("n", 0) >= 2:
                out.append(f"{name} → {x.name}: {leg['retr']:g}% повторных отправок — потери в канале между гейтом и выходом")
            ms = (v.extra.get("tcp") or {}).get(str(x.id), "?")
            if ms is None:
                out.append(f"{name} → {x.name}: TCP не открывается")
            elif isinstance(ms, int) and ms >= 300:
                out.append(f"{name} → {x.name}: подключение {ms} мс")
        direct = v.extra.get("direct")
        if direct is not None and node.role != ROLE_GATE:
            norm = _median([s.extra.get("direct") for s in db.query(NodeSample).filter(
                NodeSample.node_id == node.id, NodeSample.ok.is_(True),
                NodeSample.at >= _now() - timedelta(days=7), NodeSample.id != v.id).all()])
            if norm and direct < 0.5 * norm:
                out.append(f"{name}: сам выход качает {direct:g} Мбит/с при обычных {norm:.0f} — узкое место в канале выхода")
    return out


_SNAP_GATE = r"""
echo "--- top"; top -bn1 2>/dev/null | head -15
echo "--- ss -s"; ss -s 2>/dev/null
for t in __TARGETS__; do
  set -- $(echo "$t" | tr ',' ' ')
  echo "--- путь до $1 ($2:$3)"
  if command -v mtr >/dev/null 2>&1; then mtr -rnc 10 -T -P "$3" "$2" 2>&1 | tail -25
  elif command -v tracepath >/dev/null 2>&1; then timeout 30 tracepath -n -m 20 "$2" 2>&1 | tail -25
  else echo "(нет mtr/tracepath)"; fi
done
"""

_SNAP_EXIT = r"""
echo "--- top"; top -bn1 2>/dev/null | head -15
echo "--- ss -s"; ss -s 2>/dev/null
echo "--- путь до __SRC__"
if command -v mtr >/dev/null 2>&1; then mtr -rnc 10 -T -P 80 __SRC__ 2>&1 | tail -25
elif command -v tracepath >/dev/null 2>&1; then timeout 30 tracepath -n -m 20 __SRC__ 2>&1 | tail -25
else echo "(нет mtr/tracepath)"; fi
"""


def snapshot(db: Session, route: Route, entry: Node) -> str:
    """What the gate and the exits look like right now (≈ a minute of SSH)."""
    from .nodes import connect

    parts: list[str] = []
    nodes: list[tuple[Node, str]] = []
    if not route.is_direct:
        tg = [(db.get(Node, i), h, p) for i, h, p in _gate_tcp_targets(db, entry)]
        tg = [(x, h, p) for x, h, p in tg if x is not None and x.pool_id == route.pool_id][:2]
        spec = " ".join(f"{re.sub(r'[^\w.-]', '_', x.name)},{h},{p}" for x, h, p in tg)
        nodes.append((entry, _SNAP_GATE.replace("__TARGETS__", spec)))
    for x in sorted(route.pool.members, key=lambda m: (m.priority, m.id))[:2]:
        nodes.append((x, _SNAP_EXIT.replace("__SRC__", SOURCE_HOST)))
    for node, script in nodes:
        try:
            with connect(node) as n:
                out = _run_script(n, script, timeout=120)
        except Exception as e:
            out = f"(не удалось: {e})"
        parts.append(f"===== {node.name} ({node.public_host}) =====\n{out.strip()[:6000]}")
    return "\n\n".join(parts)


def _incident(db: Session, route: Route, proto: str, entry: Node, reason: str,
              vitals: dict[int, NodeSample], control: ProbeSample | None, others_ok: list[str]) -> None:
    last = (db.query(ProbeIncident).filter(ProbeIncident.route_id == route.id,
                                           ProbeIncident.protocol == proto,
                                           ProbeIncident.entry_id == entry.id)
            .order_by(ProbeIncident.id.desc()).first())
    if last is not None and _now() - _aware(last.at) < timedelta(seconds=INCIDENT_GAP):
        return
    try:
        snap = snapshot(db, route, entry)
    except Exception as e:
        snap = f"(снимок не снят: {e})"
    hs = hints(db, route, proto, entry, vitals, control, others_ok)
    db.add(ProbeIncident(route_id=route.id, protocol=proto, entry_id=entry.id, reason=reason[:255],
                         hints_json=json.dumps(hs, ensure_ascii=False), snapshot=snap))
    db.commit()
    log.warning("speed incident: %s / %s / %s — %s", route.name, proto, entry.name, reason)
    if config(db)["alerts"]:
        try:
            from . import tgbot
            from .models import PROTOCOL_LABELS

            text = (f"🐢 Скорость: {route.name} · {PROTOCOL_LABELS.get(proto, proto)} · {entry.name}\n{reason}"
                    + ("\n\n" + "\n".join("• " + h for h in hs[:5]) if hs else "")
                    + "\n\nПодробно — вкладка «Скорость», раздел «Провалы».")
            if tgbot.enabled():
                tgbot.broadcast(text)
        except Exception as e:
            log.warning("speed alert not sent: %s", e)


# --- the cycle --------------------------------------------------------------
def _pool_ready(db: Session, pool: ExitPool) -> bool:
    acct = probe_account(db, pool)
    if acct is None:
        probe_account(db, pool, create=True)
        db.commit()
        _sync_pools_async([pool.id])
        return False
    return bool(acct.get("ready"))


def run_cycle(db: Session, heavy_due: bool) -> dict:
    """One monitoring cycle (see the module docstring). Returns a short summary."""
    if not enabled(db):
        return {"skipped": "off"}
    summary = {"vitals": 0, "light": 0, "heavy": 0, "incidents": 0}
    vitals: dict[int, NodeSample] = {}
    for node in _monitored_nodes(db):
        vitals[node.id] = collect_vitals(db, node, with_direct=heavy_due)
        summary["vitals"] += 1
    control = _record(db, PROBE_CONTROL, _probe_direct) if heavy_due else None
    tgts = targets(db)
    ready = {}
    lights: dict[tuple, tuple[ProbeSample, str | None]] = {}
    for route, proto, entry in tgts:
        if route.pool_id not in ready:
            ready[route.pool_id] = _pool_ready(db, route.pool)
        if not ready[route.pool_id]:
            continue
        s = _record(db, PROBE_LIGHT, lambda: _probe_route(db, route, proto, entry, False), route, proto, entry)
        lights[(route.id, proto, entry.id)] = (s, light_off(db, s, route, proto, entry))
        summary["light"] += 1
    for route, proto, entry in tgts:
        got = lights.get((route.id, proto, entry.id))
        if got is None:
            continue
        s, off = got
        heavy = None
        if off:
            last = (_target_q(db, PROBE_HEAVY, route, proto, entry, _now() - timedelta(seconds=TRIGGER_GAP))
                    .order_by(ProbeSample.id.desc()).first())
            if last is None:
                heavy = _record(db, PROBE_HEAVY, lambda: _probe_route(db, route, proto, entry, True),
                                route, proto, entry)
        elif heavy_due:
            heavy = _record(db, PROBE_HEAVY, lambda: _probe_route(db, route, proto, entry, True),
                            route, proto, entry)
        if heavy is None:
            continue
        summary["heavy"] += 1
        low = heavy_low(db, heavy, route, proto, entry)
        if low:
            others_ok = [p for (rid, p, eid), (ls, loff) in lights.items()
                         if rid == route.id and eid == entry.id and p != proto and ls.ok and not loff]
            reason = low + (f"; короткий замер: {off}" if off and not off.startswith("замер не прошёл") else "")
            _incident(db, route, proto, entry, reason, vitals, control, others_ok)
            summary["incidents"] += 1
    return summary


def purge(db: Session) -> None:
    cut = _now() - timedelta(days=KEEP_DAYS)
    for model in (ProbeSample, NodeSample, ProbeIncident):
        db.query(model).filter(model.at < cut).delete(synchronize_session=False)
    db.commit()


def _cycle(heavy_due: bool) -> None:
    from .db import SessionLocal

    if not _cycle_lock.acquire(blocking=False):
        return
    db = SessionLocal()
    try:
        res = run_cycle(db, heavy_due)
        if res.get("skipped") is None:
            log.info("speed cycle: %s", res)
    except Exception as e:
        log.warning("speed cycle failed: %s", e)
        db.rollback()
    finally:
        db.close()
        _cycle_lock.release()


def run_now() -> bool:
    """«Замерить сейчас»: a full cycle with heavy probes, in the background.
    False if a cycle is already running."""
    if _cycle_lock.locked():
        return False
    threading.Thread(target=_cycle, args=(True,), name="speed-now", daemon=True).start()
    return True


def running() -> bool:
    return _cycle_lock.locked()


def _loop() -> None:
    from .db import SessionLocal

    time.sleep(45)  # let the panel settle
    next_heavy = 0.0
    last_purge = 0.0
    while True:
        t0 = time.monotonic()
        try:
            db = SessionLocal()
            try:
                cfg = config(db)
                if time.time() - last_purge > 86400:
                    purge(db)
                    last_purge = time.time()
            finally:
                db.close()
            if cfg["enabled"]:
                heavy_due = cfg["heavy_minutes"] > 0 and t0 >= next_heavy
                if heavy_due:
                    next_heavy = t0 + cfg["heavy_minutes"] * 60 + random.uniform(-300, 300)
                _cycle(heavy_due)
            else:
                next_heavy = 0.0  # the first cycle after switching on is a full one
        except Exception as e:
            log.warning("speed loop: %s", e)
        time.sleep(max(30.0, CYCLE_SEC + random.uniform(-CYCLE_JITTER, CYCLE_JITTER) - (time.monotonic() - t0)))


def start() -> None:
    global _started
    if _started:
        return
    _started = True
    threading.Thread(target=_loop, name="speed", daemon=True).start()


# --- the page ---------------------------------------------------------------
def spark(points: list[tuple[datetime, float | None]], t0: datetime, t1: datetime,
          w: int = 260, h: int = 40) -> dict:
    """SVG polyline points for (time, value); None values are failures (dots on the axis)."""
    span = max((t1 - t0).total_seconds(), 1)
    vals = [v for _, v in points if v is not None]
    top = max(vals) if vals else 1
    top = top or 1
    line, fails = [], []
    for t, v in points:
        x = round((_aware(t) - t0).total_seconds() / span * w, 1)
        if v is None:
            fails.append(x)
        else:
            line.append(f"{x},{round(h - 2 - v / top * (h - 6), 1)}")
    return {"line": " ".join(line), "fails": fails, "top": top, "w": w, "h": h}


def overview(db: Session, days: int) -> dict:
    t1 = _now()
    t0 = t1 - timedelta(days=days)
    rows = []
    for route, proto, entry in targets(db):
        heavy = _target_q(db, PROBE_HEAVY, route, proto, entry, t0).order_by(ProbeSample.at).all()
        light = _target_q(db, PROBE_LIGHT, route, proto, entry, t0).order_by(ProbeSample.at).all()
        ok_h = [x.mbps for x in heavy if x.ok and x.mbps is not None]
        rows.append({
            "route": route, "proto": proto, "entry": entry,
            "last_heavy": heavy[-1] if heavy else None,
            "last_light": light[-1] if light else None,
            "median": _median(ok_h), "min": min(ok_h) if ok_h else None,
            "light_ok": (round(sum(1 for x in light if x.ok) * 100 / len(light)) if light else None),
            "ttfb": _median([x.ttfb_ms for x in light if x.ok]),
            "spark": spark([(x.at, x.mbps if x.ok else None) for x in heavy], t0, t1),
            "spark_ttfb": spark([(x.at, x.ttfb_ms if x.ok else None) for x in light], t0, t1),
        })
    nodes = []
    for node in _monitored_nodes(db):
        ss = (db.query(NodeSample).filter(NodeSample.node_id == node.id, NodeSample.at >= t0)
              .order_by(NodeSample.at).all())
        ok = [x for x in ss if x.ok]
        nodes.append({
            "node": node, "last": ss[-1] if ss else None,
            "steal_max": max((x.steal for x in ok if x.steal is not None), default=None),
            "steal_med": _median([x.steal for x in ok]),
            "spark_steal": spark([(x.at, x.steal) for x in ok if x.steal is not None], t0, t1),
            "spark_rx": spark([(x.at, x.rx_mbps) for x in ok if x.rx_mbps is not None], t0, t1),
        })
    control = (db.query(ProbeSample).filter(ProbeSample.kind == PROBE_CONTROL, ProbeSample.at >= t0)
               .order_by(ProbeSample.at).all())
    day = t1 - timedelta(days=1)
    spent = sum(x.bytes or 0 for x in db.query(ProbeSample).filter(ProbeSample.at >= day).all())
    incidents = (db.query(ProbeIncident).filter(ProbeIncident.at >= t0)
                 .order_by(ProbeIncident.id.desc()).limit(50).all())
    names = {n.id: n.name for n in db.query(Node).all()}
    return {
        "rows": rows, "nodes": nodes, "incidents": incidents, "names": names,
        "control_last": control[-1] if control else None,
        "control_median": _median([x.mbps for x in control if x.ok]),
        "spent_day": spent, "t0": t0, "t1": t1,
        "xray": bool(xray_binary()),
        "pending": [p.name for p in _probe_pools(db)
                    if enabled(db) and not (probe_account(db, p) or {}).get("ready")],
    }
