"""Gate relay: what a gate forwards, and the daemon that does it.

A gate is a transparent L4 forwarder in front of server pools. It never decrypts:
client → gate:PORT → server:PORT → internet, the client's obfuscation riding along
unchanged. Every gate of a gate pool runs the SAME relay, built from ALL routes
that use the gate pool — so one gate pool can front several protocols and several
server pools at once:

  * a port that carries ONE target (one server pool + port) is plain kernel DNAT
    (nftables), TCP or UDP;
  * a TCP port shared by several TLS routes (e.g. VLESS-Reality and NaiveProxy on
    443, or two Reality pools with different SNIs) is split by the SNI of the TLS
    ClientHello — an HAProxy in TCP mode reads it (never terminates TLS) and pipes
    the connection to the right pool;
  * UDP has no SNI, so two UDP routes (AmneziaWG) can't share a port.

A tiny daemon on the gate health-checks each server pool (active/standby by
priority, with hysteresis) and keeps both the nftables table and the HAProxy
backends pointed only at the live member, so a dead/banned server fails over with
no client reconfiguration.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from .node_ssh import SSHNode
from .provisioning import ProvisionError, TEMPLATE_PATH, _put_file, disable_fail2ban

NAIVE_SERVER_PORT = 443  # NaiveProxy (Caddy) listens on 443 on its servers
DEFAULT_NAIVE_CLIENT_PORT = 443
PLAN_VERSION = 2


# --------------------------------------------------------------------------
# The plan: panel-side, pure (testable without a gate)
# --------------------------------------------------------------------------
@dataclass
class Service:
    """One thing a route needs the gate to forward."""
    route: str          # route name (for messages)
    proto: str          # 'tcp' | 'udp'
    port: int           # port on the gate (what clients dial)
    group: str          # server pool key
    to_port: int        # port on the server
    sni: list[str] = field(default_factory=list)  # TLS server names (TCP only)

    @property
    def target(self) -> tuple[str, int]:
        return (self.group, self.to_port)


class RelayConflict(ValueError):
    """The routes of a gate pool can't be served by one relay (explains why)."""


def reality_server_names() -> list[str]:
    """SNIs the VLESS-Reality inbound answers to (from the inbound template — the
    same for every pool until pools get their own masquerade site)."""
    try:
        tpl = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
        names = tpl["streamSettings"]["realitySettings"]["serverNames"]
        return [str(n).lower() for n in names if n]
    except Exception:
        return []


def route_services(route) -> list[Service]:
    """What the gate must forward for `route` (a models.Route with its pool)."""
    pool = route.pool
    if pool is None:
        return []
    group = str(pool.id)
    out: list[Service] = []
    for proto in route.protocols:
        if proto == "vless":
            port = route.client_port if (route.client_port and not route.is_legacy) else pool.vless_port
            out.append(Service(route.name, "tcp", int(port), group, int(pool.vless_port),
                               list(getattr(pool, "reality_names", None) or reality_server_names())))
        elif proto == "awg":
            port = route.client_port if (route.client_port and not route.is_legacy) else pool.awg_port
            out.append(Service(route.name, "udp", int(port), group, int(pool.awg_port)))
        elif proto == "naive":
            port = route.client_port or DEFAULT_NAIVE_CLIENT_PORT
            sni = [route.client_host.lower()] if route.client_host else []
            out.append(Service(route.name, "tcp", int(port), group, NAIVE_SERVER_PORT, sni))
    return out


def build_plan(routes) -> dict:
    """Turn the routes of a gate pool into the daemon's config, or raise
    RelayConflict naming the routes that clash and what to change."""
    services: list[Service] = []
    groups: dict[str, dict] = {}
    for r in routes:
        if r.pool is None:
            continue
        svc = route_services(r)
        if not svc:
            continue
        services.extend(svc)
        key = str(r.pool.id)
        if key not in groups:
            members = sorted(r.pool.members, key=lambda m: (m.priority, m.id))
            groups[key] = {
                "name": r.pool.name,
                "exits": [m.public_host for m in members],
                "probe_tcp": [],
            }
        for s in svc:
            if s.proto == "tcp" and s.to_port not in groups[key]["probe_tcp"]:
                groups[key]["probe_tcp"].append(s.to_port)
    if not services:
        raise RelayConflict("маршрутам пула гейтов нечего пересылать (нет пулов серверов)")
    for key, g in groups.items():
        if not g["exits"]:
            raise RelayConflict(f"в пуле серверов «{g['name']}» нет серверов")

    dnat: list[dict] = []
    sni: list[dict] = []
    by_port: dict[tuple[str, int], list[Service]] = {}
    for s in services:
        by_port.setdefault((s.proto, s.port), []).append(s)

    for (proto, port), svcs in sorted(by_port.items()):
        targets: dict[tuple[str, int], list[Service]] = {}
        for s in svcs:
            targets.setdefault(s.target, []).append(s)
        if len(targets) == 1:
            (group, to_port), _ = next(iter(targets.items()))
            dnat.append({"proto": proto, "port": port, "group": group, "to_port": to_port})
            continue
        names = ", ".join(sorted({s.route for s in svcs}))
        if proto == "udp":
            raise RelayConflict(
                f"UDP-порт {port} нужен сразу нескольким маршрутам ({names}) — по UDP их не "
                f"развести: задайте маршрутам разные клиентские порты"
            )
        # TCP: split by SNI — every target needs its own, non-overlapping names.
        backends, seen = [], {}
        for (group, to_port), ts in targets.items():
            snis = sorted({n for t in ts for n in t.sni})
            rnames = ", ".join(sorted({t.route for t in ts}))
            if not snis:
                raise RelayConflict(
                    f"TCP-порт {port} делят маршруты ({names}), а у «{rnames}» нет SNI, по "
                    f"которому гейт мог бы отличить его трафик: задайте ему имя или другой порт"
                )
            for n in snis:
                if n in seen and seen[n] != rnames:
                    raise RelayConflict(
                        f"TCP-порт {port}: маршруты «{seen[n]}» и «{rnames}» отвечают на один "
                        f"SNI «{n}» — гейт их не различит: разные SNI или разные порты"
                    )
                seen[n] = rnames
            backends.append({"names": snis, "group": group, "to_port": to_port, "routes": rnames})
        sni.append({"port": port, "backends": backends})

    for g in groups.values():
        g["probe_port"] = g["probe_tcp"][0] if g["probe_tcp"] else 22  # AWG-only: is the host up
        del g["probe_tcp"]
    return {"version": PLAN_VERSION, "interval": 5, "groups": groups, "dnat": dnat, "sni": sni}


def plan_summary(plan: dict) -> str:
    parts = [f"{d['proto']}/{d['port']}→{plan['groups'][d['group']]['name']}:{d['to_port']}"
             for d in plan["dnat"]]
    for s in plan["sni"]:
        parts.append(f"tcp/{s['port']} по SNI → " + ", ".join(
            f"{plan['groups'][b['group']]['name']}:{b['to_port']}" for b in s["backends"]))
    return "; ".join(parts)


# --------------------------------------------------------------------------
# The daemon (runs on the gate; stdlib only)
# --------------------------------------------------------------------------
RELAY_DAEMON = r'''#!/usr/bin/env python3
"""VesPN gate relay daemon. Reads the relay plan the panel pushes to
/etc/vespn-relay/members.json, TCP-probes the members of every server pool with
hysteresis and keeps the gate pointed at the single highest-priority HEALTHY
member of each pool (active/standby): nftables DNAT for single-target ports, an
HAProxy (TCP mode, SNI routing, never terminates TLS) for TCP ports shared by
several TLS routes. The gate forwards ciphertext only; it never decrypts."""
import json, os, socket, subprocess, sys, time

CONF = "/etc/vespn-relay/members.json"
NFT_FILE = "/run/vespn-relay.nft"
HAP_FILE = "/etc/vespn-relay/haproxy.cfg"
UP, DOWN = 2, 2  # consecutive probes needed to flip a member up/down


def load():
    try:
        with open(CONF) as f:
            cfg = json.load(f)
    except Exception:
        return None
    if cfg.get("version") == 2:
        return cfg
    # v1 (one pool, same port in and out): keep old gates working after an update.
    exits = list(cfg.get("exits", []))
    tcp, udp = cfg.get("tcp_ports", []), cfg.get("udp_ports", [])
    probe = int(cfg.get("probe_port") or (tcp[0] if tcp else 0) or 22)
    return {
        "version": 2, "interval": int(cfg.get("interval", 5)),
        "groups": {"0": {"name": "pool", "exits": exits, "probe_port": probe}},
        "dnat": [{"proto": "tcp", "port": int(p), "group": "0", "to_port": int(p)} for p in tcp]
              + [{"proto": "udp", "port": int(p), "group": "0", "to_port": int(p)} for p in udp],
        "sni": [],
    }


def tcp_ok(ip, port, timeout=2.0):
    try:
        s = socket.create_connection((ip, int(port)), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def build_nft(cfg, active):
    lines = [
        "add table ip vespn_relay",
        "flush table ip vespn_relay",
        "add chain ip vespn_relay pre { type nat hook prerouting priority dstnat; policy accept; }",
        "add chain ip vespn_relay post { type nat hook postrouting priority srcnat; policy accept; }",
    ]
    targets = set()
    for d in cfg.get("dnat", []):
        ip = active.get(d["group"])
        if not ip:
            continue  # no live member: drop rather than send to a dead one
        lines.append("add rule ip vespn_relay pre %s dport %d dnat to %s:%d"
                     % (d["proto"], int(d["port"]), ip, int(d["to_port"])))
        targets.add(ip)
    if targets:
        lines.append("add rule ip vespn_relay post ip daddr { %s } masquerade" % ", ".join(sorted(targets)))
    return "\n".join(lines) + "\n"


def build_haproxy(cfg, active):
    if not cfg.get("sni"):
        return ""
    out = [
        "global", "    maxconn 20000", "",
        "defaults", "    mode tcp", "    timeout connect 5s",
        "    timeout client 1h", "    timeout server 1h", "    option splice-auto", "",
    ]
    for s in cfg["sni"]:
        port = int(s["port"])
        out += ["frontend sni_%d" % port, "    bind :%d" % port,
                "    tcp-request inspect-delay 5s",
                "    tcp-request content accept if { req_ssl_hello_type 1 }"]
        for i, b in enumerate(s["backends"]):
            # HAProxy stops at 64 words a line and a Reality pool can answer to many
            # SNIs: split the list over lines of one named ACL (same name = OR).
            names = b["names"]
            for k in range(0, len(names), 40):
                out.append("    acl sni_%d_%d req_ssl_sni -i %s" % (port, i, " ".join(names[k:k + 40])))
            out.append("    use_backend b_%d_%d if sni_%d_%d" % (port, i, port, i))
        out.append("    default_backend b_%d_0" % port)  # unknown SNI: first (Reality → real site)
        out.append("")
        for i, b in enumerate(s["backends"]):
            out.append("backend b_%d_%d" % (port, i))
            ip = active.get(b["group"])
            if ip:
                out.append("    server s %s:%d" % (ip, int(b["to_port"])))
            out.append("")
    return "\n".join(out) + "\n"


def apply_nft(text):
    with open(NFT_FILE, "w") as f:
        f.write(text)
    subprocess.run(["nft", "-f", NFT_FILE], check=False)


def apply_haproxy(text):
    if not text:
        subprocess.run(["systemctl", "stop", "vespn-sni"], check=False)
        return
    with open(HAP_FILE, "w") as f:
        f.write(text)
    if subprocess.run(["systemctl", "is-active", "--quiet", "vespn-sni"]).returncode == 0:
        subprocess.run(["systemctl", "reload", "vespn-sni"], check=False)
    else:
        subprocess.run(["systemctl", "start", "vespn-sni"], check=False)


def drop_flows_to(ip):
    """Forget conntrack entries whose reply comes from `ip` (the old active server).
    Without this a UDP client that keeps sending (AmneziaWG keepalives) stays
    DNAT'ed to the dead server forever — its entry never times out."""
    subprocess.run(["conntrack", "-D", "--reply-src", ip],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def main():
    state = {}
    last = None
    prev_active = {}
    while True:
        cfg = load() or {"groups": {}, "dnat": [], "sni": [], "interval": 5}
        groups = cfg.get("groups", {})
        active, healthy_all = {}, {}
        for key, g in groups.items():
            probe = int(g.get("probe_port") or 22)
            exits = list(g.get("exits", []))  # priority order (lower index = preferred)
            for ip in exits:
                st = state.setdefault((key, ip), {"up": False, "s": 0, "f": 0})
                if tcp_ok(ip, probe):
                    st["s"] += 1; st["f"] = 0
                    if not st["up"] and st["s"] >= UP:
                        st["up"] = True
                else:
                    st["f"] += 1; st["s"] = 0
                    if st["up"] and st["f"] >= DOWN:
                        st["up"] = False
            healthy = [ip for ip in exits if state.get((key, ip), {}).get("up")]
            healthy_all[key] = healthy
            if healthy:
                active[key] = healthy[0]
        for k in list(state):
            if k[0] not in groups or k[1] not in groups[k[0]].get("exits", []):
                del state[k]
        sig = json.dumps([cfg.get("dnat"), cfg.get("sni"), active], sort_keys=True)
        if sig != last:
            apply_nft(build_nft(cfg, active))
            apply_haproxy(build_haproxy(cfg, active))
            last = sig
            for key, old in prev_active.items():
                if old and active.get(key) != old:
                    drop_flows_to(old)
            prev_active = dict(active)
            for key, g in groups.items():
                a = [active[key]] if key in active else []
                sys.stderr.write("vespn-relay: pool=%s active=%r (healthy=%r)\n"
                                 % (g.get("name", key), a, healthy_all.get(key, [])))
            sys.stderr.flush()
        time.sleep(int(cfg.get("interval", 5)))


if __name__ == "__main__":
    main()
'''

RELAY_SERVICE = """[Unit]
Description=VesPN gate relay daemon (health-checked nftables DNAT / SNI routing to server pools)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/vespn-relay-daemon.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
"""

# HAProxy for SNI-split ports; started/reloaded by the relay daemon only when the
# plan has such ports (not enabled at boot on its own — the daemon brings it up).
SNI_SERVICE = """[Unit]
Description=VesPN gate SNI router (HAProxy, TCP mode — never terminates TLS)
After=network-online.target

[Service]
Type=notify
ExecStartPre=/usr/sbin/haproxy -c -q -f /etc/vespn-relay/haproxy.cfg
ExecStart=/usr/sbin/haproxy -Ws -f /etc/vespn-relay/haproxy.cfg
ExecReload=/usr/sbin/haproxy -c -q -f /etc/vespn-relay/haproxy.cfg
ExecReload=/bin/kill -USR2 $MAINPID
Restart=on-failure
"""


# --------------------------------------------------------------------------
# Installing it on a gate
# --------------------------------------------------------------------------
def install(node: SSHNode, plan: dict) -> dict:
    """Set `node` up as the relay described by `plan`: daemon + systemd units,
    HAProxy if any port is SNI-split, ip_forward. Idempotent — re-running refreshes
    the files and restarts the daemon (which applies the new plan)."""
    if not plan.get("dnat") and not plan.get("sni"):
        raise ProvisionError("no ports to relay")
    need_haproxy = bool(plan.get("sni"))
    pkgs = "command -v nft >/dev/null 2>&1 || (apt-get update && apt-get install -y nftables) >/dev/null 2>&1; " \
           "command -v python3 >/dev/null 2>&1 || (apt-get update && apt-get install -y python3) >/dev/null 2>&1; " \
           "command -v conntrack >/dev/null 2>&1 || (apt-get update && apt-get install -y conntrack) >/dev/null 2>&1; "
    if need_haproxy:
        pkgs += ("command -v haproxy >/dev/null 2>&1 || (apt-get update && apt-get install -y haproxy) >/dev/null 2>&1; "
                 "systemctl disable --now haproxy >/dev/null 2>&1; ")  # we run our own unit
    node.run(pkgs + "true", timeout=600)
    if need_haproxy:
        rc, _, _ = node.run("command -v haproxy", timeout=15)
        if rc != 0:
            raise ProvisionError("не удалось установить HAProxy на гейт (нужен для разводки по SNI)")
    disable_fail2ban(node)  # must never ban the servers it relays to or the panel
    _put_file(node, "/etc/sysctl.d/99-vespn-relay.conf", "net.ipv4.ip_forward=1\n")
    node.run("sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1", timeout=20)
    node.run("mkdir -p /etc/vespn-relay", timeout=20)
    _put_file(node, "/etc/vespn-relay/members.json", json.dumps(plan, indent=2) + "\n")
    _put_file(node, "/usr/local/bin/vespn-relay-daemon.py", RELAY_DAEMON)
    _put_file(node, "/etc/systemd/system/vespn-relay.service", RELAY_SERVICE)
    _put_file(node, "/etc/systemd/system/vespn-sni.service", SNI_SERVICE)
    rc, out, err = node.run(
        "chmod +x /usr/local/bin/vespn-relay-daemon.py && systemctl daemon-reload && "
        "systemctl enable vespn-relay.service >/dev/null 2>&1 && "
        "systemctl restart vespn-relay.service 2>&1",
        timeout=60,
    )
    if rc != 0:
        raise ProvisionError(f"relay daemon setup failed:\n{(err or out)[-700:]}")
    node.run("sleep 6", timeout=15)  # two probe rounds → members come up, rules applied
    _rc, status, _ = node.run("systemctl is-active vespn-relay.service 2>&1", timeout=15)
    _rc, rules, _ = node.run("nft list table ip vespn_relay 2>&1", timeout=20)
    sni_state = ""
    if need_haproxy:
        _rc, sni_state, _ = node.run("systemctl is-active vespn-sni.service 2>&1", timeout=15)
    return {"daemon": status.strip(), "sni": sni_state.strip(), "rules": rules.strip()}
