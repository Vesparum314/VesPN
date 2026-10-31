"""Provision a fresh node's VLESS side: install mainline 3x-ui (MHSanaei) and
create a VLESS+Reality+Vision inbound with freshly generated keys.

The user deploys AmneziaWG themselves; this only handles the part the panel owns.
Per the no-migration model each node gets its OWN Reality keys — we reuse node
B's inbound only as a *shape* template (masquerade target + serverNames), never
its secrets.

NOTE: install + inbound creation are exercised for real only once a fresh node
(server C) is available; the contract follows mainline 3x-ui.
"""

from __future__ import annotations

import base64
import json
import secrets
import shlex
from pathlib import Path

from . import awg
from .config import settings
from .node_ssh import SSHNode
from .xui import XUIClient

TEMPLATE_PATH = Path(__file__).parent / "data" / "vless_inbound_template.json"


class ProvisionError(RuntimeError):
    pass


def _parse_env(text: str) -> dict[str, str]:
    env: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def ensure_base(node: SSHNode) -> None:
    """Install packages a fresh minimal Debian lacks but provisioning needs.
    Notably `curl`: the 3x-ui installer, the Docker install script and the Xray
    pin all shell out to curl, and fresh ufo.hosting Debian 13 ships without it."""
    _rc, out, _ = node.run("command -v curl >/dev/null 2>&1 && echo yes || echo no", timeout=20)
    if out.strip().endswith("yes"):
        return
    node.run(
        "apt-get update >/dev/null 2>&1; "
        "DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates >/dev/null 2>&1; true",
        timeout=300,
    )
    _rc, chk, _ = node.run("command -v curl || echo NONE", timeout=15)
    if "NONE" in chk:
        raise ProvisionError("could not install curl on the node (needed for provisioning)")


def install_3xui(node: SSHNode) -> dict:
    """Run the 3x-ui installer non-interactively and return the generated
    {xui_path, xui_port, xui_token, username, password}."""
    cmd = f"DEBIAN_FRONTEND=noninteractive bash -lc {shlex.quote(settings.xui_install_cmd)} </dev/null"
    rc, out, err = node.run(cmd, timeout=900)
    if rc != 0:
        raise ProvisionError(f"3x-ui installer failed (rc={rc}):\n{(err or out)[-2000:]}")

    rc, env_out, _ = node.run("cat /etc/x-ui/install-result.env", timeout=30)
    if rc != 0 or "XUI_API_TOKEN" not in env_out:
        raise ProvisionError(
            "installer finished but /etc/x-ui/install-result.env is missing the "
            "API token — the installer may have run interactively. Installer tail:\n"
            + out[-1500:]
        )
    env = _parse_env(env_out)
    try:
        return {
            "xui_path": env["XUI_WEB_BASE_PATH"],
            "xui_port": int(env["XUI_PANEL_PORT"]),
            "xui_token": env["XUI_API_TOKEN"],
            "username": env.get("XUI_USERNAME", ""),
            "password": env.get("XUI_PASSWORD", ""),
        }
    except KeyError as e:
        raise ProvisionError(f"install-result.env missing {e}") from e


def set_panel_localhost(node: SSHNode) -> None:
    """Bind the 3x-ui panel to 127.0.0.1 so it is reachable only via SSH tunnel
    (never exposed publicly). The panel reaches the API through the tunnel, so
    this doesn't break anything. Takes effect on the next x-ui restart."""
    rc, out, err = node.run(f"{settings.xui_folder}/x-ui setting -listenIP 127.0.0.1", timeout=30)
    if rc != 0:
        raise ProvisionError(f"could not set panel listenIP: {(err or out)[-400:]}")


_SUB_DISABLE_PY = """import sqlite3
c=sqlite3.connect("/etc/x-ui/x-ui.db")
def setk(k,v):
    if list(c.execute("SELECT 1 FROM settings WHERE key=?",(k,))): c.execute("UPDATE settings SET value=? WHERE key=?",(v,k))
    else: c.execute("INSERT INTO settings (key,value) VALUES (?,?)",(k,v))
setk("subListen","127.0.0.1"); setk("subEnable","false"); c.commit()
"""


def harden_subscription(node: SSHNode, xui_folder: str | None = None) -> None:
    """Stop the 3x-ui subscription server from listening on a public port. We hand
    out direct links, never subscriptions, so the sub server (default :2096) is
    pure attack surface. Bind it to localhost + disable it in the x-ui DB, then
    restart x-ui. Best-effort: logged shape may vary by fork, so it's non-fatal."""
    folder = xui_folder or settings.xui_folder
    node.run("python3 - <<'PYEOF'\n" + _SUB_DISABLE_PY + "PYEOF\n", timeout=30)
    # NB: on the 3x-ui fork we use, `x-ui restart` returns 0 WITHOUT cycling the
    # process, so the sub server keeps :2096 open. Restart via systemd (reliable on
    # our Debian nodes), falling back to the binary only if the unit is missing.
    node.run(f"systemctl restart x-ui >/dev/null 2>&1 || {folder}/x-ui restart >/dev/null 2>&1; sleep 3; true", timeout=45)


def disable_fail2ban(node: SSHNode) -> None:
    """Disable fail2ban on a gate/exit node. Behind the gate it adds little (the
    gate is the real boundary) but risks banning the gate's or the panel's IP on a
    connection burst, which would break all users or management. Best-effort."""
    node.run("systemctl stop fail2ban 2>/dev/null; systemctl disable fail2ban 2>/dev/null; true", timeout=30)


def pin_xray_version(node: SSHNode, version: str, panel_port: int) -> str:
    """Replace the installed Xray-core with a specific release and restart x-ui.

    The installer ships the latest Xray, which doesn't connect on all clients;
    we pin every node to a known-good version (default v26.6.27). Returns the
    version string reported by the pinned binary."""
    folder = settings.xui_folder
    url = f"https://github.com/XTLS/Xray-core/releases/download/{version}/Xray-linux-64.zip"
    cmd = (
        "set -e; command -v unzip >/dev/null 2>&1 || "
        "(apt-get update >/dev/null && apt-get install -y unzip >/dev/null); "
        "cd /tmp && rm -rf xr.zip xrbin && mkdir -p xrbin && "
        f"curl -fL -o xr.zip '{url}' && unzip -o xr.zip xray -d xrbin && "
        f"install -m 0755 xrbin/xray {folder}/bin/xray-linux-amd64 && rm -rf xr.zip xrbin"
    )
    rc, out, err = node.run(cmd, timeout=240)
    if rc != 0:
        raise ProvisionError(f"Xray pin to {version} failed:\n{(err or out)[-800:]}")

    node.run("x-ui restart >/dev/null 2>&1 || systemctl restart x-ui", timeout=60)
    # wait for the panel to serve again before we create the inbound
    for _ in range(20):
        rc, code, _ = node.run(
            f"curl -s -o /dev/null -w '%{{http_code}}' -m 3 http://127.0.0.1:{panel_port}/",
            timeout=10,
        )
        if code.strip() and code.strip() != "000":
            break
        node.run("sleep 2", timeout=10)

    rc, ver, _ = node.run(f"{folder}/bin/xray-linux-amd64 -version | head -1", timeout=15)
    if version.lstrip("v") not in ver:
        raise ProvisionError(f"Xray version not pinned (got: {ver.strip()!r})")
    return ver.strip()


def _xray_x25519(node: SSHNode) -> tuple[str, str]:
    xray = f"{settings.xui_folder}/bin/xray-linux-amd64"
    rc, out, err = node.run(f"{xray} x25519", timeout=30)
    if rc != 0:
        raise ProvisionError(f"xray x25519 failed: {err or out}")
    priv = pub = ""
    for line in out.splitlines():
        low = line.lower()
        val = line.split(":", 1)[-1].strip()
        if "private" in low:
            priv = val
        elif "public" in low:
            pub = val
    if not priv or not pub:
        raise ProvisionError(f"could not parse x25519 output:\n{out}")
    return priv, pub


def _gen_short_ids() -> list[str]:
    return [secrets.token_hex(n) for n in (1, 2, 3, 4, 5, 6, 7, 8)]


def _build_inbound_payload(
    name: str, priv: str, pub: str,
    short_ids: list[str] | None = None, spider_x: str | None = None, port: int | None = None,
) -> dict:
    tpl = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
    ss = tpl["streamSettings"]
    rs = ss["realitySettings"]
    rs["privateKey"] = priv
    rs.setdefault("settings", {})["publicKey"] = pub
    rs["shortIds"] = short_ids if short_ids is not None else _gen_short_ids()
    rs["settings"]["spiderX"] = spider_x or ("/" + secrets.token_hex(8))
    # 3x-ui's add endpoint takes settings/streamSettings/sniffing as JSON strings
    return {
        "up": 0,
        "down": 0,
        "total": 0,
        "remark": name,
        "enable": True,
        "expiryTime": 0,
        "listen": "",
        "port": port or tpl.get("port", 443),
        "protocol": "vless",
        "settings": json.dumps(tpl["settings"]),
        "streamSettings": json.dumps(ss),
        "sniffing": json.dumps(tpl["sniffing"]),
    }


def create_vless_inbound(
    node: SSHNode, xui_path: str, xui_port: int, xui_token: str, name: str = "VPN",
    priv: str | None = None, pub: str | None = None,
    short_ids: list[str] | None = None, spider_x: str | None = None, port: int | None = None,
) -> int:
    """Create the VLESS inbound if none exists yet; return its inbound id.

    Standalone: Reality keys are generated on the node (`xray x25519`). For a POOL
    exit the caller passes the pool's shared Reality identity (priv/pub/shortIds/
    spiderX/port) so every member is a clone and one link works against all."""
    if not (priv and pub):
        priv, pub = _xray_x25519(node)
    payload = _build_inbound_payload(name, priv, pub, short_ids, spider_x, port)
    with node.tunnel(xui_port) as lport:
        xui = XUIClient(f"http://127.0.0.1:{lport}/{xui_path}", xui_token)
        existing = None
        try:
            existing = xui.find_vless_inbound()
        except Exception:
            existing = None
        if existing is not None:
            # On a POOL exit the inbound MUST carry the pool's Reality key. If a
            # node already has an inbound with a DIFFERENT key (e.g. re-provisioning
            # a node that was set up standalone), replace it — otherwise the clone
            # would serve the pool's client UUIDs under the wrong server key and
            # configs would fail there after a failover.
            if xui.inbound_reality_private(existing.inbound_id) == priv:
                return existing.inbound_id  # already the pool identity
            xui.del_inbound(existing.inbound_id)
        xui.add_inbound(payload)
        return xui.find_vless_inbound().inbound_id


# --------------------------------------------------------------------------
# AmneziaWG side: deploy the server ourselves (container from the official
# amneziavpn/amneziawg-go image) instead of relying on the user's app deploy.
# --------------------------------------------------------------------------
_AWG_START_SH = """#!/bin/sh
# AmneziaWG server entrypoint (generated by the panel). Mirrors what the
# AmneziaVPN-app container does: bring up awg0, then NAT the client subnet out.
sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true
awg-quick down /opt/amnezia/awg/awg0.conf 2>/dev/null || true
awg-quick up /opt/amnezia/awg/awg0.conf
iptables -A FORWARD -i awg0 -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -o awg0 -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
iptables -t nat -A POSTROUTING -s {subnet}.0/24 ! -o awg0 -j MASQUERADE 2>/dev/null || true
exec tail -f /dev/null
"""


def _put_file(node: SSHNode, path: str, content: str) -> None:
    b64 = base64.b64encode(content.encode("utf-8")).decode()
    rc, out, err = node.run(f"echo {b64} | base64 -d > {shlex.quote(path)}", timeout=30)
    if rc != 0:
        raise ProvisionError(f"could not write {path}: {(err or out)[-300:]}")


def install_docker(node: SSHNode) -> None:
    """Ensure Docker is present (the AWG server runs as a container)."""
    _rc, out, _ = node.run("command -v docker >/dev/null 2>&1 && echo yes || echo no", timeout=30)
    if out.strip().endswith("yes"):
        return
    rc, out, err = node.run("curl -fsSL https://get.docker.com | sh", timeout=600)
    if rc != 0:
        raise ProvisionError(f"docker install failed:\n{(err or out)[-1000:]}")


def install_amneziawg(
    node: SSHNode,
    listen_port: int,
    image: str | None = None,
    container: str | None = None,
    conf_dir: str | None = None,
    subnet_prefix: str | None = None,
    priv: str | None = None,
    pub: str | None = None,
    psk: str | None = None,
    params: dict | None = None,
) -> dict:
    """Deploy an AmneziaWG server as a container and bring it up.

    Standalone: keys + obfuscation params are generated panel-side per node. For a
    POOL exit the caller passes the pool's shared identity (priv/pub/psk/params)
    so every member is a clone. Writes the AmneziaVPN-app on-disk layout
    (awg0.conf + key files + clientsTable) into a host dir bind-mounted at the
    app's /opt/amnezia/awg path, and runs the container. awg.py then reads/manages
    it unchanged. Returns {container, listen_port, subnet_prefix, server_pubkey}."""
    image = image or settings.awg_image
    container = container or settings.awg_container
    conf_dir = conf_dir or settings.awg_conf_dir
    subnet_prefix = subnet_prefix or awg.DEFAULT_SERVER_SUBNET

    install_docker(node)
    rc, out, err = node.run(f"docker pull {shlex.quote(image)}", timeout=600)
    if rc != 0:
        raise ProvisionError(f"docker pull {image} failed:\n{(err or out)[-600:]}")

    if not (priv and pub):
        priv, pub = awg.gen_keypair()
    psk = psk or awg.gen_psk()
    params = params or awg.gen_obfuscation_params()
    conf_text = awg.render_server_conf(priv, listen_port, params, subnet_prefix)

    node.run(f"mkdir -p {shlex.quote(conf_dir)}", timeout=20)
    _put_file(node, f"{conf_dir}/awg0.conf", conf_text)
    _put_file(node, f"{conf_dir}/wireguard_server_private_key.key", priv + "\n")
    _put_file(node, f"{conf_dir}/wireguard_server_public_key.key", pub + "\n")
    _put_file(node, f"{conf_dir}/wireguard_psk.key", psk + "\n")
    _put_file(node, f"{conf_dir}/clientsTable", "[]")
    _put_file(node, f"{conf_dir}/start.sh", _AWG_START_SH.format(subnet=subnet_prefix))

    node.run("modprobe tun 2>/dev/null; true", timeout=20)
    node.run(f"docker rm -f {shlex.quote(container)} 2>/dev/null; true", timeout=40)
    run_cmd = (
        f"docker run -d --name {shlex.quote(container)} --restart always "
        f"--cap-add NET_ADMIN --cap-add SYS_MODULE --device /dev/net/tun "
        f"--sysctl net.ipv4.ip_forward=1 --sysctl net.ipv4.conf.all.src_valid_mark=1 "
        f"-v {shlex.quote(conf_dir)}:/opt/amnezia/awg -v /lib/modules:/lib/modules "
        f"-p {listen_port}:{listen_port}/udp "
        f"{shlex.quote(image)} /bin/sh /opt/amnezia/awg/start.sh"
    )
    rc, out, err = node.run(run_cmd, timeout=120)
    if rc != 0:
        raise ProvisionError(f"docker run (awg) failed:\n{(err or out)[-600:]}")

    for _ in range(15):  # wait for awg0 to come up
        _rc, out, _ = node.run(
            f"docker exec {shlex.quote(container)} awg show awg0 2>/dev/null | head -1", timeout=15
        )
        if "interface" in out.lower():
            break
        node.run("sleep 2", timeout=10)
    else:
        _rc, logs, _ = node.run(f"docker logs {shlex.quote(container)} 2>&1 | tail -n 20", timeout=20)
        raise ProvisionError(f"AmneziaWG interface did not come up:\n{logs[-800:]}")

    return {
        "container": container,
        "listen_port": listen_port,
        "subnet_prefix": subnet_prefix,
        "server_pubkey": pub,
    }


# --------------------------------------------------------------------------
# Gate relay: turn a node into a transparent L4 forwarder to an exit POOL. The
# gate never decrypts — it DNATs the service ports straight through to a healthy
# pool member, so client → gate:PORT → exit:PORT → internet (the client's
# VLESS/AWG obfuscation rides along unchanged). A tiny daemon health-checks the
# pool and keeps the nftables map pointed only at live members, so a dead/banned
# exit auto-fails-over with no client reconfiguration.
# --------------------------------------------------------------------------
_RELAY_DAEMON = r'''#!/usr/bin/env python3
"""VesPN gate relay daemon. Reads the pool member list (in priority order) the
panel pushes to /etc/vespn-relay/members.json, TCP-probes each exit's VLESS port
with hysteresis, and rewrites our own nftables table so DNAT points at the single
highest-priority HEALTHY member (active/standby: all traffic to the preferred
exit, failing down to the next only when it dies). The gate forwards ciphertext
only; it never decrypts."""
import json, os, socket, subprocess, sys, time

CONF = "/etc/vespn-relay/members.json"
NFT_FILE = "/run/vespn-relay.nft"
UP, DOWN = 2, 2  # consecutive probes needed to flip a member up/down


def load():
    try:
        with open(CONF) as f:
            return json.load(f)
    except Exception:
        return {}


def tcp_ok(ip, port, timeout=2.0):
    try:
        s = socket.create_connection((ip, int(port)), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def build_nft(exits, tcp_ports, udp_ports):
    lines = [
        "add table ip vespn_relay",
        "flush table ip vespn_relay",
        "add chain ip vespn_relay pre { type nat hook prerouting priority dstnat; policy accept; }",
        "add chain ip vespn_relay post { type nat hook postrouting priority srcnat; policy accept; }",
    ]
    k = len(exits)

    def dnat(proto, port):
        if k == 1:
            return "add rule ip vespn_relay pre %s dport %d dnat to %s" % (proto, port, exits[0])
        mp = ", ".join("%d : %s" % (i, e) for i, e in enumerate(exits))
        return ("add rule ip vespn_relay pre %s dport %d dnat to jhash ip saddr mod %d map { %s }"
                % (proto, port, k, mp))

    if k:
        for p in tcp_ports:
            lines.append(dnat("tcp", int(p)))
        for p in udp_ports:
            lines.append(dnat("udp", int(p)))
        lines.append("add rule ip vespn_relay post ip daddr { %s } masquerade" % ", ".join(exits))
    return "\n".join(lines) + "\n"


def apply_nft(text):
    with open(NFT_FILE, "w") as f:
        f.write(text)
    subprocess.run(["nft", "-f", NFT_FILE], check=False)


def main():
    state = {}
    last_active = None
    while True:
        cfg = load()
        exits = list(cfg.get("exits", []))  # already in priority order (lower index = preferred)
        tcp_ports = cfg.get("tcp_ports", [])
        udp_ports = cfg.get("udp_ports", [])
        probe = int(cfg.get("probe_port") or (tcp_ports[0] if tcp_ports else 0) or 22)
        interval = int(cfg.get("interval", 5))
        for ip in exits:
            st = state.setdefault(ip, {"up": False, "s": 0, "f": 0})
            if tcp_ok(ip, probe):
                st["s"] += 1; st["f"] = 0
                if not st["up"] and st["s"] >= UP:
                    st["up"] = True
            else:
                st["f"] += 1; st["s"] = 0
                if st["up"] and st["f"] >= DOWN:
                    st["up"] = False
        for ip in list(state):
            if ip not in exits:
                del state[ip]
        healthy = [ip for ip in exits if state.get(ip, {}).get("up")]
        # Active/standby: route ALL traffic to the highest-priority healthy member
        # (first in the list). Fall down to the next only when it goes down.
        active = healthy[:1]
        if active != last_active:
            apply_nft(build_nft(active, tcp_ports, udp_ports))
            last_active = active
            sys.stderr.write("vespn-relay: active=%r (healthy=%r)\n" % (active, healthy))
            sys.stderr.flush()
        time.sleep(interval)


if __name__ == "__main__":
    main()
'''

_RELAY_SERVICE = """[Unit]
Description=VesPN gate relay daemon (health-checked nftables DNAT to the exit pool)
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


def _relay_members(exits, tcp_ports, udp_ports, probe_port=None, interval=5) -> dict:
    exits = [str(e) for e in exits]
    tcp_ports = [int(p) for p in tcp_ports]
    udp_ports = [int(p) for p in udp_ports]
    return {
        "exits": exits,
        "tcp_ports": tcp_ports,
        "udp_ports": udp_ports,
        "probe_port": int(probe_port) if probe_port else (tcp_ports[0] if tcp_ports else 0),
        "interval": int(interval),
    }


def push_gate_members(node: SSHNode, exits, tcp_ports, udp_ports, probe_port=None, interval=5) -> dict:
    """Update ONLY the member list on an already-set-up gate; the daemon picks it
    up on its next cycle (used when the pool's membership/health changes)."""
    members = _relay_members(exits, tcp_ports, udp_ports, probe_port, interval)
    node.run("mkdir -p /etc/vespn-relay", timeout=20)
    _put_file(node, "/etc/vespn-relay/members.json", json.dumps(members, indent=2) + "\n")
    return members


def install_telegram_proxy(node: SSHNode, hostname: str, upstream: str = "https://api.telegram.org",
                           container: str = "vespn-tgproxy") -> dict:
    """Run a Caddy reverse proxy (official docker image) on a node so the RU-based
    Hub can reach Telegram through it. `hostname` is a public DNS name pointing at
    this node (e.g. a DuckDNS subdomain) — Caddy auto-obtains a Let's Encrypt cert
    for it and forwards to api.telegram.org. Needs :80 + :443 free on the node.
    The bot then uses https://<hostname> as its API base."""
    install_docker(node)
    rc, out, err = node.run("docker pull caddy:2", timeout=600)
    if rc != 0:
        raise ProvisionError(f"docker pull caddy failed:\n{(err or out)[-400:]}")
    node.run(f"docker rm -f {shlex.quote(container)} 2>/dev/null; true", timeout=30)
    run_cmd = (
        f"docker run -d --name {shlex.quote(container)} --restart always "
        f"-p 80:80 -p 443:443 -v vespn_caddy_data:/data -v vespn_caddy_cfg:/config "
        f"caddy:2 caddy reverse-proxy --from {shlex.quote(hostname)} "
        f"--to {shlex.quote(upstream)} --change-host-header"
    )
    rc, out, err = node.run(run_cmd, timeout=120)
    if rc != 0:
        raise ProvisionError(f"docker run (tgproxy) failed:\n{(err or out)[-500:]}")
    node.run("sleep 3", timeout=10)
    _rc, st, _ = node.run(f"docker ps --filter name={shlex.quote(container)} --format '{{{{.Status}}}}'", timeout=15)
    return {"container": container, "hostname": hostname, "status": st.strip()}


def install_gate_relay(node: SSHNode, exits, tcp_ports, udp_ports, probe_port=None, interval=5) -> dict:
    """Set `node` up as a health-checked L4 relay to the exit pool: install the
    daemon + systemd unit, push the member list, enable ip_forward. Idempotent —
    re-running just refreshes the files and restarts the daemon."""
    members = _relay_members(exits, tcp_ports, udp_ports, probe_port, interval)
    if not members["tcp_ports"] and not members["udp_ports"]:
        raise ProvisionError("no ports to relay")

    node.run(
        "command -v nft >/dev/null 2>&1 || (apt-get update && apt-get install -y nftables) >/dev/null 2>&1; "
        "command -v python3 >/dev/null 2>&1 || (apt-get update && apt-get install -y python3) >/dev/null 2>&1; true",
        timeout=300,
    )
    disable_fail2ban(node)  # must never ban the exits it relays to or the panel
    _put_file(node, "/etc/sysctl.d/99-vespn-relay.conf", "net.ipv4.ip_forward=1\n")
    node.run("sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1", timeout=20)
    node.run("mkdir -p /etc/vespn-relay", timeout=20)
    _put_file(node, "/etc/vespn-relay/members.json", json.dumps(members, indent=2) + "\n")
    _put_file(node, "/usr/local/bin/vespn-relay-daemon.py", _RELAY_DAEMON)
    _put_file(node, "/etc/systemd/system/vespn-relay.service", _RELAY_SERVICE)
    rc, out, err = node.run(
        "chmod +x /usr/local/bin/vespn-relay-daemon.py && systemctl daemon-reload && "
        "systemctl enable vespn-relay.service >/dev/null 2>&1 && "
        "systemctl restart vespn-relay.service 2>&1",
        timeout=60,
    )
    if rc != 0:
        raise ProvisionError(f"relay daemon setup failed:\n{(err or out)[-700:]}")
    node.run("sleep 3", timeout=10)
    _rc, status, _ = node.run("systemctl is-active vespn-relay.service 2>&1", timeout=15)
    _rc, rules, _ = node.run("nft list table ip vespn_relay 2>&1", timeout=20)
    return {
        "exits": members["exits"], "tcp": members["tcp_ports"], "udp": members["udp_ports"],
        "daemon": status.strip(), "rules": rules.strip(),
    }
