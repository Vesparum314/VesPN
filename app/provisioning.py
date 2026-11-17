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


def install_fleet_key(node: SSHNode, public_line: str) -> None:
    """Append the panel's fleet public key to the node's root authorized_keys
    (idempotent). After this, the panel manages the node by key (no Hub→node
    password needed). Called first in every provisioning flow, right after the
    initial — possibly password-based — connect. A no-op if no key is given."""
    public_line = (public_line or "").strip()
    if not public_line:
        return
    q = shlex.quote(public_line)
    node.run("install -d -m 700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys", timeout=20)
    node.run(f"grep -qxF {q} ~/.ssh/authorized_keys || echo {q} >> ~/.ssh/authorized_keys", timeout=20)


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
    we pin every node to a known-good version (default v26.11.9). Returns the
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


TG_PROXY_PORT = 8666  # localhost-only Telegram reverse-proxy port on each exit


def install_telegram_proxy(node: SSHNode, port: int = TG_PROXY_PORT,
                           upstream: str = "https://api.telegram.org",
                           container: str = "vespn-tgproxy") -> dict:
    """Run a Caddy reverse-proxy on the exit bound to 127.0.0.1:<port> → Telegram.
    The panel reaches it ONLY over the gate SSH tunnel (Hub→gate→exit), so there is
    no public endpoint, no DNS and no TLS cert to manage — SSH already secures the
    hop, and Caddy originates TLS to api.telegram.org. This is what lets the RU-based
    Hub reach Telegram through ANY exit (bot picks one by priority). Idempotent."""
    install_docker(node)
    rc, out, err = node.run("docker pull caddy:2", timeout=600)
    if rc != 0:
        raise ProvisionError(f"docker pull caddy failed:\n{(err or out)[-400:]}")
    node.run(f"docker rm -f {shlex.quote(container)} 2>/dev/null; true", timeout=30)
    run_cmd = (
        f"docker run -d --name {shlex.quote(container)} --restart always "
        f"-p 127.0.0.1:{int(port)}:{int(port)} "
        f"caddy:2 caddy reverse-proxy --from http://:{int(port)} "
        f"--to {shlex.quote(upstream)} --change-host-header"
    )
    rc, out, err = node.run(run_cmd, timeout=120)
    if rc != 0:
        raise ProvisionError(f"docker run (tgproxy) failed:\n{(err or out)[-500:]}")
    node.run("sleep 3", timeout=10)
    _rc, st, _ = node.run(f"docker ps --filter name={shlex.quote(container)} --format '{{{{.Status}}}}'", timeout=15)
    return {"container": container, "port": int(port), "status": st.strip()}
