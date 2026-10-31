"""Service layer: operations on a node, and DB-aware config issuance.

All node access goes over SSH using the node's stored (decrypted) credentials.
"""

from __future__ import annotations

import logging
import re
import secrets
from contextlib import contextmanager

from sqlalchemy.orm import Session, object_session

log = logging.getLogger("vpnpanel.nodes")

# 3x-ui builds the share link's host from the API request Host header, which is
# the SSH tunnel (127.0.0.1) — so force the node's real public host into it.
_VLESS_HOST_RE = re.compile(r"^(vless://[^@]+@)([^:/?#]+)(:\d+)?(.*)$", re.S)


def _rewrite_vless_host(link: str, host: str) -> str:
    m = _VLESS_HOST_RE.match(link)
    if not m:
        return link
    pre, _old, port, rest = m.groups()
    return f"{pre}{host}{port or ''}{rest}"

from . import provisioning
from .awg import AWGManager
from .models import PROTO_AWG, PROTO_VLESS, ROLE_EXIT, ROLE_GATE, Device, IssuedConfig, Node, Route
from .node_ssh import NodeCredentials, SSHNode
from .xui import XUIClient


class NodeOpError(RuntimeError):
    pass


def _creds(node: Node) -> NodeCredentials:
    return NodeCredentials(
        host=node.ssh_host,
        port=node.ssh_port,
        username=node.ssh_username,
        password=node.ssh_password,
    )


def _gate_creds_for(node: Node) -> NodeCredentials | None:
    """SSH jump host for reaching a pooled exit: its pool's gate. RU DPI drops the
    direct Hub→exit handshake for flagged ranges, but the gate reaches the exit, so
    the panel tunnels its management SSH through the gate (the gate only forwards
    ciphertext, never authenticates to the exit). Returns None for gates, non-pooled
    nodes, or when no gate is resolvable (then we connect directly)."""
    try:
        if node.role != ROLE_EXIT or node.pool_id is None:
            return None
        sess = object_session(node)
        if sess is None:
            return None
        route = (
            sess.query(Route)
            .filter(Route.pool_id == node.pool_id, Route.gate_id.isnot(None))
            .order_by(Route.is_default.desc(), Route.id)
            .first()
        )
        gate = route.gate_node if route else None
        if gate is None:
            # Exit provisioned before its route exists (first-time self-service): if
            # exactly one gate node is registered, front through it. With several we
            # can't guess — a route must then say which gate fronts this pool.
            gates = sess.query(Node).filter(Node.role == ROLE_GATE).all()
            if len(gates) == 1:
                gate = gates[0]
        if gate is None or gate.id == node.id:
            return None
        return NodeCredentials(
            host=gate.ssh_host, port=gate.ssh_port,
            username=gate.ssh_username, password=gate.ssh_password,
        )
    except Exception:
        return None


@contextmanager
def connect(node: Node):
    """SSH to a node. For a pooled exit, tunnel through its gate (ProxyJump); fall
    back to a direct connection if the gate path can't be established."""
    jump = _gate_creds_for(node)
    try:
        n = SSHNode(_creds(node), jump=jump).connect()
    except Exception:
        if jump is None:
            raise
        log.warning("gate-jump SSH to %s failed; trying direct", node.name)
        n = SSHNode(_creds(node)).connect()
    try:
        yield n
    finally:
        n.close()


# --- diagnostics --------------------------------------------------------
def test_node(node: Node) -> dict:
    """Probe SSH, the AmneziaWG container, and the 3x-ui API. Never raises."""
    result = {"ssh": False, "awg": False, "xui": False, "detail": ""}
    try:
        with connect(node) as n:
            rc, out, _ = n.run("echo ok")
            result["ssh"] = rc == 0 and out.strip() == "ok"
            rc, dps, _ = n.run("docker ps --format '{{.Names}} {{.Image}}'")
            if rc == 0:
                result["awg"] = any(
                    ("awg" in l.lower() or "amnezia" in l.lower()) for l in dps.splitlines() if l.strip()
                )
            if node.has_xui:
                with n.tunnel(node.xui_port) as lport:
                    xui = XUIClient(f"http://127.0.0.1:{lport}/{node.xui_path}", node.xui_token)
                    ib = xui.find_vless_inbound()
                    result["xui"] = True
                    result["detail"] = f"vless inbound id={ib.inbound_id}"
    except Exception as e:  # diagnostics must always return something
        result["detail"] = f"{type(e).__name__}: {e}"
    return result


# --- DB-aware orchestration (delegates to the pool layer) ---------------
# These keep the names main.py imports (node_ops.*) but Model A routes a device
# through a gate + an exit POOL, so the real work lives in `pool`. Imported
# lazily because `pool` imports helpers from this module.
def get_or_issue_config(db: Session, device: Device) -> IssuedConfig:
    """Return the device's pool-wide config, creating it if needed."""
    from . import pool

    return pool.issue_for_device(db, device)


def deprovision_device(db: Session, device: Device) -> None:
    """Remove the device's clients/peers from every member of its pool(s)."""
    from . import pool

    pool.deprovision_device(db, device)


def _pick_awg_port() -> int:
    """A fresh high UDP port for the AmneziaWG server. We avoid 443/80 and the
    'round' well-known ports that RU DPI tends to target, per the node-ban
    lesson, and stay below the ephemeral range to dodge source-port clashes."""
    return 20000 + secrets.randbelow(25000)  # 20000..44999


def provision_node(db: Session, node: Node) -> dict:
    """Stand up a fresh node end to end: install 3x-ui + the VLESS inbound, and
    deploy the AmneziaWG server (container). Persist the discovered params."""
    from .config import settings

    awg_port = _pick_awg_port()  # fresh random port per node (ban lesson)
    with connect(node) as n:
        provisioning.ensure_base(n)  # fresh Debian lacks curl, which the installers need
        info = provisioning.install_3xui(n)
        provisioning.set_panel_localhost(n)  # panel reachable only via SSH tunnel
        provisioning.pin_xray_version(n, settings.xray_version, info["xui_port"])
        provisioning.create_vless_inbound(
            n, info["xui_path"], info["xui_port"], info["xui_token"], name=node.name
        )
        awg_info = provisioning.install_amneziawg(n, listen_port=awg_port)
        provisioning.harden_subscription(n)  # no public :2096 sub server
        provisioning.disable_fail2ban(n)      # never ban the gate/panel
    node.xui_path = info["xui_path"]
    node.xui_port = info["xui_port"]
    node.xui_token = info["xui_token"]  # encrypted via setter
    node.awg_port = awg_port
    if not node.awg_endpoint_host:
        node.awg_endpoint_host = node.public_host
    db.commit()
    return {**info, "awg_port": awg_port, "awg": awg_info}


def provision_gate_for_route(db: Session, route) -> dict:
    """Set the route's gate up as a health-checked L4 relay to its exit pool."""
    from . import pool

    return pool.provision_gate_for_route(db, route)
