"""Exit pools (Model A): a set of cryptographically-cloned exit nodes behind a
gate, with health-checked L4 failover.

Every exit in a pool shares ONE identity — the same VLESS Reality keys / shortIds
/ spiderX / port and the same AmneziaWG server key / PSK / obfuscation params /
port — plus the same client+peer tables (kept in step by `reconcile_exit`). A
client config therefore authenticates against ANY member, so the gate can fail
over or balance across the pool without the client ever reconfiguring. The pool
is the source of truth: `desired_state` is derived from the issued configs, and
each exit is converged to it.

The gate never decrypts: it only DNATs ciphertext to a healthy member (see
`provisioning.install_gate_relay` + its daemon). Public IPs differ between
members and are invisible to the client — it always dials the gate.
"""

from __future__ import annotations

import base64
import logging
import re
import secrets
import uuid as _uuid
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from sqlalchemy.orm import Session

from . import awg, fleetkey, provisioning
from .awg import AWGManager
from .config import settings
from .models import (
    PROTO_AWG,
    PROTO_VLESS,
    ROLE_EXIT,
    SYNC_SYNCED,
    SYNC_UNREACHABLE,
    Device,
    ExitPool,
    IssuedConfig,
    Node,
    Route,
    slugify,
)
from .nodes import NodeOpError, _gate_creds_for, _rewrite_vless_host, _set_vless_label, connect
from .xui import XUIClient

log = logging.getLogger("vpnpanel.pool")

DEFAULT_VLESS_PORT = 17771
DEFAULT_AWG_PORT = 17772


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _link_uuid(payload: str) -> str | None:
    """The client UUID inside a stored vless:// link (what the user actually has)."""
    m = re.search(r"vless://([^@]+)@", payload or "")
    return m.group(1) if m else None


def accessible_routes(db: Session, user) -> list[Route]:
    """Routes the user may make configs on. Staff (admin/operator) see EVERY enabled
    route; a client only enabled routes sharing >=1 access group (a route with no
    groups is accessible to no client)."""
    enabled = db.query(Route).filter_by(enabled=True).order_by(Route.name).all()
    if user.is_staff:
        return enabled
    gids = user.group_ids
    if not gids:
        return []
    return [r for r in enabled if gids & {g.id for g in r.groups}]


# --- identity -----------------------------------------------------------
def _gen_reality_keypair() -> tuple[str, str]:
    """An X25519 keypair for VLESS Reality, base64url without padding — the exact
    encoding `xray x25519` emits and the inbound config expects. Generated panel-
    side so every pool member can be configured with the SAME Reality identity."""
    raw = bytearray(secrets.token_bytes(32))
    raw[0] &= 248
    raw[31] &= 127
    raw[31] |= 64
    priv = X25519PrivateKey.from_private_bytes(bytes(raw))
    priv_b = priv.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    pub_b = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    def b64u(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    return b64u(priv_b), b64u(pub_b)


def create_pool(
    db: Session, name: str, vless_port: int = DEFAULT_VLESS_PORT, awg_port: int = DEFAULT_AWG_PORT
) -> ExitPool:
    """Generate a fresh pool identity (Reality + AmneziaWG) and persist it."""
    rpriv, rpub = _gen_reality_keypair()
    apriv, apub = awg.gen_keypair()
    pool = ExitPool(
        name=name.strip(),
        vless_port=vless_port,
        awg_port=awg_port,
        reality_public=rpub,
        awg_public=apub,
        awg_subnet=awg.DEFAULT_SERVER_SUBNET,
        spider_x="/" + secrets.token_hex(8),
    )
    pool.reality_private = rpriv
    pool.awg_private = apriv
    pool.awg_psk = awg.gen_psk()
    pool.short_ids = [secrets.token_hex(n) for n in (1, 2, 3, 4, 5, 6, 7, 8)]
    pool.awg_params = awg.gen_obfuscation_params()
    db.add(pool)
    db.commit()
    db.refresh(pool)
    return pool


# --- desired state ------------------------------------------------------
def _pool_configs(db: Session, pool: ExitPool, protocol: str) -> list[IssuedConfig]:
    return (
        db.query(IssuedConfig)
        .filter(IssuedConfig.pool_id == pool.id, IssuedConfig.protocol == protocol)
        .all()
    )


def _config_name(cfg: IssuedConfig) -> str:
    dev = cfg.device
    try:
        return dev.node_identifier() if dev else cfg.identifier[:8]
    except Exception:
        return cfg.identifier[:8]


# --- provisioning a pool exit (clone) -----------------------------------
def provision_pool_exit(db: Session, node: Node) -> dict:
    """Stand a node up as a CLONE in its pool: install 3x-ui + the VLESS inbound
    and the AmneziaWG server, all with the pool's shared identity, then converge
    it to the pool's current clients."""
    if node.pool_id is None:
        raise NodeOpError("нода не привязана к пулу")
    pool = db.get(ExitPool, node.pool_id)
    if pool is None:
        raise NodeOpError("пул не найден")
    # Model A: a pooled exit is always managed THROUGH its gate (RU DPI drops the
    # direct Hub→exit handshake). Require a resolvable gate before we start, so
    # rollout never silently depends on a direct connection that dies on DPI.
    if _gate_creds_for(node) is None:
        raise NodeOpError(
            "у пула нет гейта: заведите gate-ноду и маршрут (пул→гейт) до раскатки выхода"
        )

    with connect(node) as n:
        provisioning.install_fleet_key(n, fleetkey.public_line(db))  # key-manage from here on
        provisioning.ensure_base(n)  # fresh Debian lacks curl, which the installers need
        info = provisioning.install_3xui(n)
        provisioning.set_panel_localhost(n)
        provisioning.pin_xray_version(n, settings.xray_version, info["xui_port"])
        provisioning.create_vless_inbound(
            n, info["xui_path"], info["xui_port"], info["xui_token"], name=node.name,
            priv=pool.reality_private, pub=pool.reality_public,
            short_ids=pool.short_ids, spider_x=pool.spider_x, port=pool.vless_port,
        )
        awg_info = provisioning.install_amneziawg(
            n, listen_port=pool.awg_port,
            priv=pool.awg_private, pub=pool.awg_public, psk=pool.awg_psk,
            params=pool.awg_params, subnet_prefix=pool.awg_subnet,
        )
        provisioning.harden_subscription(n)  # no public :2096 sub server
        provisioning.disable_fail2ban(n)      # never ban the gate/panel
        try:
            provisioning.install_telegram_proxy(n)  # localhost TG proxy; bot reaches it via gate
        except Exception as e:
            log.warning("tg-proxy install on %s skipped: %s", node.name, e)

    node.xui_path = info["xui_path"]
    node.xui_port = info["xui_port"]
    node.xui_token = info["xui_token"]  # encrypted via setter
    node.awg_port = pool.awg_port
    node.key_installed = True  # fleet key now in authorized_keys → key-managed
    if not node.awg_endpoint_host:
        node.awg_endpoint_host = node.public_host
    db.commit()

    rec = reconcile_exit(db, pool, node)
    return {"xui_port": info["xui_port"], "awg_port": pool.awg_port, "awg": awg_info, "reconcile": rec}


# --- reconcile ----------------------------------------------------------
def reconcile_exit(db: Session, pool: ExitPool, node: Node) -> dict:
    """Converge one exit to the pool's desired client/peer set (idempotent).
    Adds missing clients/peers and removes extras, then records sync state."""
    added_v = removed_v = added_a = removed_a = 0
    try:
        with connect(node) as n:
            # --- VLESS ---
            if node.has_xui:
                with n.tunnel(node.xui_port) as lport:
                    xui = XUIClient(f"http://127.0.0.1:{lport}/{node.xui_path}", node.xui_token)
                    inbound = xui.find_vless_inbound()
                    desired = _pool_configs(db, pool, PROTO_VLESS)
                    desired_emails = {c.identifier for c in desired}
                    # Robust check: don't trust list_client_emails() for "present"
                    # (orphaned clients from an inbound recreate still appear there
                    # but serve no link). Verify each desired config resolves to a
                    # link carrying the SAME uuid the user has; otherwise rebuild it.
                    for c in desired:
                        want = _link_uuid(c.payload) or c.uuid
                        if not want:
                            continue
                        try:
                            ls = xui.get_client_links(c.identifier)
                            have = _link_uuid(ls[0]) if ls else None
                        except Exception:
                            have = None
                        if have != want:
                            try:
                                xui.del_client(c.identifier)
                            except Exception:
                                pass
                            xui.add_client(
                                c.identifier, [inbound.inbound_id],
                                client_id=want, sub_id=(c.sub_id or None),
                            )
                            added_v += 1
                    for email in (xui.list_client_emails() - desired_emails):
                        xui.del_client(email)
                        removed_v += 1
            # --- AmneziaWG ---
            mgr = AWGManager(n)
            mgr.discover_container()
            desired_a = _pool_configs(db, pool, PROTO_AWG)
            desired_pubs = {c.identifier for c in desired_a}
            current_pubs = {pub for pub, _ in mgr.list_peers()}
            for c in desired_a:
                if c.identifier not in current_pubs:
                    mgr.upsert_peer(c.identifier, c.address, name=_config_name(c))
                    added_a += 1
            for pub in current_pubs - desired_pubs:
                mgr.del_peer(pub)
                removed_a += 1
    except Exception as e:
        node.sync_state = SYNC_UNREACHABLE
        node.last_reconcile_at = _now()
        db.commit()
        log.warning("reconcile of %s failed: %s", node.name, e)
        return {"node": node.name, "ok": False, "error": str(e)}

    node.sync_state = SYNC_SYNCED
    node.last_reconcile_at = _now()
    db.commit()
    return {
        "node": node.name, "ok": True,
        "vless_added": added_v, "vless_removed": removed_v,
        "awg_added": added_a, "awg_removed": removed_a,
    }


def reconcile_pool(db: Session, pool: ExitPool) -> list[dict]:
    """Reconcile every member of the pool; never raises."""
    return [reconcile_exit(db, pool, m) for m in pool.members]


# --- issuance -----------------------------------------------------------
def _alloc_awg_address(db: Session, pool: ExitPool) -> str:
    """Next free 10.8.1.x inside the POOL (server is .0, clients .1+)."""
    used: set[int] = set()
    for c in _pool_configs(db, pool, PROTO_AWG):
        parts = c.address.split("/")[0].split(".")
        if len(parts) == 4 and parts[3].isdigit():
            used.add(int(parts[3]))
    for h in range(1, 255):
        if h not in used:
            return f"{pool.awg_subnet}.{h}"
    raise NodeOpError("адресный пул AmneziaWG исчерпан")


def _vless_add_and_link(node: Node, email: str, cid: str, sub: str, host: str) -> str:
    with connect(node) as n, n.tunnel(node.xui_port) as lport:
        xui = XUIClient(f"http://127.0.0.1:{lport}/{node.xui_path}", node.xui_token)
        inbound = xui.find_vless_inbound()
        if not xui.client_exists(email):
            xui.add_client(email, [inbound.inbound_id], client_id=cid, sub_id=sub)
        links = xui.get_client_links(email)
        if not links:
            raise NodeOpError(f"no link returned for {email!r}")
        return _rewrite_vless_host(links[0], host)


def _vless_add(node: Node, email: str, cid: str, sub: str) -> None:
    with connect(node) as n, n.tunnel(node.xui_port) as lport:
        xui = XUIClient(f"http://127.0.0.1:{lport}/{node.xui_path}", node.xui_token)
        inbound = xui.find_vless_inbound()
        if not xui.client_exists(email):
            xui.add_client(email, [inbound.inbound_id], client_id=cid, sub_id=sub)


def issue_for_device(db: Session, device: Device) -> IssuedConfig:
    """Issue (or return existing) the device's pool-wide config.

    VLESS: generate the client's uuid/subId panel-side and force them onto every
    ready member (identical link everywhere); the link is fetched from the first
    member that answers. AmneziaWG: generate the peer locally, build the vpn://
    from the POOL identity (no live node needed), and push the peer to all members."""
    # The client picks the route; honour exactly what the device is pinned to and
    # re-check access at issue time (so a revoked group stops working). No fallback.
    route = device.route
    if route is None or not route.enabled:
        raise NodeOpError("маршрут устройства не выбран или отключён — выберите доступный маршрут")
    if not route.allows(device.user):
        raise NodeOpError("этот маршрут вам недоступен — выберите другой")
    pool = route.pool
    gate = route.gate_node
    if pool is None:
        raise NodeOpError("у маршрута нет пула выходов")
    if gate is None:
        raise NodeOpError("у маршрута нет гейта")
    host = route.host  # the gate

    existing = db.query(IssuedConfig).filter_by(device_id=device.id).one_or_none()

    # members that can serve now: synced first, else any that has 3x-ui.
    ready = pool.synced_exits or [m for m in pool.members if m.has_xui]

    if device.protocol == PROTO_VLESS:
        if not ready:
            raise NodeOpError("в пуле нет готовых выходов")
        email = device.node_identifier()
        if existing and existing.uuid:
            cid, sub = existing.uuid, existing.sub_id
        else:
            cid, sub = str(_uuid.uuid4()), secrets.token_hex(8)

        link = None
        used_node = None
        last_err: Exception | None = None
        for m in ready:
            try:
                if link is None:
                    link = _vless_add_and_link(m, email, cid, sub, host)
                    used_node = m
                else:
                    _vless_add(m, email, cid, sub)
            except Exception as e:  # a down member mustn't block issuance
                last_err = e
                log.warning("vless fan-out to %s failed: %s", m.name, e)
        if link is None:
            raise NodeOpError(f"не удалось выпустить VLESS: {last_err}")

        # Label the link by ROUTE + full identifier (route-user-device), not the
        # exit node's name that 3x-ui bakes in — stays meaningful after failover.
        link = _set_vless_label(link, f"{slugify(route.name)}-{email}")

        if existing is None:
            existing = IssuedConfig(device_id=device.id, protocol=PROTO_VLESS)
            db.add(existing)
        existing.pool_id = pool.id
        existing.node_id = used_node.id if used_node else None
        existing.route_id = route.id
        existing.identifier = email
        existing.uuid = cid
        existing.sub_id = sub
        existing.payload = link
        db.commit()
        db.refresh(existing)
        return existing

    elif device.protocol == PROTO_AWG:
        if existing:
            return existing  # keep stored vpn:// (holds the client private key)
        address = _alloc_awg_address(db, pool)
        priv, pub = awg.gen_keypair()
        server = awg.server_from_identity(
            pool.awg_public, pool.awg_psk, pool.awg_port, pool.awg_params, pool.awg_subnet
        )
        email = device.node_identifier()
        doc = awg.build_amnezia_dict(server, priv, pub, address, host, email)
        vpn = awg.encode_vpn(doc)

        pushed = 0
        for m in pool.members:
            try:
                with connect(m) as n:
                    mgr = AWGManager(n)
                    mgr.discover_container()
                    mgr.upsert_peer(pub, address, name=email)
                    pushed += 1
            except Exception as e:
                log.warning("awg fan-out to %s failed: %s", m.name, e)
        if pushed == 0 and pool.members:
            raise NodeOpError("не удалось добавить пир ни на один выход пула")

        existing = IssuedConfig(
            device_id=device.id, pool_id=pool.id, node_id=None, route_id=route.id,
            protocol=PROTO_AWG, identifier=pub, address=address, payload=vpn,
        )
        db.add(existing)
        db.commit()
        db.refresh(existing)
        return existing

    raise NodeOpError(f"unknown protocol {device.protocol!r}")


def deprovision_device(db: Session, device: Device) -> None:
    """Remove the device's clients/peers from every member of its pool(s).
    Never raises — a dead exit just can't be cleaned, which is fine."""
    for cfg in list(device.configs):
        pool = db.get(ExitPool, cfg.pool_id) if cfg.pool_id else None
        if pool is None:
            continue
        for m in pool.members:
            try:
                if cfg.protocol == PROTO_VLESS:
                    if not m.has_xui:
                        continue
                    with connect(m) as n, n.tunnel(m.xui_port) as lport:
                        XUIClient(f"http://127.0.0.1:{lport}/{m.xui_path}", m.xui_token).del_client(
                            cfg.identifier
                        )
                else:
                    with connect(m) as n:
                        mgr = AWGManager(n)
                        mgr.discover_container()
                        mgr.del_peer(cfg.identifier)
            except Exception as e:
                log.warning("deprovision of %s on %s failed: %s", cfg.identifier, m.name, e)


# --- gate relay for a pool route ---------------------------------------
def provision_gate_for_route(db: Session, route: Route) -> dict:
    """Set the route's gate up as a health-checked L4 relay to its pool: push the
    member IPs + the pool's service ports, deploy the daemon. The daemon then
    steers DNAT to live members only."""
    gate = route.gate_node
    pool = route.pool
    if gate is None or not gate.is_gate:
        raise NodeOpError("у маршрута нет gate-сервера")
    if pool is None:
        raise NodeOpError("у маршрута нет пула выходов")
    # Priority order (lower = preferred): the gate daemon routes to the first
    # healthy member in this list, so the order IS the active/standby priority.
    members = sorted(pool.members, key=lambda m: (m.priority, m.id))
    exits = [m.public_host for m in members]
    if not exits:
        raise NodeOpError("в пуле нет выходов")
    with connect(gate) as g:
        provisioning.install_fleet_key(g, fleetkey.public_line(db))  # key-manage from here on
        info = provisioning.install_gate_relay(
            g, exits, [pool.vless_port], [pool.awg_port], probe_port=pool.vless_port
        )
    if not gate.key_installed:
        gate.key_installed = True
        db.commit()
    return {"pool": pool.name, "exits": exits, **info}
