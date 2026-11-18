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
`relay.py` + its daemon). Public IPs differ between
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
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import awg, fleetkey, provisioning
from .awg import AWGManager
from .config import settings
from .models import (
    PROTO_AWG,
    PROTO_NAIVE,
    PROTO_VLESS,
    ROLE_EXIT,
    SYNC_SYNCED,
    SYNC_UNREACHABLE,
    VLESS_XHTTP,
    Device,
    ExitPool,
    IssuedConfig,
    Node,
    Route,
    slugify,
)
from .nodes import (
    NodeOpError,
    _exit_needs_gate,
    _gate_creds_for,
    connect,
)
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
    """Generate a fresh pool identity (Reality + AmneziaWG) and persist it. Which
    protocols the servers actually run follows from the routes on the pool."""
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
        vless_transport=VLESS_XHTTP,
        xhttp_path="/" + secrets.token_hex(6),
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


# VLESS and NaiveProxy clients are accounts (uuid / login+password) that can live
# on several pools at once, so a device's subscription can list every route of its
# protocol its owner may use. (AmneziaWG peers are per pool: address + key.)
def user_proto_routes(db: Session, user, proto: str) -> list[Route]:
    """Enabled routes of `proto` the user may use — what their devices'
    subscriptions list (the device's own route first is up to the caller)."""
    return [r for r in accessible_routes(db, user) if r.serves(proto) and r.pool is not None]


def user_vless_routes(db: Session, user) -> list[Route]:
    return user_proto_routes(db, user, PROTO_VLESS)


def device_proto_pools(db: Session, device: Device, proto: str) -> list[ExitPool]:
    """Server pools a device's account must exist on: its own route's pool plus
    the pool of every `proto` route its owner may use."""
    pools: dict[int, ExitPool] = {}
    if device.route is not None and device.route.pool is not None:
        pools[device.route.pool.id] = device.route.pool
    for r in user_proto_routes(db, device.user, proto):
        pools.setdefault(r.pool.id, r.pool)
    return list(pools.values())


def device_vless_pools(db: Session, device: Device) -> list[ExitPool]:
    return device_proto_pools(db, device, PROTO_VLESS)


def pool_proto_configs(db: Session, pool: ExitPool, proto: str) -> list[IssuedConfig]:
    """Accounts of `proto` that must exist on `pool`'s servers: configs issued on
    the pool, plus those of devices whose owner may use some `proto` route on it
    (they reach it through their subscription). A user who loses access to all of
    the pool's routes drops out — reconcile then removes the account. A protocol
    paused on the pool's route has no accounts at all (they come back on resume)."""
    carrying = [r for r in pool.routes if r.has(proto)]
    if carrying and not any(r.serves(proto) for r in carrying):
        return []  # paused: the servers drop its accounts, the configs stay in the DB
    routes = [r for r in pool.routes if r.enabled and r.serves(proto)]
    out = []
    for c in db.query(IssuedConfig).filter(IssuedConfig.protocol == proto).all():
        if proto == PROTO_VLESS and not c.uuid:
            continue
        if c.pool_id == pool.id:
            out.append(c)
            continue
        dev = c.device
        if dev is not None and any(r.allows(dev.user) for r in routes):
            out.append(c)
    return out


def pool_vless_configs(db: Session, pool: ExitPool) -> list[IssuedConfig]:
    return pool_proto_configs(db, pool, PROTO_VLESS)


def _config_name(cfg: IssuedConfig) -> str:
    dev = cfg.device
    try:
        return dev.node_identifier() if dev else cfg.identifier[:8]
    except Exception:
        return cfg.identifier[:8]


# --- provisioning a pool exit (clone) -----------------------------------
def provision_pool_exit(db: Session, node: Node, only_missing: bool = False) -> dict:
    """Stand a node up as a CLONE in its pool: install what the pool's routes need
    — 3x-ui + the VLESS inbound (pool transport/masquerade), the AmneziaWG server,
    the NaiveProxy Caddy — all with the pool's shared identity, then converge it
    to the pool's current clients.

    `only_missing` («Привести к пулу») is the safe mode for a server that already
    serves clients: install only protocols that aren't there yet (3x-ui is not
    reinstalled, the AWG container is not recreated), refresh NaiveProxy users and
    certificates, ensure the VLESS inbound matches the pool, then reconcile."""
    if node.pool_id is None:
        raise NodeOpError("нода не привязана к пулу")
    pool = db.get(ExitPool, node.pool_id)
    if pool is None:
        raise NodeOpError("пул не найден")
    protos = pool.protocols
    if not protos:
        raise NodeOpError(
            f"у пула «{pool.name}» нет маршрутов — непонятно, какие протоколы ставить; "
            f"сначала создайте маршрут на этом пуле"
        )
    # A pooled exit behind gates is always managed THROUGH a gate (RU DPI drops the
    # direct Hub→exit handshake). Require a resolvable gate before we start, so
    # rollout never silently depends on a direct connection that dies on DPI.
    if _exit_needs_gate(node) and _gate_creds_for(node) is None:
        raise NodeOpError(
            "у пула нет гейта: заведите пул гейтов и маршрут (пул→гейты) до раскатки выхода"
        )

    from . import naive

    if PROTO_NAIVE in protos:
        # Certificates are issued on the Hub (DNS-01) before touching the server.
        for r in naive.pool_routes(pool):
            naive.ensure_cert(db, r)

    info: dict = {}
    installed: list[str] = []
    with connect(node) as n:
        provisioning.install_fleet_key(n, fleetkey.public_line(db))  # key-manage from here on
        provisioning.ensure_base(n)  # fresh Debian lacks curl, which the installers need
        _rc, names, _ = n.run("docker ps -a --format '{{.Names}}' 2>/dev/null", timeout=30)
        running = set((names or "").split())
        if PROTO_VLESS in protos and only_missing and node.has_xui:
            # Keep 3x-ui and its clients; only make sure the inbound is the pool's.
            provisioning.create_vless_inbound(
                n, node.xui_path, node.xui_port, node.xui_token, name=node.name,
                priv=pool.reality_private, pub=pool.reality_public,
                short_ids=pool.short_ids, spider_x=pool.spider_x, port=pool.vless_port,
                transport=pool.vless_transport, xhttp_path=pool.xhttp_path,
                target=pool.reality_dest, server_names=pool.reality_names,
            )
            installed.append(f"VLESS {pool.vless_transport.upper()} (проверен)")
        elif PROTO_VLESS in protos:
            info = provisioning.install_3xui(n)
            provisioning.set_panel_localhost(n)
            provisioning.pin_xray_version(n, settings.xray_version, info["xui_port"])
            provisioning.create_vless_inbound(
                n, info["xui_path"], info["xui_port"], info["xui_token"], name=node.name,
                priv=pool.reality_private, pub=pool.reality_public,
                short_ids=pool.short_ids, spider_x=pool.spider_x, port=pool.vless_port,
                transport=pool.vless_transport, xhttp_path=pool.xhttp_path,
                target=pool.reality_dest, server_names=pool.reality_names,
            )
            provisioning.harden_subscription(n)  # no public :2096 sub server
            installed.append(f"VLESS {pool.vless_transport.upper()} :{pool.vless_port}")
        if PROTO_AWG in protos and only_missing and settings.awg_container in running:
            installed.append("AmneziaWG (уже стоит)")
        elif PROTO_AWG in protos:
            provisioning.install_amneziawg(
                n, listen_port=pool.awg_port,
                priv=pool.awg_private, pub=pool.awg_public, psk=pool.awg_psk,
                params=pool.awg_params, subnet_prefix=pool.awg_subnet,
            )
            installed.append(f"AmneziaWG {pool.awg_version} UDP :{pool.awg_port}")
        if PROTO_NAIVE in protos:
            if only_missing and naive.CONTAINER in running:
                naive.sync(n, db, pool)
                installed.append("NaiveProxy (обновлён)")
            else:
                res = naive.install(n, db, pool)
                installed.append(f"NaiveProxy :443 ({', '.join(res['domains'])})")
        provisioning.disable_fail2ban(n)      # never ban the gate/panel
        try:
            provisioning.install_telegram_proxy(n)  # localhost TG proxy; bot reaches it via gate
        except Exception as e:
            log.warning("tg-proxy install on %s skipped: %s", node.name, e)

    if info:
        node.xui_path = info["xui_path"]
        node.xui_port = info["xui_port"]
        node.xui_token = info["xui_token"]  # encrypted via setter
    if PROTO_AWG in protos:
        node.awg_port = pool.awg_port
    node.key_installed = True  # fleet key now in authorized_keys → key-managed
    if not node.awg_endpoint_host:
        node.awg_endpoint_host = node.public_host
    db.commit()

    rec = reconcile_exit(db, pool, node)
    return {"installed": installed, "reconcile": rec}


# --- reconcile ----------------------------------------------------------
def reconcile_exit(db: Session, pool: ExitPool, node: Node) -> dict:
    """Converge one exit to the pool's desired client/peer set (idempotent).
    Adds missing clients/peers and removes extras, then records sync state."""
    added_v = removed_v = added_a = removed_a = 0
    protos = pool.protocols
    try:
        with connect(node) as n:
            # --- VLESS ---
            if node.has_xui and PROTO_VLESS in protos:
                with n.tunnel(node.xui_port) as lport:
                    xui = XUIClient(f"http://127.0.0.1:{lport}/{node.xui_path}", node.xui_token)
                    inbound = xui.find_vless_inbound()
                    desired = pool_vless_configs(db, pool)
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
                                c.identifier, [inbound.inbound_id], flow=pool.vless_flow,
                                client_id=want, sub_id=(c.sub_id or None),
                            )
                            added_v += 1
                    for email in (xui.list_client_emails() - desired_emails):
                        xui.del_client(email)
                        removed_v += 1
            # --- AmneziaWG ---
            if PROTO_AWG in protos:
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
            # --- NaiveProxy: the whole user list + certificates, then a reload ---
            if PROTO_NAIVE in protos:
                from . import naive

                naive.sync(n, db, pool)
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


def vless_link(pool: ExitPool, uuid: str, host: str, port: int, label: str = "") -> str:
    """The client's vless:// link, built from the POOL identity (no node needed):
    valid against every clone, for any entry point (`host`:`port` — a gate, the
    route's managed name, or a server of a direct route). Subscriptions build one
    per entry point the same way."""
    from urllib.parse import quote, urlencode

    from .models import VLESS_XHTTP, reality_template

    params = {
        "encryption": "none",
        "security": "reality",
        "sni": pool.reality_sni,
        "fp": reality_template()["fp"],
        "pbk": pool.reality_public,
        "sid": (pool.short_ids or [""])[0],
        "spx": pool.spider_x or "/",
    }
    if pool.vless_transport == VLESS_XHTTP:
        params.update({"type": "xhttp", "path": pool.xhttp_path or "/", "mode": "auto"})
    else:
        params.update({"type": "tcp", "headerType": "none", "flow": pool.vless_flow})
    h = f"[{host}]" if ":" in host else host  # IPv6 literal
    frag = f"#{quote(label, safe='-_.')}" if label else ""
    return f"vless://{uuid}@{h}:{int(port)}?{urlencode(params, quote_via=quote, safe='/')}{frag}"


def _vless_add(node: Node, email: str, cid: str, sub: str, flow: str) -> None:
    with connect(node) as n, n.tunnel(node.xui_port) as lport:
        xui = XUIClient(f"http://127.0.0.1:{lport}/{node.xui_path}", node.xui_token)
        inbound = xui.find_vless_inbound()
        if not xui.client_exists(email):
            xui.add_client(email, [inbound.inbound_id], flow=flow, client_id=cid, sub_id=sub)


def _reserve_config(db: Session, row: IssuedConfig) -> IssuedConfig:
    """Insert the device's (single) IssuedConfig row BEFORE any node-side work and
    commit it, so concurrent issuers agree on one identity. If another request got
    there first, UNIQUE(device_id) rejects ours: roll back (the session must stay
    usable) and return the winner's row instead."""
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        winner = db.query(IssuedConfig).filter_by(device_id=row.device_id).one_or_none()
        if winner is None:  # not a duplicate after all — surface the real error
            raise
        return winner
    db.refresh(row)
    return row


def issue_for_device(db: Session, device: Device) -> IssuedConfig:
    """Issue (or return existing) the device's pool-wide config.

    VLESS: generate the client's uuid/subId panel-side and force them onto every
    ready member (identical client everywhere); the link is built from the pool
    identity + the route's address (`vless_link`). AmneziaWG: generate the peer locally, build the vpn://
    from the POOL identity (no live node needed), and push the peer to all members."""
    # The client picks the route; honour exactly what the device is pinned to and
    # re-check access at issue time (so a revoked group stops working). No fallback.
    route = device.route
    if route is None or not route.enabled:
        raise NodeOpError("маршрут устройства не выбран или отключён — выберите доступный маршрут")
    if not route.allows(device.user):
        raise NodeOpError("этот маршрут вам недоступен — выберите другой")
    pool = route.pool
    if pool is None:
        raise NodeOpError("у маршрута нет пула выходов")
    if not route.is_direct and not route.gates:
        raise NodeOpError("в пуле гейтов маршрута нет гейтов")
    if not route.has(device.protocol):
        raise NodeOpError(
            f"маршрут «{route.name}» — {route.protocol_label}, а устройство — "
            f"{device.protocol}: выберите маршрут этого протокола"
        )
    host = route.host_for(device.protocol)  # managed hostname, else the first gate / server

    existing = db.query(IssuedConfig).filter_by(device_id=device.id).one_or_none()
    if not route.serves(device.protocol):
        # Paused: an issued config is still shown (it works again after resume),
        # a new one isn't made.
        if (existing is not None and existing.payload and existing.protocol == device.protocol
                and existing.route_id == route.id):
            return existing
        raise NodeOpError(f"{device.protocol} на маршруте «{route.name}» приостановлен — "
                          f"конфиг будет выдан после включения")

    # Already issued for this very route/pool: hand it back as is. Opening the
    # device page must not re-run the SSH fan-out to every exit each time (new
    # members get existing clients through pool sync, not through page views).
    if (
        existing is not None
        and existing.payload
        and existing.protocol == device.protocol
        and existing.pool_id == pool.id
        and existing.route_id == route.id
    ):
        if device.protocol == PROTO_VLESS and existing.uuid:
            # The link is built locally from the pool identity + route address, so
            # keep it current when the route's host/port changed (no node calls).
            fresh = vless_link(pool, existing.uuid, host, route.port_for(PROTO_VLESS),
                               f"{slugify(route.name)}-{existing.identifier}")
            if fresh != existing.payload:
                existing.payload = fresh
                db.commit()
        elif device.protocol == PROTO_NAIVE and existing.secret:
            from . import naive

            fresh = naive.link(existing.identifier, existing.secret, host,
                               route.port_for(PROTO_NAIVE), f"{slugify(route.name)}-{existing.identifier}")
            if fresh != existing.payload:
                existing.payload = fresh
                db.commit()
        return existing

    # members that can serve now: synced first, else any that has 3x-ui.
    ready = pool.synced_exits or [m for m in pool.members if m.has_xui]

    if device.protocol == PROTO_VLESS:
        if not ready:
            raise NodeOpError("в пуле нет готовых выходов")
        email = device.node_identifier()
        if existing is None:
            # Reserve the row (and with it the client identity) before touching any
            # node, so a parallel request reuses the same uuid/subId instead of
            # minting a second client.
            existing = _reserve_config(db, IssuedConfig(
                device_id=device.id, pool_id=pool.id, route_id=route.id,
                protocol=PROTO_VLESS, identifier=email,
                uuid=str(_uuid.uuid4()), sub_id=secrets.token_hex(8),
            ))
            if existing.payload and existing.pool_id == pool.id and existing.route_id == route.id:
                return existing  # a parallel request finished issuing meanwhile
        if existing.uuid:
            cid, sub = existing.uuid, existing.sub_id
        else:
            cid, sub = str(_uuid.uuid4()), secrets.token_hex(8)

        # Put the client (same uuid/subId) on every ready clone; at least one must
        # take it. The link itself is built from the pool identity, not fetched.
        used_node = None
        last_err: Exception | None = None
        for m in ready:
            try:
                _vless_add(m, email, cid, sub, pool.vless_flow)
                used_node = used_node or m
            except Exception as e:  # a down member mustn't block issuance
                last_err = e
                log.warning("vless fan-out to %s failed: %s", m.name, e)
        if used_node is None:
            raise NodeOpError(f"не удалось выпустить VLESS: {last_err}")
        # The device's subscription also lists the owner's other VLESS routes: put
        # the same client on those pools too (best effort — reconcile heals gaps).
        for other in device_vless_pools(db, device):
            if other.id == pool.id:
                continue
            for m in (other.synced_exits or [x for x in other.members if x.has_xui]):
                try:
                    _vless_add(m, email, cid, sub, other.vless_flow)
                except Exception as e:
                    log.warning("vless fan-out to %s (pool %s) failed: %s", m.name, other.name, e)

        # Label the link by ROUTE + full identifier (route-user-device) — stays
        # meaningful whichever gate/exit carries it.
        link = vless_link(pool, cid, host, route.port_for(PROTO_VLESS), f"{slugify(route.name)}-{email}")

        existing.protocol = PROTO_VLESS
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
            pool.awg_public, pool.awg_psk, route.port_for(PROTO_AWG), pool.awg_params, pool.awg_subnet
        )
        email = device.node_identifier()
        doc = awg.build_amnezia_dict(server, priv, pub, address, host, email)
        vpn = awg.encode_vpn(doc)

        # Reserve before pushing peers: a parallel request gets this same config
        # (same key pair) instead of pushing a second peer for the device.
        cfg = _reserve_config(db, IssuedConfig(
            device_id=device.id, pool_id=pool.id, node_id=None, route_id=route.id,
            protocol=PROTO_AWG, identifier=pub, address=address, payload=vpn,
        ))
        if cfg.identifier != pub:
            return cfg  # lost the race: the winner pushes its own peer

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
            # Nothing reached a node: drop the reservation so the next attempt
            # starts clean (otherwise it would be handed out without a peer).
            db.delete(cfg)
            db.commit()
            raise NodeOpError("не удалось добавить пир ни на один выход пула")
        return cfg

    elif device.protocol == PROTO_NAIVE:
        from . import naive

        if not pool.members:
            raise NodeOpError("в пуле нет серверов")
        login = device.node_identifier()
        if existing is None:
            # Reserve first: a parallel request reuses this login/password.
            row = IssuedConfig(device_id=device.id, pool_id=pool.id, route_id=route.id,
                               protocol=PROTO_NAIVE, identifier=login)
            row.secret = naive.new_password()
            existing = _reserve_config(db, row)
        password = existing.secret or naive.new_password()
        existing.secret = password
        existing.protocol = PROTO_NAIVE
        existing.pool_id = pool.id
        existing.route_id = route.id
        existing.identifier = existing.identifier or login
        db.commit()
        # The user list is per pool: push it to every NaiveProxy pool the owner can
        # use (their subscription lists those routes). The home pool must take it.
        ok_home, errs = naive.push_pool(db, pool)
        if ok_home == 0:
            raise NodeOpError("не удалось добавить пользователя NaiveProxy ни на один сервер пула: "
                              + "; ".join(errs))
        for other in device_proto_pools(db, device, PROTO_NAIVE):
            if other.id != pool.id:
                naive.push_pool(db, other)
        existing.payload = naive.link(existing.identifier, password, host,
                                      route.port_for(PROTO_NAIVE),
                                      f"{slugify(route.name)}-{existing.identifier}")
        db.commit()
        db.refresh(existing)
        return existing

    raise NodeOpError(f"unknown protocol {device.protocol!r}")


def deprovision_device(db: Session, device: Device) -> None:
    """Remove the device's clients/peers from every member of its pool(s).
    Never raises — a dead exit just can't be cleaned, which is fine."""
    for cfg in list(device.configs):
        if cfg.protocol == PROTO_NAIVE:
            # Users are a full list per pool: re-push it without this device to
            # every NaiveProxy pool (the device row still exists at this point).
            from . import naive

            for p in db.query(ExitPool).all():
                if PROTO_NAIVE in p.protocols:
                    naive.push_pool(db, p, exclude={cfg.id})
            continue
        pools: dict[int, ExitPool] = {}
        home = db.get(ExitPool, cfg.pool_id) if cfg.pool_id else None
        if home is not None:
            pools[home.id] = home
        if cfg.protocol == PROTO_VLESS:
            # The client was also put on the pools of the owner's other VLESS routes.
            for p in db.query(ExitPool).all():
                if PROTO_VLESS in p.protocols:
                    pools.setdefault(p.id, p)
        for m in [m for p in pools.values() for m in p.members]:
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


# --- gate relay for a gate pool ----------------------------------------
def gate_pool_plan(db: Session, gate_pool_id: int) -> dict:
    """The relay plan every gate of the pool runs, built from ALL routes using the
    pool (see app/relay.py). Raises NodeOpError explaining a conflict."""
    from . import relay

    routes = (
        db.query(Route)
        .filter(Route.gate_pool_id == gate_pool_id)
        .order_by(Route.id)
        .all()
    )
    if not routes:
        raise NodeOpError("пул гейтов не используется ни одним маршрутом")
    try:
        return relay.build_plan(routes)
    except relay.RelayConflict as e:
        raise NodeOpError(str(e)) from None


def gate_pool_problem(db: Session, gate_pool_id: int) -> str:
    """'' if the pool's routes fit one relay, else why not (for the «Парк» page)."""
    try:
        gate_pool_plan(db, gate_pool_id)
        return ""
    except NodeOpError as e:
        return str(e)


def provision_gate_relay(db: Session, gate: Node) -> dict:
    """Set one gate up as the health-checked relay of its gate pool: the plan built
    from every route of the pool (DNAT for single-target ports, SNI routing for TCP
    ports shared by several TLS routes, UDP for AmneziaWG), pushed with the daemon.
    The daemon then steers traffic to live servers only. Every gate of a gate pool
    gets the same relay."""
    from . import relay

    if not gate.is_gate:
        raise NodeOpError(f"«{gate.name}» — не gate-сервер")
    if gate.gate_pool_id is None:
        raise NodeOpError(f"гейт «{gate.name}» не входит в пул гейтов")
    plan = gate_pool_plan(db, gate.gate_pool_id)
    with connect(gate) as g:
        provisioning.install_fleet_key(g, fleetkey.public_line(db))  # key-manage from here on
        info = relay.install(g, plan)
    if not gate.key_installed:
        gate.key_installed = True
        db.commit()
    return {"summary": relay.plan_summary(plan), "plan": plan, **info}
