"""Panel data model: users -> devices -> issued configs, and nodes.

One active node at a time. A device is a named client of one protocol owned by a
user. An IssuedConfig records what was handed out for a (device, node) pair so a
repeat visit re-shows the same config and nothing gets duplicated; for AmneziaWG
it is also the ONLY place the client private key is kept (the node never has it).
"""

from __future__ import annotations

import json
import re
import time

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base
from .crypto import decrypt, encrypt

PROTO_VLESS = "vless"
PROTO_AWG = "awg"
PROTOCOLS = (PROTO_VLESS, PROTO_AWG)

# A node's role in a route. An exit runs the VPN and leaves to the internet; a
# gate is an RU relay placed in front of an exit (client → gate → exit → net).
ROLE_EXIT = "exit"
ROLE_GATE = "gate"
ROLES = (ROLE_EXIT, ROLE_GATE)

# A node's reachability status (set by the admin). `ok` = normal; `blocked` =
# fully blocked/dead (not reachable even via a gate); `gate_only` = blocked for
# direct access but still reachable through a clean gate on high ports (so it
# works as an exit behind a gate, just not directly).
STATUS_OK = "ok"
STATUS_BLOCKED = "blocked"
STATUS_GATE_ONLY = "gate_only"
NODE_STATUSES = (STATUS_OK, STATUS_BLOCKED, STATUS_GATE_ONLY)
_STATUS_LABEL = {STATUS_OK: "", STATUS_BLOCKED: "Заблокирован", STATUS_GATE_ONLY: "Только через гейт"}

# An exit node's sync state within its pool. `pending` = provisioned/added but
# not yet converged to the pool's client set; `synced` = holds all current
# clients/peers; `drifted` = a reconcile found/left a mismatch; `unreachable` =
# last reconcile couldn't reach it. Only `synced` exits are routed to by the gate.
SYNC_PENDING = "pending"
SYNC_SYNCED = "synced"
SYNC_DRIFTED = "drifted"
SYNC_UNREACHABLE = "unreachable"
SYNC_STATES = (SYNC_PENDING, SYNC_SYNCED, SYNC_DRIFTED, SYNC_UNREACHABLE)
_SYNC_LABEL = {
    SYNC_PENDING: "ожидает синхронизации",
    SYNC_SYNCED: "синхронизирован",
    SYNC_DRIFTED: "рассинхрон",
    SYNC_UNREACHABLE: "недоступен",
}


def slugify(value: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower()).strip("-")
    return s or "x"


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")
    created_at: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), server_default=func.now())

    devices: Mapped[list["Device"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class Node(Base):
    __tablename__ = "nodes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)

    # public host clients dial (VLESS + AWG endpoint). Usually the node's IP.
    public_host: Mapped[str] = mapped_column(String(255))

    # SSH access (root) — how the panel manages the node.
    ssh_host: Mapped[str] = mapped_column(String(255))
    ssh_port: Mapped[int] = mapped_column(Integer, default=22)
    ssh_username: Mapped[str] = mapped_column(String(64), default="root")
    ssh_password_enc: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # 3x-ui (filled in manually or by provisioning).
    xui_path: Mapped[str | None] = mapped_column(String(255), nullable=True)
    xui_port: Mapped[int] = mapped_column(Integer, default=29568)
    xui_token_enc: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # AmneziaWG. Endpoint host defaults to public_host.
    awg_endpoint_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    awg_port: Mapped[int] = mapped_column(Integer, default=44625)

    # Role: 'exit' (runs VPN, leaves to the internet) or 'gate' (RU relay).
    role: Mapped[str] = mapped_column(String(16), default=ROLE_EXIT, server_default=ROLE_EXIT)

    # Reachability status (admin-set): ok | blocked | gate_only.
    status: Mapped[str] = mapped_column(String(16), default=STATUS_OK, server_default=STATUS_OK)

    # Pool membership (exit nodes only). An exit in a pool is a cryptographic
    # CLONE of its siblings (shares the pool's Reality/AWG identity); the gate
    # fails over across the pool's synced members.
    pool_id: Mapped[int | None] = mapped_column(
        ForeignKey("exit_pools.id", ondelete="SET NULL"), nullable=True, index=True
    )
    sync_state: Mapped[str] = mapped_column(String(16), default=SYNC_PENDING, server_default=SYNC_PENDING)
    last_reconcile_at: Mapped["DateTime | None"] = mapped_column(DateTime(timezone=True), nullable=True)
    # Failover priority within the pool: LOWER = preferred. The gate relay sends
    # all traffic to the lowest-priority healthy member and only falls down to the
    # next when it dies (active/standby, not load-balancing).
    priority: Mapped[int] = mapped_column(Integer, default=100, server_default="100")

    is_active: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # --- secret helpers --------------------------------------------------
    @property
    def ssh_password(self) -> str | None:
        return decrypt(self.ssh_password_enc)

    @ssh_password.setter
    def ssh_password(self, value: str | None) -> None:
        self.ssh_password_enc = encrypt(value)

    @property
    def xui_token(self) -> str | None:
        return decrypt(self.xui_token_enc)

    @xui_token.setter
    def xui_token(self, value: str | None) -> None:
        self.xui_token_enc = encrypt(value)

    @property
    def endpoint_host(self) -> str:
        return self.awg_endpoint_host or self.public_host

    @property
    def has_xui(self) -> bool:
        return bool(self.xui_path and self.xui_token)

    @property
    def is_gate(self) -> bool:
        return self.role == ROLE_GATE

    @property
    def status_label(self) -> str:
        return _STATUS_LABEL.get(self.status, "")

    @property
    def is_blocked(self) -> bool:
        return self.status == STATUS_BLOCKED

    @property
    def sync_label(self) -> str:
        return _SYNC_LABEL.get(self.sync_state, self.sync_state)

    @property
    def is_synced(self) -> bool:
        return self.sync_state == SYNC_SYNCED


class ExitPool(Base):
    """A set of interchangeable exit nodes that share ONE crypto identity.

    Every exit in the pool is provisioned as a clone: same VLESS Reality keys /
    shortIds / spiderX / port and same AmneziaWG server key / PSK / obfuscation
    params / port, and the same client+peer tables (kept in step by reconcile).
    A client config is valid against any member, so the gate can fail over /
    load-balance across the pool without the client ever reconfiguring. The
    public IPs differ (invisible to the client — it dials the gate)."""

    __tablename__ = "exit_pools"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    status: Mapped[str] = mapped_column(String(16), default=STATUS_OK, server_default=STATUS_OK)

    # --- VLESS Reality identity (shared across members) ---
    vless_port: Mapped[int] = mapped_column(Integer, default=17771)
    reality_private_enc: Mapped[str | None] = mapped_column(String(512), nullable=True)
    reality_public: Mapped[str] = mapped_column(String(128), default="")
    short_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    spider_x: Mapped[str] = mapped_column(String(64), default="/")

    # --- AmneziaWG identity (shared across members) ---
    awg_port: Mapped[int] = mapped_column(Integer, default=17772)
    awg_private_enc: Mapped[str | None] = mapped_column(String(512), nullable=True)
    awg_public: Mapped[str] = mapped_column(String(128), default="")
    awg_psk_enc: Mapped[str | None] = mapped_column(String(512), nullable=True)
    awg_params_json: Mapped[str] = mapped_column(Text, default="{}")
    awg_subnet: Mapped[str] = mapped_column(String(32), default="10.8.1")

    created_at: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), server_default=func.now())

    members: Mapped[list["Node"]] = relationship(
        "Node", primaryjoin="Node.pool_id == ExitPool.id", viewonly=True
    )

    # --- secret helpers ---
    @property
    def reality_private(self) -> str | None:
        return decrypt(self.reality_private_enc)

    @reality_private.setter
    def reality_private(self, value: str | None) -> None:
        self.reality_private_enc = encrypt(value)

    @property
    def awg_private(self) -> str | None:
        return decrypt(self.awg_private_enc)

    @awg_private.setter
    def awg_private(self, value: str | None) -> None:
        self.awg_private_enc = encrypt(value)

    @property
    def awg_psk(self) -> str | None:
        return decrypt(self.awg_psk_enc)

    @awg_psk.setter
    def awg_psk(self, value: str | None) -> None:
        self.awg_psk_enc = encrypt(value)

    # --- json helpers ---
    @property
    def short_ids(self) -> list[str]:
        try:
            return json.loads(self.short_ids_json or "[]")
        except ValueError:
            return []

    @short_ids.setter
    def short_ids(self, value: list[str]) -> None:
        self.short_ids_json = json.dumps(list(value))

    @property
    def awg_params(self) -> dict:
        try:
            return json.loads(self.awg_params_json or "{}")
        except ValueError:
            return {}

    @awg_params.setter
    def awg_params(self, value: dict) -> None:
        self.awg_params_json = json.dumps(dict(value))

    @property
    def exits(self) -> list["Node"]:
        return list(self.members)

    @property
    def synced_exits(self) -> list["Node"]:
        return [n for n in self.members if n.sync_state == SYNC_SYNCED]


class Route(Base):
    """A path clients can pick: a GATE fronting an exit POOL.

    The client always dials the gate (`host`); the gate's L4 relay fails over
    across the pool's synced exits. The config's crypto comes from the pool's
    shared identity, so it stays valid whichever exit currently serves it.
    """

    __tablename__ = "routes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    pool_id: Mapped[int | None] = mapped_column(
        ForeignKey("exit_pools.id", ondelete="CASCADE"), nullable=True, index=True
    )
    gate_id: Mapped[int | None] = mapped_column(
        ForeignKey("nodes.id", ondelete="SET NULL"), nullable=True
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="1")
    # The single route new devices are issued against. Users don't pick a route;
    # the admin marks one "основной". (Kept as a model concept so multiple gates
    # can later be offered as a minimal choice, but hidden from clients for now.)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")
    created_at: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), server_default=func.now())

    pool: Mapped["ExitPool | None"] = relationship("ExitPool")
    gate_node: Mapped["Node | None"] = relationship("Node", foreign_keys=[gate_id])

    @property
    def host(self) -> str:
        """Host clients dial — the gate (the stable, domestic failover point)."""
        return self.gate_node.public_host if self.gate_node else ""

    @property
    def hops(self) -> str:
        """Human path, e.g. 'gate-ru-1 → pool:eu (2 exit)'."""
        gate = self.gate_node.name if self.gate_node else "—"
        if self.pool:
            return f"{gate} → пул:{self.pool.name} ({len(self.pool.exits)} exit)"
        return f"{gate} → ?"

    @property
    def is_blocked(self) -> bool:
        """Unusable if there is no gate/pool, the gate is blocked, or the pool has
        no synced exit to route to."""
        if self.gate_node is None or self.pool is None:
            return True
        if self.gate_node.status == STATUS_BLOCKED:
            return True
        if not self.pool.synced_exits:
            return True
        return False

    @property
    def block_reason(self) -> str:
        if self.gate_node is None:
            return "нет гейта"
        if self.pool is None:
            return "нет пула выходов"
        if self.gate_node.status == STATUS_BLOCKED:
            return f"гейт {self.gate_node.name} заблокирован"
        if not self.pool.synced_exits:
            return "в пуле нет синхронизированных выходов"
        return ""


class Setting(Base):
    """Tiny key/value store for global panel settings (e.g. the site-wide
    announcement banner shown to all logged-in clients)."""

    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")


ANNOUNCEMENT_KEY = "announcement"


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("user_id", "name", "protocol", name="uq_device"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(64))
    protocol: Mapped[str] = mapped_column(String(16))
    # Route this device's config is built against (chosen by the user).
    route_id: Mapped[int | None] = mapped_column(
        ForeignKey("routes.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_at: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), server_default=func.now())

    user: Mapped[User] = relationship(back_populates="devices")
    route: Mapped["Route | None"] = relationship("Route")
    configs: Mapped[list["IssuedConfig"]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )

    def node_identifier(self) -> str:
        """Stable, human-readable id used as the node-side client email / peer
        name. Unique across users (username is unique) AND across a user's own
        devices: two device names that slug to the same base (e.g. "x" and "X")
        would otherwise collide into ONE client/peer. We disambiguate by appending
        the device id — but only when an EARLIER (lower-id) device of the same user
        and protocol already owns the base, so adding a colliding device never
        changes an existing device's identifier (and so its config keeps working)."""
        base = f"{slugify(self.user.username)}-{slugify(self.name)}"
        try:
            my_slug = slugify(self.name)
            collides = any(
                d.id < self.id and d.protocol == self.protocol
                and slugify(d.name) == my_slug
                for d in self.user.devices
            )
        except Exception:
            collides = False
        return f"{base}-{self.id}" if collides else base


class IssuedConfig(Base):
    """What was handed out for a device — now pool-wide (one per device).

    The crypto belongs to the pool, so a single config is valid across every
    member. For VLESS we also keep the client `uuid`/`sub_id` so the SAME client
    can be forced onto every exit clone (identical link everywhere). For AWG the
    client private key lives only here (in `payload`, inside the vpn:// string)."""

    __tablename__ = "issued_configs"
    __table_args__ = (UniqueConstraint("device_id", name="uq_issued_device"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    pool_id: Mapped[int | None] = mapped_column(
        ForeignKey("exit_pools.id", ondelete="SET NULL"), nullable=True, index=True
    )
    node_id: Mapped[int | None] = mapped_column(
        ForeignKey("nodes.id", ondelete="SET NULL"), nullable=True, index=True
    )  # the member we fetched the VLESS link from (record only)
    route_id: Mapped[int | None] = mapped_column(
        ForeignKey("routes.id", ondelete="SET NULL"), nullable=True, index=True
    )
    protocol: Mapped[str] = mapped_column(String(16))
    identifier: Mapped[str] = mapped_column(String(128), default="")  # vless email / awg pubkey
    uuid: Mapped[str] = mapped_column(String(64), default="")          # vless client uuid (forced on clones)
    sub_id: Mapped[str] = mapped_column(String(64), default="")        # vless subId (forced on clones)
    address: Mapped[str] = mapped_column(String(64), default="")       # awg ip
    payload: Mapped[str] = mapped_column(Text, default="")             # vless link / awg vpn://
    created_at: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), server_default=func.now())

    device: Mapped[Device] = relationship(back_populates="configs")
