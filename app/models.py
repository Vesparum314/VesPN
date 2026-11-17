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
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base
from .crypto import decrypt, encrypt

PROTO_VLESS = "vless"
PROTO_AWG = "awg"
PROTO_NAIVE = "naive"
# Protocols a client can pick for a device / a route can carry.
PROTOCOLS = (PROTO_VLESS, PROTO_AWG, PROTO_NAIVE)
ALL_PROTOCOLS = PROTOCOLS
PROTOCOL_LABELS = {PROTO_VLESS: "VLESS", PROTO_AWG: "AmneziaWG", PROTO_NAIVE: "NaiveProxy"}

# VLESS transports a server pool can run (see ExitPool.vless_transport).
VLESS_TCP = "tcp"      # VLESS + TCP + Reality + Vision (pools from before XHTTP)
VLESS_XHTTP = "xhttp"  # VLESS + XHTTP + Reality (default for new pools)

# Default client-facing port of a NEW route (gate or server side). VLESS and
# NaiveProxy share TCP 443 (split by SNI on a gate), AmneziaWG uses UDP 443.
DEFAULT_CLIENT_PORT = 443

_template_cache: dict | None = None


def reality_template() -> dict:
    """Masquerade defaults from the VLESS inbound template: target, server names,
    uTLS fingerprint. Read once."""
    global _template_cache
    if _template_cache is None:
        from pathlib import Path

        path = Path(__file__).parent / "data" / "vless_inbound_template.json"
        try:
            rs = json.loads(path.read_text(encoding="utf-8"))["streamSettings"]["realitySettings"]
            _template_cache = {
                "target": rs.get("target") or rs.get("dest") or "",
                "names": [str(n).lower() for n in rs.get("serverNames", []) if n],
                "fp": (rs.get("settings") or {}).get("fingerprint") or "chrome",
            }
        except Exception:
            _template_cache = {"target": "", "names": [], "fp": "chrome"}
    return _template_cache


# DNS providers the panel can keep a route's client hostname in sync with
# (A records = the route's live entry points). Only the API flavour differs.
DNS_CLOUDFLARE = "cloudflare"
DNS_DESEC = "desec"
DNS_DYNV6 = "dynv6"
DNS_KINDS = (DNS_CLOUDFLARE, DNS_DESEC, DNS_DYNV6)

# A node's role in a route. An exit runs the VPN and leaves to the internet; a
# gate is an RU relay placed in front of an exit (client → gate → exit → net).
ROLE_EXIT = "exit"
ROLE_GATE = "gate"
ROLES = (ROLE_EXIT, ROLE_GATE)

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

# Background job state for a long node operation (provisioning / gate relay). The
# HTTP request returns at once and the real work runs in a thread (see app/jobs.py);
# the «Парк» page shows this and blocks a second click while `running`. This is how
# minutes-long operations survive a reverse-proxy response timeout (e.g. Cloudflare
# 524 at 100 s) without the admin losing the result or double-triggering a rollout.
JOB_IDLE = "idle"
JOB_RUNNING = "running"
JOB_DONE = "done"
JOB_ERROR = "error"
JOB_STATES = (JOB_IDLE, JOB_RUNNING, JOB_DONE, JOB_ERROR)

# Monitoring reachability-history kinds (see NodeStatusHistory).
HIST_MGMT = "mgmt"      # Hub → node management reachability (Hub→gate, Hub→exit via gate)
HIST_CLIENT = "client"  # gate → exit client path (VLESS traffic port)
HIST_HUB = "hub"        # gate journal: gate's ports reachable from the Hub (inside the region)
HIST_ABROAD = "abroad"  # gate journal: gate reachable from a server abroad


# A user's access role (distinct from a node's role above). `admin` = full control
# INCLUDING managing people's roles; `operator` = same powers over the fleet,
# clients, groups and routes but CANNOT manage roles; `client` = end user.
ROLE_ADMIN = "admin"
ROLE_OPERATOR = "operator"
ROLE_CLIENT = "client"
USER_ROLES = (ROLE_ADMIN, ROLE_OPERATOR, ROLE_CLIENT)
STAFF_ROLES = (ROLE_ADMIN, ROLE_OPERATOR)
_USER_ROLE_LABEL = {ROLE_ADMIN: "админ", ROLE_OPERATOR: "оператор", ROLE_CLIENT: "клиент"}


# Access groups (many-to-many). A client may use a route only if they share at
# least one group with it; a route with no groups is accessible to no client.
user_groups = Table(
    "user_groups", Base.metadata,
    Column("user_id", ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("group_id", ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True),
)
route_groups = Table(
    "route_groups", Base.metadata,
    Column("route_id", ForeignKey("routes.id", ondelete="CASCADE"), primary_key=True),
    Column("group_id", ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True),
)
# Target groups for an announcement. Empty = shown to ALL clients (not nobody).
announcement_groups = Table(
    "announcement_groups", Base.metadata,
    Column("announcement_id", ForeignKey("announcements.id", ondelete="CASCADE"), primary_key=True),
    Column("group_id", ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True),
)


# Cyrillic → Latin, so Russian user/device names become readable ASCII slugs
# (the client's node-side email, the config filename, the VLESS link label) instead
# of being stripped to "x". Lowercase keys — slugify lowercases before transliterating.
_TRANSLIT = {ord(k): v for k, v in {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e",
    "ж": "zh", "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m",
    "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
    "ф": "f", "х": "kh", "ц": "ts", "ч": "ch", "ш": "sh", "щ": "shch",
    "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
}.items()}


def slugify(value: str) -> str:
    s = value.strip().lower().translate(_TRANSLIT)
    s = re.sub(r"[^a-zA-Z0-9]+", "-", s).strip("-")
    return s or "x"


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default=ROLE_CLIENT, server_default=ROLE_CLIENT)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")
    # The staff account (admin/operator) that created this user; NULL for the
    # bootstrap admin or if the creator was later deleted.
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), server_default=func.now())

    devices: Mapped[list["Device"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    groups: Mapped[list["Group"]] = relationship(secondary=user_groups, back_populates="users")
    creator: Mapped["User | None"] = relationship(
        "User", remote_side=[id], foreign_keys=[created_by]
    )

    @property
    def is_staff(self) -> bool:
        """admin or operator — may access the admin area and manage the fleet,
        clients, groups and routes."""
        return self.role in STAFF_ROLES

    @property
    def is_admin(self) -> bool:
        """Only the top role — the single thing an operator can't do is manage
        people's roles (create operators/admins, change roles, delete staff)."""
        return self.role == ROLE_ADMIN

    @property
    def role_label(self) -> str:
        return _USER_ROLE_LABEL.get(self.role, self.role)

    @property
    def group_ids(self) -> set[int]:
        return {g.id for g in self.groups}


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
    # next when it dies (active/standby, not load-balancing). For a gate it orders
    # the gates of its gate pool (which one the panel manages exits through first).
    priority: Mapped[int] = mapped_column(Integer, default=100, server_default="100")

    # Gate-pool membership (gate nodes only). Every gate of a pool runs the same
    # relay, so clients may enter through any of them.
    gate_pool_id: Mapped[int | None] = mapped_column(
        ForeignKey("gate_pools.id", ondelete="SET NULL"), nullable=True, index=True
    )

    is_active: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    # True once provisioning has put the fleet public key in the node's
    # authorized_keys — i.e. the panel now manages it by key, not by password.
    key_installed: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")

    # Background job for a long op on this node (provisioning, gate relay). The
    # request thread only flips `job_state` to `running` and spawns a worker; the
    # worker writes the result back here (see app/jobs.py). job_kind is a short code
    # ('provision' | 'relay'); job_message holds the success text or the error.
    job_state: Mapped[str] = mapped_column(String(16), default=JOB_IDLE, server_default=JOB_IDLE)
    job_kind: Mapped[str | None] = mapped_column(String(32), nullable=True)
    job_message: Mapped[str] = mapped_column(Text, default="", server_default="")
    job_started_at: Mapped["DateTime | None"] = mapped_column(DateTime(timezone=True), nullable=True)
    job_finished_at: Mapped["DateTime | None"] = mapped_column(DateTime(timezone=True), nullable=True)

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
    def sync_label(self) -> str:
        return _SYNC_LABEL.get(self.sync_state, self.sync_state)

    @property
    def is_synced(self) -> bool:
        return self.sync_state == SYNC_SYNCED

    @property
    def job_running(self) -> bool:
        return self.job_state == JOB_RUNNING


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

    # --- VLESS Reality identity (shared across members) ---
    vless_port: Mapped[int] = mapped_column(Integer, default=17771)
    reality_private_enc: Mapped[str | None] = mapped_column(String(512), nullable=True)
    reality_public: Mapped[str] = mapped_column(String(128), default="")
    short_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    spider_x: Mapped[str] = mapped_column(String(64), default="/")
    # VLESS transport: 'xhttp' (VLESS + XHTTP + Reality) for new pools; 'tcp'
    # (VLESS + TCP + Reality + Vision) for pools from before. Part of the client
    # config — changing it means re-issuing every VLESS config of the pool.
    vless_transport: Mapped[str] = mapped_column(String(16), default=VLESS_XHTTP, server_default="tcp")
    xhttp_path: Mapped[str] = mapped_column(String(64), default="", server_default="")
    # Reality masquerade: the real site unauthenticated visitors are proxied to
    # (host:port) and the SNIs the inbound answers to. Empty = the inbound
    # template's (app/data/vless_inbound_template.json). Also part of client configs.
    reality_target: Mapped[str] = mapped_column(String(255), default="", server_default="")
    reality_names_json: Mapped[str] = mapped_column(Text, default="[]", server_default="[]")

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
    routes: Mapped[list["Route"]] = relationship("Route", back_populates="pool", viewonly=True)

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
    def reality_names(self) -> list[str]:
        """SNIs the pool's Reality inbound answers to (own, else the template's)."""
        try:
            own = [str(n).strip().lower() for n in json.loads(self.reality_names_json or "[]") if str(n).strip()]
        except ValueError:
            own = []
        return own or reality_template()["names"]

    @reality_names.setter
    def reality_names(self, value: list[str]) -> None:
        self.reality_names_json = json.dumps([str(n).strip().lower() for n in value if str(n).strip()])

    @property
    def reality_dest(self) -> str:
        """host:port of the masquerade site (own, else the template's)."""
        return self.reality_target or reality_template()["target"]

    @property
    def reality_sni(self) -> str:
        """The SNI put into client configs: the masquerade host if it is among the
        server names, else the first server name."""
        names = self.reality_names
        host = self.reality_dest.rsplit(":", 1)[0].lower()
        return host if host in names else (names[0] if names else host)

    @property
    def awg_version(self) -> str:
        """AmneziaWG protocol of the pool: '3.1' (header protection etc.) or '2'."""
        return "3.1" if self.awg_params.get("HeaderProtectionKey") else "2"

    @property
    def vless_flow(self) -> str:
        """Client flow: Vision only on raw TCP (XHTTP carries no flow)."""
        return "xtls-rprx-vision" if self.vless_transport == VLESS_TCP else ""

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

    @property
    def protocols(self) -> list[str]:
        """Protocols this pool's servers must run — the union of its routes'
        protocols. One server can carry several (e.g. VLESS and NaiveProxy): the
        pool simply has a route per protocol."""
        found: set[str] = set()
        for r in self.routes:
            found.update(r.protocols)
        return [p for p in ALL_PROTOCOLS if p in found]

    @property
    def protocols_label(self) -> str:
        return " + ".join(PROTOCOL_LABELS[p] for p in self.protocols) or "—"


class GatePool(Base):
    """A set of interchangeable RU entry points (gates).

    Every gate of the pool runs the same relay — built from ALL routes that use
    the pool — so a client may enter through any of them, and one pool can front
    several routes (several protocols) at once. Gates are expendable: adding or
    replacing one changes only DNS and subscriptions, never the client's config."""

    __tablename__ = "gate_pools"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), server_default=func.now())

    members: Mapped[list["Node"]] = relationship(
        "Node", primaryjoin="Node.gate_pool_id == GatePool.id", viewonly=True
    )
    routes: Mapped[list["Route"]] = relationship("Route", back_populates="gate_pool", viewonly=True)

    @property
    def gates(self) -> list["Node"]:
        """Gates in management/preference order (lower priority first)."""
        return sorted(self.members, key=lambda n: (n.priority, n.id))


class DnsProvider(Base):
    """API access to one DNS zone, used to point a route's client hostname at the
    route's live entry points. The token is stored encrypted, like node secrets."""

    __tablename__ = "dns_providers"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    kind: Mapped[str] = mapped_column(String(16))  # one of DNS_KINDS
    zone: Mapped[str] = mapped_column(String(255))
    token_enc: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    created_at: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), server_default=func.now())

    @property
    def token(self) -> str | None:
        return decrypt(self.token_enc)

    @token.setter
    def token(self, value: str | None) -> None:
        self.token_enc = encrypt(value)


class Route(Base):
    """A path clients can pick: ONE protocol over a server POOL, entered either
    through a GATE POOL (RU relays) or directly. A pool whose servers carry several
    protocols has one route per protocol (they may share the gate pool, too).

    The client dials `host` — a hostname kept pointing at the route's live entry
    points (or, when none is set, the first gate / server itself). Through a gate
    pool, every gate's L4 relay fails over across the server pool's synced
    members. The config's crypto comes from the server pool's shared identity, so
    it stays valid whichever gate and whichever server currently carry it.
    """

    __tablename__ = "routes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    # vless | naive | awg. Empty = a legacy route from before per-protocol routes:
    # it serves BOTH VLESS and AmneziaWG (and its pool's servers run both).
    protocol: Mapped[str] = mapped_column(String(16), default="", server_default="")
    pool_id: Mapped[int | None] = mapped_column(
        ForeignKey("exit_pools.id", ondelete="CASCADE"), nullable=True, index=True
    )
    # NULL = direct: clients connect to the server pool itself, no RU gate.
    gate_pool_id: Mapped[int | None] = mapped_column(
        ForeignKey("gate_pools.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # What goes into client configs. Empty host = fall back to the first gate's
    # (or, for a direct route, the first server's) public host; empty port = the
    # protocol's default port of the server pool.
    client_host: Mapped[str] = mapped_column(String(255), default="", server_default="")
    client_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Zone whose API keeps `client_host` A records = live entry points (optional).
    dns_provider_id: Mapped[int | None] = mapped_column(
        ForeignKey("dns_providers.id", ondelete="SET NULL"), nullable=True
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="1")
    created_at: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), server_default=func.now())

    pool: Mapped["ExitPool | None"] = relationship("ExitPool", back_populates="routes")
    gate_pool: Mapped["GatePool | None"] = relationship("GatePool", back_populates="routes")
    dns_provider: Mapped["DnsProvider | None"] = relationship("DnsProvider")
    # Access groups allowed to use this route. Empty = no client may use it.
    groups: Mapped[list["Group"]] = relationship(secondary=route_groups, back_populates="routes")

    def allows(self, user) -> bool:
        """True if the user may make a config on this route. Staff (admin/operator)
        may use ANY enabled route; a client only one sharing an access group."""
        if not self.enabled:
            return False
        if user.is_staff:
            return True
        return bool({g.id for g in self.groups} & set(user.group_ids))

    @property
    def is_direct(self) -> bool:
        return self.gate_pool_id is None

    @property
    def gates(self) -> list["Node"]:
        return self.gate_pool.gates if self.gate_pool else []

    @property
    def primary_gate(self) -> "Node | None":
        gates = self.gates
        return gates[0] if gates else None

    @property
    def entry_points(self) -> list["Node"]:
        """Nodes clients actually connect to: the gates, or (direct) the servers."""
        if not self.is_direct:
            return self.gates
        return sorted(self.pool.members, key=lambda n: (n.priority, n.id)) if self.pool else []

    @property
    def host(self) -> str:
        """Host clients dial: the managed hostname, else the first entry point."""
        if self.client_host:
            return self.client_host
        entries = self.entry_points
        return entries[0].public_host if entries else ""

    @property
    def is_legacy(self) -> bool:
        return not self.protocol

    @property
    def protocols(self) -> list[str]:
        """What a device on this route may use (a legacy route: VLESS and AWG)."""
        return [PROTO_VLESS, PROTO_AWG] if self.is_legacy else [self.protocol]

    def serves(self, protocol: str) -> bool:
        return protocol in self.protocols

    def port_for(self, protocol: str) -> int:
        """Port clients dial for `protocol` on this route: the route's own port if
        set (not for legacy routes, whose configs carry the pool ports, and not for
        direct routes — there's no gate to map a port, clients hit the server's own
        port), else the pool's server port (VLESS/AWG) or 443 (NaiveProxy)."""
        if self.client_port and not self.is_legacy and not self.is_direct:
            return int(self.client_port)
        if self.pool is not None:
            if protocol == PROTO_VLESS:
                return int(self.pool.vless_port)
            if protocol == PROTO_AWG:
                return int(self.pool.awg_port)
        return DEFAULT_CLIENT_PORT

    @property
    def protocol_label(self) -> str:
        return " + ".join(PROTOCOL_LABELS.get(p, p) for p in self.protocols)

    @property
    def hops(self) -> str:
        """Human path, e.g. 'гейты:ru-a (2) → пул:eu (2 exit)'."""
        entry = "напрямую" if self.is_direct else (
            f"гейты:{self.gate_pool.name} ({len(self.gates)})" if self.gate_pool else "—"
        )
        if self.pool:
            return f"{entry} → пул:{self.pool.name} ({len(self.pool.exits)} exit)"
        return f"{entry} → ?"

    @property
    def is_blocked(self) -> bool:
        return bool(self.block_reason)

    @property
    def block_reason(self) -> str:
        """Why the route can't serve clients right now ('' = it can)."""
        if self.pool is None:
            return "нет пула выходов"
        if self.protocol == PROTO_NAIVE and not self.client_host:
            return "у NaiveProxy-маршрута не задано имя хоста (на него выпускается сертификат)"
        if not self.is_direct and not self.gates:
            return "в пуле гейтов нет гейтов"
        if not self.pool.synced_exits:
            return "в пуле нет синхронизированных выходов"
        return ""


class Group(Base):
    """A named access group. A user can be in several; a route can allow several.
    A client may use a route only if they share at least one group with it."""

    __tablename__ = "groups"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), server_default=func.now())

    users: Mapped[list["User"]] = relationship(secondary=user_groups, back_populates="groups")
    routes: Mapped[list["Route"]] = relationship(secondary=route_groups, back_populates="groups")


class Setting(Base):
    """Tiny key/value store for global panel settings (e.g. the site-wide
    announcement banner shown to all logged-in clients)."""

    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")


ANNOUNCEMENT_KEY = "announcement"  # legacy single-banner setting (migrated to Announcement)


class Announcement(Base):
    """An admin→clients message. Active ones show as a banner to every logged-in
    client; all are kept as a journal on the admin «Уведомления» page."""

    __tablename__ = "announcements"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="1", index=True)
    created_at: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), server_default=func.now())
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    author: Mapped["User | None"] = relationship("User", foreign_keys=[created_by])
    # Target groups; empty = shown to every client.
    groups: Mapped[list["Group"]] = relationship("Group", secondary=announcement_groups)

    def visible_to(self, user) -> bool:
        """A client sees this active announcement if it targets no group (everyone)
        or shares at least one target group with the user."""
        tg = self.groups
        if not tg:
            return True
        return bool({g.id for g in tg} & set(user.group_ids))


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
    # Secret part of the device's subscription URL (random, unguessable). NULL until
    # first requested; re-issuing it revokes the old URL.
    sub_token: Mapped[str | None] = mapped_column(String(64), nullable=True, unique=True, index=True)
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
    # A per-device secret the servers must know in clear (NaiveProxy password),
    # stored encrypted like node secrets.
    secret_enc: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), server_default=func.now())

    device: Mapped[Device] = relationship(back_populates="configs")

    @property
    def secret(self) -> str | None:
        return decrypt(self.secret_enc)

    @secret.setter
    def secret(self, value: str | None) -> None:
        self.secret_enc = encrypt(value)


class TrafficStat(Base):
    """Per-device traffic accounting, collected periodically THROUGH THE GATE (never
    a direct Hub→exit). Node counters (3x-ui usedTraffic / `awg show transfer`) are
    cumulative and reset on node restart, so we store per-(device,node) last-seen
    values in `seen_json` and accumulate deltas into total + today (UTC). `up` =
    client→server, `down` = server→client; summed across the pool's members."""

    __tablename__ = "traffic_stats"
    device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True
    )
    up_total: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    down_total: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    up_today: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    down_today: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    day: Mapped[str] = mapped_column(String(10), default="", server_default="")  # YYYY-MM-DD UTC
    seen_json: Mapped[str] = mapped_column(Text, default="{}", server_default="{}")
    updated_at: Mapped["DateTime | None"] = mapped_column(DateTime(timezone=True), nullable=True)

    device: Mapped["Device"] = relationship("Device")

    @property
    def seen(self) -> dict:
        try:
            return json.loads(self.seen_json or "{}")
        except ValueError:
            return {}

    @seen.setter
    def seen(self, value: dict) -> None:
        self.seen_json = json.dumps(value)


class NaiveCert(Base):
    """TLS certificate of a NaiveProxy domain, issued on the Hub (app/acme.py, DNS-01)
    and pushed to every server of the pool. The key is stored encrypted."""

    __tablename__ = "naive_certs"
    domain: Mapped[str] = mapped_column(String(255), primary_key=True)
    cert_pem: Mapped[str] = mapped_column(Text)
    key_enc: Mapped[str] = mapped_column(Text)
    not_after: Mapped["DateTime"] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), server_default=func.now())

    @property
    def key_pem(self) -> str:
        return decrypt(self.key_enc) or ""

    @key_pem.setter
    def key_pem(self, value: str) -> None:
        self.key_enc = encrypt(value)


class GateSample(Base):
    """One gate-journal sample (every few minutes): is the gate reachable from the
    Hub (inside the censored region — roughly what clients see) and from a server
    abroad (tells «blocked at the hoster/upstream» from «blocked for local
    clients»), plus traffic counters and how many clients were connected. Kept to
    answer, after a ban, *when* it happened, *from which side* and *under what
    load* — the point of running several gates side by side."""

    __tablename__ = "gate_samples"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id", ondelete="CASCADE"), index=True)
    at: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    hub_ok: Mapped[bool] = mapped_column(Boolean)
    abroad_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)  # None = no vantage point
    vantage: Mapped[str] = mapped_column(String(64), default="", server_default="")
    # Cumulative interface counters on the gate (reset on reboot); None = not read.
    rx_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tx_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    clients: Mapped[int | None] = mapped_column(Integer, nullable=True)  # distinct client IPs right now

    node: Mapped["Node"] = relationship("Node")


class NodeStatusHistory(Base):
    """Reachability transitions per node — one row per up<->down flip, so the panel
    keeps a timeline of when a node was reachable and when not. `kind`: `mgmt`
    (Hub→node management) or `client` (gate→exit traffic path); `up` = reachable."""

    __tablename__ = "node_status_history"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[int] = mapped_column(
        ForeignKey("nodes.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(8), index=True)
    up: Mapped[bool] = mapped_column(Boolean)
    at: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)

    node: Mapped["Node"] = relationship("Node")
