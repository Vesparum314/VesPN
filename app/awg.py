"""AmneziaWG peer management on a node + AmneziaVPN-app config generation.

The user deploys AmneziaWG themselves (Amnezia-client Docker container, image
amneziavpn/amneziawg-go, config under /opt/amnezia/awg). The panel adds client
peers to that running container and emits a config that the **AmneziaVPN app**
can import.

Crucial format note (learned from real app-exported configs):
  * The AmneziaVPN app does NOT import a plain WireGuard `.conf`. It imports a
    `vpn://<base64url>` string whose bytes are `qCompress` (4-byte big-endian
    length + zlib) of a JSON document (containers → awg → last_config, dns1/dns2,
    hostName, …). We reproduce that exact structure.
  * The client config must carry the FULL obfuscation set incl. `I1..I5` (junk
    packets). On the server these live in awg0.conf's [Interface], often
    COMMENTED OUT — the app still ships them to clients, so we read them even
    from commented lines.

Peer creation itself (validated on live nodes): add LIVE with
`awg set awg0 peer <pub> ... allowed-ips X/32` (no interface restart), persist a
[Peer] block to awg0.conf, keep clientsTable in sync.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import struct
import zlib
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .node_ssh import SSHNode

# obfuscation keys we carry into client configs (order used in the .conf text)
PARAM_ORDER = ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4",
               "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5"]
_PARAM_SET = set(PARAM_ORDER)
DEFAULT_CONF_DIR = "/opt/amnezia/awg"
DEFAULT_DNS1 = "1.1.1.1"
DEFAULT_DNS2 = "1.0.0.1"
DEFAULT_MTU = "1280"
# Container TYPE the AmneziaVPN app recognizes for AmneziaWG (distinct from the
# docker container's name on the server, which only we use for peer management).
APP_CONTAINER_TYPE = "amnezia-awg2"


class AWGError(RuntimeError):
    pass


def gen_keypair() -> tuple[str, str]:
    """WireGuard-compatible (clamped Curve25519) keypair -> (priv_b64, pub_b64).
    Private key stays panel-side; only the public key is pushed to the node."""
    raw = bytearray(secrets.token_bytes(32))
    raw[0] &= 248
    raw[31] &= 127
    raw[31] |= 64
    priv = X25519PrivateKey.from_private_bytes(bytes(raw))
    priv_b = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                serialization.NoEncryption())
    pub_b = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(priv_b).decode(), base64.b64encode(pub_b).decode()


# --------------------------------------------------------------------------
# Fresh AmneziaWG server config generation (panel auto-deploys the server now,
# via the official amneziavpn/amneziawg-go image — the same engine the
# AmneziaVPN app runs). These render the exact on-disk shape read_server() parses
# back, so peer management + vpn:// generation keep working unchanged.
# --------------------------------------------------------------------------
DEFAULT_SERVER_SUBNET = "10.8.1"


def gen_psk() -> str:
    """A fresh WireGuard pre-shared key (32 random bytes, base64)."""
    return base64.b64encode(secrets.token_bytes(32)).decode()


def gen_obfuscation_params() -> dict:
    """Per-server AmneziaWG **2.0** obfuscation set, randomized so no two of our
    servers share a DPI signature. H1..H4 are four distinct, non-overlapping
    RANGES high in the uint32 space (well clear of the 1..4 real WireGuard
    message types) and S1..S4 are all >= 12 — both are what makes the AmneziaVPN
    app treat the config as AmneziaWG 2.0 (header protection) rather than
    "legacy". Jmax stays under the client MTU. I1..I5 (optional client-side junk
    signatures) are left empty."""
    rnd = secrets.SystemRandom()
    jmin = rnd.randint(8, 25)
    jmax = rnd.randint(jmin + 30, 120)
    hv = sorted(rnd.sample(range(16, 2 ** 31 - 1), 8))
    return {
        "Jc": str(rnd.randint(4, 12)),
        "Jmin": str(jmin),
        "Jmax": str(jmax),
        "S1": str(rnd.randint(15, 90)),
        "S2": str(rnd.randint(15, 90)),
        "S3": str(rnd.randint(15, 90)),
        "S4": str(rnd.randint(15, 90)),
        "H1": f"{hv[0]}-{hv[1]}",
        "H2": f"{hv[2]}-{hv[3]}",
        "H3": f"{hv[4]}-{hv[5]}",
        "H4": f"{hv[6]}-{hv[7]}",
    }


def render_server_conf(priv: str, listen_port: int, params: dict,
                       subnet_prefix: str = DEFAULT_SERVER_SUBNET, cidr: int = 24) -> str:
    """Render a fresh awg0.conf [Interface] (no peers) in the exact shape the
    AmneziaVPN-app container uses — which is what read_server() parses back. The
    server address is <prefix>.0/<cidr> (the app's convention). I1..I5 are
    written commented-out (client-side only) so awg-quick ignores them, while
    read_server() still picks them up for the client config."""
    lines = [
        "[Interface]",
        f"PrivateKey = {priv}",
        f"Address = {subnet_prefix}.0/{cidr}",
        f"ListenPort = {listen_port}",
    ]
    for k in ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"):
        lines.append(f"{k} = {params.get(k, '')}")
    for k in ("I1", "I2", "I3", "I4", "I5"):
        lines.append(f"# {k} = {params.get(k, '')}")
    return "\n".join(lines) + "\n"


@dataclass
class AWGServer:
    container: str
    conf_path: str
    interface: str
    server_pubkey: str
    psk: str
    psk_path: str
    listen_port: int
    subnet_prefix: str          # e.g. "10.8.1"
    cidr: int
    params: dict = field(default_factory=dict)   # Jc..I5 (strings; missing -> "")
    used_hosts: set[int] = field(default_factory=set)
    protocol_version: str = "2"

    def p(self, key: str) -> str:
        return self.params.get(key, "")


def server_from_identity(
    server_pubkey: str, psk: str, listen_port: int, params: dict,
    subnet_prefix: str = DEFAULT_SERVER_SUBNET, cidr: int = 24,
) -> "AWGServer":
    """Build an AWGServer from a POOL identity (shared keys/params) with no live
    node — so a client's vpn:// config can be produced from the pool's stored
    identity alone, valid against every cloned exit in the pool."""
    return AWGServer(
        container="",
        conf_path=f"{DEFAULT_CONF_DIR}/awg0.conf",
        interface="awg0",
        server_pubkey=server_pubkey,
        psk=psk,
        psk_path=f"{DEFAULT_CONF_DIR}/wireguard_psk.key",
        listen_port=listen_port,
        subnet_prefix=subnet_prefix,
        cidr=cidr,
        params=dict(params),
    )


# --------------------------------------------------------------------------
# AmneziaVPN-app config (vpn://) construction
# --------------------------------------------------------------------------
def _wg_config_text(server: AWGServer, priv: str, address: str, host: str) -> str:
    """The inner [Interface]/[Peer] text, DNS left as the app's placeholders."""
    lines = [
        "[Interface]",
        f"Address = {address}/32",
        "DNS = $PRIMARY_DNS, $SECONDARY_DNS",
        f"PrivateKey = {priv}",
    ]
    for k in PARAM_ORDER:
        lines.append(f"{k} = {server.p(k)}")
    lines += [
        "",
        "[Peer]",
        f"PublicKey = {server.server_pubkey}",
        f"PresharedKey = {server.psk}",
        "AllowedIPs = 0.0.0.0/0, ::/0",
        f"Endpoint = {host}:{server.listen_port}",
        "PersistentKeepalive = 25",
    ]
    return "\n".join(lines) + "\n"


def build_amnezia_dict(
    server: AWGServer, priv: str, pub: str, address: str, host: str,
    description: str, dns1: str = DEFAULT_DNS1, dns2: str = DEFAULT_DNS2,
) -> dict:
    """Build the JSON document the AmneziaVPN app expects (pre-encoding)."""
    param_fields = {k: server.p(k) for k in PARAM_ORDER}

    inner = {
        **param_fields,
        "allowed_ips": ["0.0.0.0/0", "::/0"],
        "clientId": pub,
        "client_ip": address,
        "client_priv_key": priv,
        "client_pub_key": pub,
        "config": _wg_config_text(server, priv, address, host),
        "hostName": host,
        "mtu": DEFAULT_MTU,
        "persistent_keep_alive": "25",
        "port": server.listen_port,
        "psk_key": server.psk,
        "server_pub_key": server.server_pubkey,
    }
    last_config = json.dumps(inner, sort_keys=True, indent=4, ensure_ascii=False) + "\n"

    awg_block = {
        **param_fields,
        "last_config": last_config,
        "port": str(server.listen_port),
        "protocol_version": server.protocol_version,
        "subnet_address": f"{server.subnet_prefix}.0",
        "transport_proto": "udp",
    }
    # The AmneziaVPN app identifies the protocol purely by the container TYPE
    # string (NOT the docker container's name on the server, which we only use
    # for peer management). The type also selects the UI label:
    #   "amnezia-awg2"  -> AmneziaWG 2.0 (current)
    #   "amnezia-awg"   -> AmneziaWG Legacy (shown as "Legacy (version 2)")
    #   our docker name (e.g. "vespn-awg") -> "not installed", offers to deploy
    # Verified against real AmneziaVPN app exports (which use "amnezia-awg2")
    # and amnezia-client issues. So always emit the current type.
    return {
        "containers": [{"awg": awg_block, "container": APP_CONTAINER_TYPE}],
        "defaultContainer": APP_CONTAINER_TYPE,
        "description": description,
        "dns1": dns1,
        "dns2": dns2,
        "hostName": host,
        "nameOverriddenByUser": True,
    }


def encode_vpn(doc: dict) -> str:
    """Encode the JSON doc as the app's `vpn://` string (qCompress + base64url)."""
    raw = json.dumps(doc, sort_keys=True, ensure_ascii=False).encode("utf-8")
    blob = struct.pack(">I", len(raw)) + zlib.compress(raw, 8)
    return "vpn://" + base64.urlsafe_b64encode(blob).decode("ascii").rstrip("=")


def decode_vpn(text: str) -> dict:
    """Inverse of encode_vpn (used by tests)."""
    tok = text[text.find("vpn://") + len("vpn://"):].strip()
    s = tok.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    b = base64.b64decode(s)
    for attempt in (b[4:], b):
        try:
            return json.loads(zlib.decompress(attempt))
        except Exception:
            continue
    raise AWGError("decode_vpn failed")


def client_conf_from_vpn(
    vpn_string: str, dns1: str = DEFAULT_DNS1, dns2: str = DEFAULT_DNS2,
) -> str:
    """Render a WireGuard-style AmneziaWG `.conf` from a stored `vpn://` string.

    Some clients import a plain `.conf` instead of the AmneziaVPN `vpn://` — most
    notably the **iOS AmneziaWG app** (same shape as WireGuard, plus the AmneziaWG
    obfuscation set in [Interface]). We pull the client key/IP, the server identity
    and the FULL obfuscation set straight out of the `vpn://`, so the `.conf`
    authenticates against the very same pool the device already has. Empty params
    (I1..I5) are omitted; the AWG 2.0 set (S1..S4, H1..H4 — including H *ranges*) is
    carried verbatim, because both ends must agree on it for the handshake to work."""
    doc = decode_vpn(vpn_string)
    try:
        awg = doc["containers"][0]["awg"]
        inner = json.loads(awg["last_config"])
    except (KeyError, IndexError, ValueError, TypeError) as e:
        raise AWGError(f"cannot read vpn:// for .conf export: {e}")

    def g(key: str) -> str:
        v = inner.get(key)
        if v in (None, ""):
            v = awg.get(key, "")
        return str(v) if v not in (None, "") else ""

    priv = g("client_priv_key")
    if not priv:
        raise AWGError("vpn:// carries no client private key")
    endpoint_host = g("hostName")
    port = g("port")

    lines = [
        "[Interface]",
        f"Address = {g('client_ip')}/32",
        f"DNS = {dns1}, {dns2}",
        f"MTU = {g('mtu') or DEFAULT_MTU}",
        f"PrivateKey = {priv}",
    ]
    for k in PARAM_ORDER:  # Jc,Jmin,Jmax,S1..S4,H1..H4,I1..I5 — skip empties
        v = g(k)
        if v:
            lines.append(f"{k} = {v}")
    lines += [
        "",
        "[Peer]",
        f"PublicKey = {g('server_pub_key')}",
        f"PresharedKey = {g('psk_key')}",
        "AllowedIPs = 0.0.0.0/0, ::/0",
        f"Endpoint = {endpoint_host}:{port}",
        "PersistentKeepalive = 25",
    ]
    return "\n".join(lines) + "\n"


class AWGManager:
    def __init__(self, node: SSHNode, container: str | None = None, conf_dir: str = DEFAULT_CONF_DIR):
        self.node = node
        self.container = container
        self.conf_dir = conf_dir.rstrip("/")

    # --- shell helpers ---------------------------------------------------
    def _run(self, cmd: str, timeout: int = 60) -> str:
        rc, out, err = self.node.run(cmd, timeout=timeout)
        if rc != 0:
            raise AWGError(f"cmd failed (rc={rc}): {cmd}\n{err or out}")
        return out

    def _dexec(self, argv: str, timeout: int = 60) -> str:
        return self._run(f"docker exec {self.container} {argv}", timeout=timeout)

    def _read_container_file(self, path: str) -> str:
        return self._dexec(f"cat {path}")

    def _write_container_file(self, path: str, content: str) -> None:
        b64 = base64.b64encode(content.encode("utf-8")).decode()
        tmp = f"{path}.panel.tmp"
        cmd = (
            f"printf '%s' '{b64}' | base64 -d | "
            f"docker exec -i {self.container} sh -c 'cat > {tmp} && mv {tmp} {path}'"
        )
        self._run(cmd)

    # --- discovery -------------------------------------------------------
    def discover_container(self) -> str:
        if self.container:
            return self.container
        out = self._run("docker ps --format '{{.Names}}\\t{{.Image}}'")
        for line in out.splitlines():
            if not line.strip():
                continue
            name, _, image = line.partition("\t")
            if "amneziawg" in image.lower() or "awg" in name.lower() or "amnezia" in name.lower():
                self.container = name.strip()
                return self.container
        raise AWGError("no AmneziaWG container found (docker ps)")

    @property
    def conf_path(self) -> str:
        return f"{self.conf_dir}/awg0.conf"

    # --- read server state ----------------------------------------------
    def read_server(self) -> AWGServer:
        self.discover_container()
        conf = self._read_container_file(self.conf_path)
        pubkey = self._read_container_file(f"{self.conf_dir}/wireguard_server_public_key.key").strip()
        psk = self._read_container_file(f"{self.conf_dir}/wireguard_psk.key").strip()

        params: dict = {}
        listen_port = 0
        subnet_prefix = ""
        cidr = 24
        used: set[int] = set()
        section = None

        for raw in conf.splitlines():
            line = raw.strip()
            if not line:
                continue
            # obfuscation I-params may be commented out but are still needed
            candidate = line.lstrip("#").strip() if line.startswith("#") else line
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1].lower()
                continue
            if "=" not in candidate:
                continue
            key, _, val = candidate.partition("=")
            key = key.strip()
            val = val.strip()
            if section == "interface":
                if key in _PARAM_SET:
                    params[key] = val
                elif key == "ListenPort" and not line.startswith("#"):
                    listen_port = int(val)
                elif key == "Address" and not line.startswith("#"):
                    addr = val.split("/")[0]
                    octets = addr.split(".")
                    subnet_prefix = ".".join(octets[:3])
                    cidr = int(val.split("/")[1]) if "/" in val else 24
            elif section == "peer" and key == "AllowedIPs" and not line.startswith("#"):
                for ip in val.split(","):
                    parts = ip.strip().split("/")[0].split(".")
                    if len(parts) == 4 and ".".join(parts[:3]) == subnet_prefix:
                        used.add(int(parts[3]))

        if not subnet_prefix or not listen_port:
            raise AWGError("could not parse Address/ListenPort from server config")

        return AWGServer(
            container=self.container,
            conf_path=self.conf_path,
            interface="awg0",
            server_pubkey=pubkey,
            psk=psk,
            psk_path=f"{self.conf_dir}/wireguard_psk.key",
            listen_port=listen_port,
            subnet_prefix=subnet_prefix,
            cidr=cidr,
            params=params,
            used_hosts=used,
        )

    @staticmethod
    def next_free_host(server: AWGServer) -> int:
        for h in range(1, 255):
            if h not in server.used_hosts:
                return h
        raise AWGError("address pool exhausted")

    # --- mutate ----------------------------------------------------------
    def add_peer(self, name: str, endpoint_host: str, description: str | None = None,
                 dns1: str = DEFAULT_DNS1, dns2: str = DEFAULT_DNS2) -> dict:
        """Create a client peer; return {vpn, public_key, address, name}.
        `vpn` is the AmneziaVPN-app `vpn://` config string."""
        server = self.read_server()
        host = self.next_free_host(server)
        address = f"{server.subnet_prefix}.{host}"
        priv, pub = gen_keypair()

        # 1) apply live (no interface restart)
        self._dexec(
            f"awg set {server.interface} peer {pub} "
            f"preshared-key {server.psk_path} allowed-ips {address}/32"
        )
        # 2) persist to awg0.conf so it survives container restart
        peer_block = f"\n[Peer]\nPublicKey = {pub}\nPresharedKey = {server.psk}\nAllowedIPs = {address}/32\n"
        conf = self._read_container_file(server.conf_path)
        if not conf.endswith("\n"):
            conf += "\n"
        self._write_container_file(server.conf_path, conf + peer_block)
        # 3) keep Amnezia's clientsTable in sync (best effort)
        self._add_to_clients_table(pub, name, address)

        doc = build_amnezia_dict(server, priv, pub, address, endpoint_host,
                                 description or name, dns1, dns2)
        return {"vpn": encode_vpn(doc), "public_key": pub, "address": f"{address}/32", "name": name}

    def del_peer(self, public_key: str) -> None:
        server = self.read_server()
        self._dexec(f"awg set {server.interface} peer {public_key} remove")
        conf = self._read_container_file(server.conf_path)
        self._write_container_file(server.conf_path, _remove_peer_block(conf, public_key))
        self._remove_from_clients_table(public_key)

    # --- pool reconcile primitives --------------------------------------
    def list_peers(self) -> list[tuple[str, str]]:
        """[(public_key, address)] for every [Peer] in awg0.conf. Used to diff an
        exit against the pool's desired peer set during reconcile."""
        self.discover_container()
        conf = self._read_container_file(self.conf_path)
        peers: list[tuple[str, str]] = []
        for block in re.split(r"(?m)^(?=\[Peer\])", conf):
            if not block.lstrip().startswith("[Peer]"):
                continue
            pub = ""
            addr = ""
            for line in block.splitlines():
                s = line.strip()
                if s.startswith("PublicKey"):
                    pub = s.split("=", 1)[1].strip()
                elif s.startswith("AllowedIPs"):
                    addr = s.split("=", 1)[1].strip().split(",")[0].split("/")[0].strip()
            if pub:
                peers.append((pub, addr))
        return peers

    def upsert_peer(self, pub: str, address: str, name: str = "") -> None:
        """Idempotently ensure peer `pub` -> `address` exists on this node: apply
        live (no interface restart) and persist to awg0.conf. Replacing any stale
        block for the same pub. This is how the pool pushes one client to every
        cloned exit; the keypair/address are generated once at pool level."""
        server = self.read_server()
        addr = address.split("/")[0]
        self._dexec(
            f"awg set {server.interface} peer {pub} "
            f"preshared-key {server.psk_path} allowed-ips {addr}/32"
        )
        conf = _remove_peer_block(self._read_container_file(server.conf_path), pub)
        if not conf.endswith("\n"):
            conf += "\n"
        conf += f"\n[Peer]\nPublicKey = {pub}\nPresharedKey = {server.psk}\nAllowedIPs = {addr}/32\n"
        self._write_container_file(server.conf_path, conf)
        self._remove_from_clients_table(pub)
        self._add_to_clients_table(pub, name or pub[:8], addr)

    # --- clientsTable (Amnezia UI metadata) ------------------------------
    def _clients_table_path(self) -> str:
        return f"{self.conf_dir}/clientsTable"

    def _add_to_clients_table(self, pub: str, name: str, address: str) -> None:
        try:
            raw = self._read_container_file(self._clients_table_path())
            table = json.loads(raw) if raw.strip() else []
            table.append({"clientId": pub, "userData": {"clientName": name, "allowedIps": f"{address}/32"}})
            self._write_container_file(self._clients_table_path(), json.dumps(table, indent=4))
        except Exception:
            pass  # connectivity doesn't depend on it

    def _remove_from_clients_table(self, pub: str) -> None:
        try:
            raw = self._read_container_file(self._clients_table_path())
            table = json.loads(raw) if raw.strip() else []
            table = [e for e in table if e.get("clientId") != pub]
            self._write_container_file(self._clients_table_path(), json.dumps(table, indent=4))
        except Exception:
            pass


def _remove_peer_block(conf: str, public_key: str) -> str:
    blocks = re.split(r"(?m)^(?=\[Peer\])", conf)
    return "".join(b for b in blocks if not (b.lstrip().startswith("[Peer]") and public_key in b))
