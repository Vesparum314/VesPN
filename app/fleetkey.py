"""The fleet SSH key: ONE Ed25519 keypair the panel uses to log into every node.

Generated once, on the Hub, on first use, and stored ENCRYPTED in the panel DB
(same at-rest protection as node SSH passwords — the Fernet key is derived from
PANEL_SECRET_KEY). The private key never leaves the Hub; its public part is
installed into each node's root authorized_keys during provisioning
(`provisioning.install_fleet_key`), after which the panel manages the node by key
and the bootstrap password is no longer needed.

Nothing is hard-coded: the keypair is created by the Hub itself, so a fresh Hub
mints its own fleet identity. Losing the DB loses the key — restore from the
usual backup (DB + PANEL_SECRET_KEY) to get it back.
"""

from __future__ import annotations

import base64
import hashlib
import io
import threading

import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy.orm import Session

from .crypto import decrypt, encrypt
from .models import Setting

_SETTING_KEY = "fleet_ssh_key"  # Setting row holding the encrypted OpenSSH private key (PEM)
_COMMENT = "vespn-fleet"
_gen_lock = threading.Lock()
_key_cache: dict[str, paramiko.Ed25519Key] = {}  # PEM -> parsed key (avoid reparsing per connect)


def _generate_pem() -> str:
    """Mint a new Ed25519 private key in OpenSSH format (the only private-key
    format paramiko's Ed25519Key can load)."""
    priv = ed25519.Ed25519PrivateKey.generate()
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def _load(pem: str) -> paramiko.Ed25519Key:
    k = _key_cache.get(pem)
    if k is None:
        k = paramiko.Ed25519Key.from_private_key(io.StringIO(pem))
        _key_cache[pem] = k
    return k


def get_pem(db: Session, create: bool = True) -> str | None:
    """Return the fleet private key (OpenSSH PEM). Generates and persists it
    (encrypted) on first use when `create` is True; returns None if absent and
    `create` is False (then callers fall back to password auth)."""
    row = db.get(Setting, _SETTING_KEY)
    pem = decrypt(row.value) if row and row.value else None
    if pem or not create:
        return pem
    with _gen_lock:
        # re-check inside the lock: another thread may have created it
        row = db.get(Setting, _SETTING_KEY)
        pem = decrypt(row.value) if row and row.value else None
        if pem:
            return pem
        pem = _generate_pem()
        enc = encrypt(pem)
        if row is None:
            db.add(Setting(key=_SETTING_KEY, value=enc))
        else:
            row.value = enc
        db.commit()
        return pem


def pkey(db: Session) -> paramiko.Ed25519Key | None:
    """The fleet key as a paramiko key for SSH auth, or None if not minted yet
    (read-only: never generates, so management/monitor paths stay side-effect free
    and simply fall back to the node password)."""
    pem = get_pem(db, create=False)
    return _load(pem) if pem else None


def public_line(db: Session) -> str:
    """The `ssh-ed25519 AAAA... vespn-fleet` line to drop into authorized_keys.
    Ensures the key exists (used by provisioning and the UI)."""
    k = _load(get_pem(db, create=True))
    return f"{k.get_name()} {k.get_base64()} {_COMMENT}"


def fingerprint(db: Session) -> str:
    """OpenSSH-style SHA256 fingerprint (for display)."""
    k = _load(get_pem(db, create=True))
    raw = base64.b64decode(k.get_base64())
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
