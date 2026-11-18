"""Minimal ACME v2 client (RFC 8555), DNS-01 only — certificates issued ON THE HUB.

NaiveProxy needs a real certificate for its domain on every server of the pool.
Clients reach the servers through gates (the domain resolves to the gates), so
an HTTP/TLS-ALPN challenge would land on whichever server a gate picks — no good
for a pool. DNS-01 through the route's DNS provider works for any number of
servers, and the zone's API token never leaves the Hub: the panel gets the
certificate here and pushes it to the servers.

Only what's needed: ES256 account key (kept encrypted in settings), one order per
domain, dns-01 via app/dns.py TXT records, a P-256 certificate key.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import time

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID
from sqlalchemy.orm import Session

from .crypto import decrypt, encrypt
from .models import DnsProvider, Setting

log = logging.getLogger("vpnpanel.acme")

LETSENCRYPT = "https://acme-v02.api.letsencrypt.org/directory"
_ACCOUNT_KEY = "acme_account_key"
TIMEOUT = 30


class AcmeError(RuntimeError):
    pass


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _account_key(db: Session) -> ec.EllipticCurvePrivateKey:
    s = db.get(Setting, _ACCOUNT_KEY)
    if s and s.value:
        return serialization.load_pem_private_key(decrypt(s.value).encode(), password=None)
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    if s is None:
        db.add(Setting(key=_ACCOUNT_KEY, value=encrypt(pem)))
    else:
        s.value = encrypt(pem)
    db.commit()
    return key


def _jwk(key: ec.EllipticCurvePrivateKey) -> dict:
    nums = key.public_key().public_numbers()
    return {"crv": "P-256", "kty": "EC",
            "x": _b64(nums.x.to_bytes(32, "big")), "y": _b64(nums.y.to_bytes(32, "big"))}


def _thumbprint(jwk: dict) -> str:
    canon = json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")}, separators=(",", ":"), sort_keys=True)
    return _b64(hashlib.sha256(canon.encode()).digest())


class _Client:
    def __init__(self, db: Session, directory: str | None = None):
        from .config import settings

        directory = directory or settings.acme_directory
        self.key = _account_key(db)
        self.jwk = _jwk(self.key)
        self.dir = requests.get(directory, timeout=TIMEOUT).json()
        self.kid: str | None = None
        self.nonce: str | None = None

    def _nonce(self) -> str:
        if self.nonce:
            n, self.nonce = self.nonce, None
            return n
        return requests.head(self.dir["newNonce"], timeout=TIMEOUT).headers["Replay-Nonce"]

    def _sign(self, url: str, payload) -> dict:
        prot = {"alg": "ES256", "nonce": self._nonce(), "url": url}
        if self.kid:
            prot["kid"] = self.kid
        else:
            prot["jwk"] = self.jwk
        p64 = _b64(json.dumps(prot).encode())
        y64 = "" if payload is None else _b64(json.dumps(payload).encode())
        der = self.key.sign(f"{p64}.{y64}".encode(), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return {"protected": p64, "payload": y64,
                "signature": _b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))}

    def post(self, url: str, payload=None, retry: bool = True) -> requests.Response:
        """POST (payload None = POST-as-GET); retries once on a bad nonce."""
        r = requests.post(url, json=self._sign(url, payload), timeout=TIMEOUT,
                          headers={"Content-Type": "application/jose+json"})
        self.nonce = r.headers.get("Replay-Nonce")
        if r.status_code == 400 and retry and "badNonce" in r.text:
            return self.post(url, payload, retry=False)
        if r.status_code >= 400:
            raise AcmeError(f"ACME {url.rsplit('/', 1)[-1]}: HTTP {r.status_code} {r.text[:300]}")
        return r

    def account(self) -> None:
        r = self.post(self.dir["newAccount"], {"termsOfServiceAgreed": True})
        self.kid = r.headers["Location"]

    def poll(self, url: str, until: tuple[str, ...], tries: int = 40, delay: float = 3.0) -> dict:
        for _ in range(tries):
            obj = self.post(url).json()
            if obj.get("status") in until:
                return obj
            if obj.get("status") == "invalid":
                raise AcmeError(f"ACME: {json.dumps(obj)[:400]}")
            time.sleep(delay)
        raise AcmeError(f"ACME: timeout waiting for {until} at {url}")


def issue(db: Session, provider: DnsProvider, domain: str, propagation_wait: int = 60) -> tuple[str, str]:
    """Issue a certificate for `domain` via DNS-01 in `provider`'s zone. Returns
    (fullchain_pem, private_key_pem). Blocks for a minute or two."""
    from . import dns

    domain = domain.rstrip(".").lower()
    c = _Client(db)
    c.account()
    order_r = c.post(c.dir["newOrder"], {"identifiers": [{"type": "dns", "value": domain}]})
    order_url = order_r.headers["Location"]
    order = order_r.json()
    txt_name = f"_acme-challenge.{domain}"
    challenges = []
    try:
        for az_url in order["authorizations"]:
            az = c.post(az_url).json()
            if az.get("status") == "valid":
                continue
            ch = next((x for x in az["challenges"] if x["type"] == "dns-01"), None)
            if ch is None:
                raise AcmeError("ACME: no dns-01 challenge offered")
            key_auth = f"{ch['token']}.{_thumbprint(c.jwk)}"
            value = _b64(hashlib.sha256(key_auth.encode()).digest())
            dns.set_txt(provider, txt_name, value)
            challenges.append((ch["url"], az_url))
        if challenges:
            time.sleep(propagation_wait)  # let the TXT reach the authoritative servers
            for ch_url, az_url in challenges:
                c.post(ch_url, {})
                c.poll(az_url, ("valid",))
        key = ec.generate_private_key(ec.SECP256R1())
        csr = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
               .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
               .sign(key, hashes.SHA256()))
        c.post(order["finalize"], {"csr": _b64(csr.public_bytes(serialization.Encoding.DER))})
        done = c.poll(order_url, ("valid",))
        cert_pem = c.post(done["certificate"]).text
        key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()).decode()
        log.info("acme: issued certificate for %s", domain)
        return cert_pem, key_pem
    finally:
        if challenges:
            try:
                dns.clear_txt(provider, txt_name)
            except Exception as e:
                log.warning("acme: could not remove %s: %s", txt_name, e)


def not_after(cert_pem: str):
    """Expiry of the leaf certificate (aware datetime)."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    return cert.not_valid_after_utc
