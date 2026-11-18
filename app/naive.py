"""NaiveProxy servers: Caddy + the naive fork of forwardproxy, managed by the panel.

NaiveProxy's client is Chromium's own network stack, so its TLS (and HTTP/2) look
exactly like Chrome talking to a website — no uTLS imitation. The server is a
real web server: Caddy serving a placeholder site, with a forward proxy that
answers only to authenticated clients (`probe_resistance`: anyone else just sees
the site). HTTP/2 only — no QUIC, so nothing UDP on the way in.

Per server pool (clones, like the other protocols):
  * every server runs the same Caddy (container `vespn-naive`, host network, :443),
    built ON the server with xcaddy (no prebuilt image to trust or pin);
  * one site on :443 (NOT bound to a hostname: a proxy request's Host is its
    target) serving every NaiveProxy route of the pool; each route's domain has
    its certificate, picked by SNI — issued on the Hub by DNS-01 (app/acme.py)
    and pushed here, so the zone token never leaves the Hub;
  * the same user list on every server: one login/password per device whose owner
    may use a NaiveProxy route on the pool (password stored encrypted in the DB).
"""

from __future__ import annotations

import logging
import secrets
import shlex
import string
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from sqlalchemy.orm import Session

from .config import settings
from .models import PROTO_NAIVE, ExitPool, NaiveCert, RouteProto
from .node_ssh import SSHNode
from .provisioning import ProvisionError, _put_file, install_docker

log = logging.getLogger("vpnpanel.naive")

CONTAINER = "vespn-naive"
BASE = "/opt/vespn-naive"
SERVER_PORT = 443
RENEW_BEFORE = timedelta(days=30)

_SITE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Welcome</title>
<style>body{font:16px/1.6 system-ui,sans-serif;max-width:40rem;margin:12vh auto;padding:0 1rem;color:#333}</style>
</head><body><h1>Welcome</h1><p>This site is under construction. Please check back later.</p></body></html>
"""


def new_password() -> str:
    alphabet = string.ascii_letters + string.digits  # nothing that needs escaping anywhere
    return "".join(secrets.choice(alphabet) for _ in range(24))


def image_tag() -> str:
    ref = "".join(ch if ch.isalnum() else "-" for ch in settings.naive_forwardproxy_ref)
    return f"vespn-naive:{ref}"


# --- links --------------------------------------------------------------
def link(user: str, password: str, host: str, port: int, label: str = "") -> str:
    """naive+https:// share link (the host is also the TLS SNI, so: the domain)."""
    frag = f"#{quote(label, safe='-_.')}" if label else ""
    return f"naive+https://{quote(user, safe='')}:{quote(password, safe='')}@{host}:{int(port)}{frag}"


def singbox_outbound(tag: str, user: str, password: str, host: str, port: int, sni: str) -> dict:
    """sing-box `naive` outbound — may dial a gate IP while presenting the domain."""
    return {
        "type": "naive", "tag": tag, "server": host, "server_port": int(port),
        "username": user, "password": password,
        "tls": {"enabled": True, "server_name": sni},
    }


# --- certificates -------------------------------------------------------
def cert_for(db: Session, domain: str) -> NaiveCert | None:
    return db.get(NaiveCert, domain.lower()) if domain else None


def needs_cert(db: Session, domain: str) -> bool:
    c = cert_for(db, domain)
    if c is None:
        return True
    exp = c.not_after if c.not_after.tzinfo else c.not_after.replace(tzinfo=timezone.utc)
    return exp - datetime.now(timezone.utc) < RENEW_BEFORE


def ensure_cert(db: Session, rp: RouteProto, force: bool = False) -> NaiveCert:
    """Certificate of a route's NaiveProxy hostname (`rp` = the route's NaiveProxy
    protocol), issuing/renewing it on the Hub if missing or due."""
    from . import acme

    name = rp.route.name
    domain = (rp.client_host or "").lower()
    if not domain:
        raise ProvisionError(f"у NaiveProxy маршрута «{name}» нет имени хоста — не на что выпускать сертификат")
    if rp.dns_provider is None:
        raise ProvisionError(
            f"у NaiveProxy маршрута «{name}» не выбран DNS-провайдер — сертификат выпускается через DNS-01"
        )
    if not force and not needs_cert(db, domain):
        return cert_for(db, domain)
    cert_pem, key_pem = acme.issue(db, rp.dns_provider, domain)
    row = cert_for(db, domain) or NaiveCert(domain=domain, cert_pem="", key_enc="",
                                            not_after=datetime.now(timezone.utc))
    row.cert_pem = cert_pem
    row.key_pem = key_pem
    row.not_after = acme.not_after(cert_pem)
    row.updated_at = datetime.now(timezone.utc)
    db.merge(row)
    db.commit()
    return cert_for(db, domain)


# --- desired state ------------------------------------------------------
def pool_routes(pool: ExitPool) -> list[RouteProto]:
    """NaiveProxy protocols (with a hostname) of the routes on the pool."""
    out = []
    for r in pool.routes:
        rp = r.proto(PROTO_NAIVE)
        if rp is not None and rp.client_host:
            out.append(rp)
    return out


def pool_users(db: Session, pool: ExitPool, exclude: set[int] | None = None) -> list[tuple[str, str]]:
    """(login, password) of every NaiveProxy client that must exist on the pool."""
    from .pool import pool_proto_configs

    out = []
    for c in pool_proto_configs(db, pool, PROTO_NAIVE):
        if exclude and c.id in exclude:
            continue
        pw = c.secret
        if c.identifier and pw:
            out.append((c.identifier, pw))
    return out


def render_caddyfile(domains: list[str], users: list[tuple[str, str]]) -> str:
    """Caddyfile: ONE site on :443 for all of the pool's domains, the same users.

    The site must not be bound to a hostname: a proxy request's Host is its TARGET
    (e.g. example.com:443), so a `https://<domain>` site (= a Host matcher) would
    never see it and the proxy would silently not work. The certificates — one
    PEM bundle per domain in /data/certs — are loaded as a folder; Caddy picks the
    one matching the TLS SNI. Never an open proxy: with no users a random
    throwaway account is put in."""
    if not users:
        users = [(f"x{secrets.token_hex(6)}", new_password())]
    auth = "\n".join(f"\t\tbasic_auth {u} {p}" for u, p in users)
    out = [
        "{",
        "\tadmin localhost:2019",
        "\tauto_https off",
        "\tservers {",
        "\t\tprotocols h1 h2",  # no HTTP/3: nothing UDP
        "\t}",
        "\torder forward_proxy before file_server",
        "}",
        "",
        f"# domains: {', '.join(domains)}",
        f":{SERVER_PORT} {{",
        "\ttls {",
        "\t\tload /data/certs",
        "\t}",
        "\tforward_proxy {",
        auth,
        "\t\thide_ip",
        "\t\thide_via",
        "\t\tprobe_resistance",
        "\t}",
        "\tfile_server {",
        "\t\troot /srv/site",
        "\t}",
        "}",
        "",
    ]
    return "\n".join(out)


# --- server side --------------------------------------------------------
_DOCKERFILE = """FROM {builder} AS build
RUN xcaddy build --with github.com/caddyserver/forwardproxy=github.com/klzgrad/forwardproxy@{ref}
FROM {runtime}
COPY --from=build /usr/bin/caddy /usr/bin/caddy
"""


def present(node: SSHNode) -> bool:
    rc, out, _ = node.run(f"docker ps -a --format '{{{{.Names}}}}' | grep -x {CONTAINER}", timeout=20)
    return rc == 0 and out.strip() == CONTAINER


def _write_config(node: SSHNode, db: Session, pool: ExitPool, exclude: set[int] | None) -> list[str]:
    """Write Caddyfile, certificates and the site; returns the domains served."""
    domains = []
    # Rewritten from scratch each time, so a removed route's domain goes away too.
    node.run(f"mkdir -p {BASE}/certs {BASE}/site && chmod 700 {BASE}/certs && rm -f {BASE}/certs/*",
             timeout=20)
    for r in pool_routes(pool):
        c = cert_for(db, r.client_host)
        if c is None:
            log.warning("naive: no certificate for %s yet — domain skipped", r.client_host)
            continue
        d = r.client_host.lower()
        # one PEM bundle per domain (cert chain + key) — what `tls { load <dir> }` reads
        _put_file(node, f"{BASE}/certs/{d}.pem", c.cert_pem.rstrip() + "\n" + c.key_pem)
        domains.append(d)
    if not domains:
        raise ProvisionError(
            f"у пула «{pool.name}» нет NaiveProxy-маршрута с выпущенным сертификатом — "
            f"задайте имя хоста и DNS-провайдер маршрута и выпустите сертификат"
        )
    node.run(f"chmod 600 {BASE}/certs/*.pem", timeout=20)
    _put_file(node, f"{BASE}/site/index.html", _SITE)
    _put_file(node, f"{BASE}/Caddyfile", render_caddyfile(domains, pool_users(db, pool, exclude)))
    return domains


def install(node: SSHNode, db: Session, pool: ExitPool) -> dict:
    """Build the image on the server (once per fork ref) and run the container."""
    install_docker(node)
    tag = image_tag()
    rc, _, _ = node.run(f"docker image inspect {shlex.quote(tag)} >/dev/null 2>&1", timeout=30)
    if rc != 0:
        _put_file(node, f"{BASE}/build/Dockerfile", _DOCKERFILE.format(
            builder=settings.naive_builder_image, runtime=settings.naive_runtime_image,
            ref=settings.naive_forwardproxy_ref))
        rc, out, err = node.run(f"docker build -t {shlex.quote(tag)} {BASE}/build 2>&1 | tail -20",
                                timeout=1800)
        rc2, _, _ = node.run(f"docker image inspect {shlex.quote(tag)} >/dev/null 2>&1", timeout=30)
        if rc2 != 0:
            raise ProvisionError(f"сборка Caddy с naive не удалась:\n{(out or err)[-800:]}")
    domains = _write_config(node, db, pool, None)
    node.run(f"docker rm -f {CONTAINER} 2>/dev/null; true", timeout=40)
    rc, out, err = node.run(
        f"docker run -d --name {CONTAINER} --restart always --network host "
        f"-v {BASE}/Caddyfile:/etc/caddy/Caddyfile:ro -v {BASE}/certs:/data/certs:ro "
        f"-v {BASE}/site:/srv/site:ro {shlex.quote(tag)} "
        f"caddy run --config /etc/caddy/Caddyfile --adapter caddyfile",
        timeout=120,
    )
    if rc != 0:
        raise ProvisionError(f"docker run (naive) failed:\n{(err or out)[-600:]}")
    node.run("sleep 3", timeout=10)
    _rc, st, _ = node.run(f"docker ps --filter name={CONTAINER} --format '{{{{.Status}}}}'", timeout=15)
    if not st.strip():
        _rc, logs, _ = node.run(f"docker logs {CONTAINER} 2>&1 | tail -20", timeout=20)
        raise ProvisionError(f"Caddy (naive) не запустился:\n{logs[-800:]}")
    return {"domains": domains, "status": st.strip()}


def sync(node: SSHNode, db: Session, pool: ExitPool, exclude: set[int] | None = None) -> None:
    """Bring a running server's users/certs/sites to the pool's state (reload,
    no restart: connections stay up)."""
    if not present(node):
        install(node, db, pool)
        return
    _write_config(node, db, pool, exclude)
    rc, out, err = node.run(
        f"docker exec {CONTAINER} caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1",
        timeout=60,
    )
    if rc != 0:
        raise ProvisionError(f"caddy reload (naive) failed:\n{(out or err)[-600:]}")


def push_pool(db: Session, pool: ExitPool, exclude: set[int] | None = None) -> tuple[int, list[str]]:
    """sync() every member of the pool; returns (ok_count, errors). Never raises."""
    from .nodes import connect

    ok, errors = 0, []
    for m in pool.members:
        try:
            with connect(m) as n:
                sync(n, db, pool, exclude)
            ok += 1
        except Exception as e:
            errors.append(f"{m.name}: {e}")
            log.warning("naive push to %s failed: %s", m.name, e)
    return ok, errors


def renew_all(db: Session) -> list[str]:
    """Daily: renew certificates that are due and push them. Returns messages."""
    msgs = []
    for r in db.query(RouteProto).filter(RouteProto.protocol == PROTO_NAIVE).all():
        if not r.client_host or r.dns_provider is None or r.route.pool is None:
            continue
        if not needs_cert(db, r.client_host):
            continue
        try:
            ensure_cert(db, r)
            ok, errs = push_pool(db, r.route.pool)
            msgs.append(f"{r.client_host}: сертификат обновлён, разослан на {ok} серв."
                        + (f"; ошибки: {'; '.join(errs)}" if errs else ""))
        except Exception as e:
            msgs.append(f"{r.client_host}: не удалось обновить сертификат: {e}")
            log.warning("naive: renew %s failed: %s", r.client_host, e)
    return msgs
