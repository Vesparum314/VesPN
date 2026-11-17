"""Keep a route's client hostname pointed at its live entry points.

A route may carry `client_host` (the name in client configs) and a DNS provider
for the zone that name lives in. After every gate-journal cycle the panel puts
the IPs of the route's LIVE entry points into the name's A records — the gates of
its gate pool that the Hub still reaches, or (direct route) the pool's synced
servers. A banned gate thus drops out of DNS on its own and a new one comes in,
and clients (whose config only names the host) follow without a new config.

Never empties a name: if no entry point counts as alive, all of them stay — a
wrong guess about liveness must not take the route off the air. Providers are
called only when the wanted set differs from what was last pushed (or every few
hours, to heal manual edits). Supported: Cloudflare, deSEC, dynv6.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from datetime import datetime, timedelta, timezone

import requests
from sqlalchemy.orm import Session

from .models import DNS_CLOUDFLARE, DNS_DESEC, DNS_DYNV6, DnsProvider, Route, Setting

log = logging.getLogger("vpnpanel.dns")

TTL = 60
TIMEOUT = 20
RESYNC = timedelta(hours=6)


class DnsError(RuntimeError):
    pass


def _check(resp: requests.Response, what: str) -> requests.Response:
    if resp.status_code >= 400:
        raise DnsError(f"{what}: HTTP {resp.status_code} {resp.text[:200]}")
    return resp


def _subname(fqdn: str, zone: str) -> str:
    fqdn, zone = fqdn.rstrip(".").lower(), zone.rstrip(".").lower()
    if fqdn == zone:
        return ""
    if not fqdn.endswith("." + zone):
        raise DnsError(f"имя {fqdn} не в зоне {zone}")
    return fqdn[: -len(zone) - 1]


# --- providers ------------------------------------------------------------
def _cloudflare(p: DnsProvider, fqdn: str, ips: list[str]) -> None:
    api = "https://api.cloudflare.com/client/v4"
    h = {"Authorization": f"Bearer {p.token}", "Content-Type": "application/json"}
    z = _check(requests.get(f"{api}/zones", params={"name": p.zone}, headers=h, timeout=TIMEOUT),
               "cloudflare zones").json().get("result") or []
    if not z:
        raise DnsError(f"зона {p.zone} не найдена в Cloudflare (или нет доступа у токена)")
    zid = z[0]["id"]
    have = _check(requests.get(f"{api}/zones/{zid}/dns_records",
                               params={"type": "A", "name": fqdn, "per_page": 100},
                               headers=h, timeout=TIMEOUT), "cloudflare records").json().get("result") or []
    have_ips = {r["content"]: r["id"] for r in have}
    for ip in ips:
        if ip not in have_ips:
            _check(requests.post(f"{api}/zones/{zid}/dns_records", headers=h, timeout=TIMEOUT,
                                 json={"type": "A", "name": fqdn, "content": ip, "ttl": TTL,
                                       "proxied": False}), "cloudflare create")
    for ip, rid in have_ips.items():
        if ip not in ips:
            _check(requests.delete(f"{api}/zones/{zid}/dns_records/{rid}", headers=h, timeout=TIMEOUT),
                   "cloudflare delete")


def _desec(p: DnsProvider, fqdn: str, ips: list[str]) -> None:
    api = f"https://desec.io/api/v1/domains/{p.zone.rstrip('.')}"
    h = {"Authorization": f"Token {p.token}", "Content-Type": "application/json"}
    dom = _check(requests.get(f"{api}/", headers=h, timeout=TIMEOUT), "desec domain").json()
    ttl = max(TTL, int(dom.get("minimum_ttl") or TTL))
    body = [{"subname": _subname(fqdn, p.zone), "type": "A", "ttl": ttl, "records": ips}]
    # Bulk PATCH creates the RRset if missing and replaces its records otherwise.
    _check(requests.patch(f"{api}/rrsets/", headers=h, data=json.dumps(body), timeout=TIMEOUT),
           "desec rrset")


def _dynv6(p: DnsProvider, fqdn: str, ips: list[str]) -> None:
    api = "https://dynv6.com/api/v2"
    h = {"Authorization": f"Bearer {p.token}", "Accept": "application/json"}
    zone = _check(requests.get(f"{api}/zones/by-name/{p.zone.rstrip('.')}", headers=h, timeout=TIMEOUT),
                  "dynv6 zone").json()
    zid = zone["id"]
    sub = _subname(fqdn, p.zone)
    if sub == "":
        # The zone apex holds a single IPv4 in dynv6 — use the preferred entry point.
        _check(requests.patch(f"{api}/zones/{zid}", headers=h, json={"ipv4address": ips[0]},
                              timeout=TIMEOUT), "dynv6 apex")
        return
    recs = _check(requests.get(f"{api}/zones/{zid}/records", headers=h, timeout=TIMEOUT),
                  "dynv6 records").json()
    have = {r["data"]: r["id"] for r in recs if r.get("type") == "A" and r.get("name") == sub}
    for ip in ips:
        if ip not in have:
            _check(requests.post(f"{api}/zones/{zid}/records", headers=h, timeout=TIMEOUT,
                                 json={"type": "A", "name": sub, "data": ip}), "dynv6 create")
    for ip, rid in have.items():
        if ip not in ips:
            _check(requests.delete(f"{api}/zones/{zid}/records/{rid}", headers=h, timeout=TIMEOUT),
                   "dynv6 delete")


_PROVIDERS = {DNS_CLOUDFLARE: _cloudflare, DNS_DESEC: _desec, DNS_DYNV6: _dynv6}


def set_a_records(p: DnsProvider, fqdn: str, ips: list[str]) -> None:
    if not ips:
        raise DnsError("нечего публиковать: нет IP")
    fn = _PROVIDERS.get(p.kind)
    if fn is None:
        raise DnsError(f"неизвестный DNS-провайдер {p.kind}")
    _subname(fqdn, p.zone)  # validates the name is in the zone
    fn(p, fqdn.rstrip(".").lower(), ips)


# --- route sync -------------------------------------------------------------
def _is_ipv4(s: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(s), ipaddress.IPv4Address)
    except ValueError:
        return False


def wanted_ips(route: Route, live_gates: set[int]) -> list[str]:
    """IPs the route's hostname should resolve to right now."""
    if route.is_direct:
        servers = route.entry_points
        pick = [n for n in servers if n.is_synced] or servers
    else:
        gates = route.gates
        pick = [g for g in gates if g.id in live_gates] or gates  # never empty the name
    return sorted({n.public_host for n in pick if _is_ipv4(n.public_host)})


def _state_key(route_id: int) -> str:
    return f"dns_route_{route_id}"


def get_state(db: Session, route_id: int) -> dict:
    s = db.get(Setting, _state_key(route_id))
    try:
        return json.loads(s.value) if s and s.value else {}
    except ValueError:
        return {}


def _put_state(db: Session, route_id: int, state: dict) -> None:
    s = db.get(Setting, _state_key(route_id))
    if s is None:
        db.add(Setting(key=_state_key(route_id), value=json.dumps(state)))
    else:
        s.value = json.dumps(state)
    db.commit()


def sync_route(db: Session, route: Route, live_gates: set[int], force: bool = False) -> dict:
    """Push the route's wanted A records if they changed (or force). Returns the
    stored state: {"ips", "at", "error"}."""
    p = route.dns_provider
    if p is None or not route.client_host:
        return {}
    ips = wanted_ips(route, live_gates)
    st = get_state(db, route.id)
    now = datetime.now(timezone.utc)
    fresh = False
    try:
        fresh = now - datetime.fromisoformat(st.get("at", "")) < RESYNC
    except ValueError:
        pass
    if not force and st.get("ips") == ips and not st.get("error") and fresh:
        return st
    try:
        set_a_records(p, route.client_host, ips)
        st = {"ips": ips, "at": now.isoformat(timespec="seconds"), "error": ""}
        log.info("dns: %s -> %s", route.client_host, ", ".join(ips))
    except Exception as e:
        st = {"ips": st.get("ips", []), "at": st.get("at", ""), "error": str(e)[:300],
              "tried": now.isoformat(timespec="seconds")}
        log.warning("dns: %s failed: %s", route.client_host, e)
    _put_state(db, route.id, st)
    return st


def sync_routes(db: Session, live_gates: set[int]) -> None:
    for r in db.query(Route).filter(Route.dns_provider_id.isnot(None)).all():
        sync_route(db, r, live_gates)
