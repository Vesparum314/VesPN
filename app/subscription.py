"""Subscriptions: one URL per device, the list of ways in kept current by the panel.

A device's subscription lists every enabled VLESS route its owner may use (its
own route first), and for each route one entry per entry point:

  * «авто» — the route's managed hostname (A records = its live gates, see
    app/dns.py), when it has one: the client's core tries the addresses in turn,
    so a dead gate is skipped without the user doing anything;
  * one entry per gate by IP (or, for a direct route, per server) — a manual
    fallback when the name itself is blocked on the ISP's DNS.

The client app re-downloads it every SUB_UPDATE_HOURS, so gates joining or
leaving a route reach every device by themselves — no new config to hand out.

Formats (picked by the app's User-Agent, or ?format=):
  * `base64` — newline-separated vless:// links, base64'd (v2rayNG, OneXray,
    v2rayN, Happ … — the default);
  * `singbox` — sing-box JSON with a `urltest` group (Karing, sing-box, Hiddify):
    the app itself switches to a working entry. sing-box has no XHTTP, so only
    entries it can run go in; if none, the base64 list is served instead.

Security: the token is 192 random bits; unknown/revoked tokens get a bare 404
(the front proxy may replace it with the site's own 404 page); requests are
rate-limited per IP. Rotating the token revokes the old URL.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from collections import defaultdict, deque
from urllib.parse import quote

from sqlalchemy.orm import Session

from .models import PROTO_NAIVE, PROTO_VLESS, VLESS_TCP, Device, Route, TrafficStat

FORMAT_BASE64 = "base64"
FORMAT_SINGBOX = "singbox"
_SINGBOX_UA = ("karing", "sing-box", "singbox", "hiddify", "sfa", "sfi", "sfm", "nekobox")


# --- tokens -------------------------------------------------------------
def new_token() -> str:
    return secrets.token_urlsafe(24)  # 192 bits


def ensure_token(db: Session, device: Device) -> str:
    if not device.sub_token:
        device.sub_token = new_token()
        db.commit()
    return device.sub_token


def rotate_token(db: Session, device: Device) -> str:
    device.sub_token = new_token()
    db.commit()
    return device.sub_token


def device_by_token(db: Session, token: str) -> Device | None:
    if not token or len(token) < 16:
        return None
    return db.query(Device).filter(Device.sub_token == token).one_or_none()


def sub_url(device: Device, panel_base: str) -> str:
    from .config import settings

    base = settings.sub_base_url or panel_base.rstrip("/")
    return f"{base}/s/{device.sub_token}"


# --- rate limit ---------------------------------------------------------
_WINDOW, _LIMIT = 600, 120
_hits: dict[str, deque] = defaultdict(deque)


def allow(ip: str) -> bool:
    now = time.monotonic()
    dq = _hits[ip]
    while dq and now - dq[0] > _WINDOW:
        dq.popleft()
    if len(dq) >= _LIMIT:
        return False
    dq.append(now)
    if len(_hits) > 10000:  # keep memory bounded
        for k in [k for k, v in _hits.items() if not v or now - v[-1] > _WINDOW]:
            del _hits[k]
    return True


# --- entries ------------------------------------------------------------
def _routes_for(db: Session, device: Device) -> list[Route]:
    from .pool import user_proto_routes

    proto = device.protocol
    routes = [r for r in user_proto_routes(db, device.user, proto) if not r.proto_block_reason(proto)]
    own = device.route
    if own is not None and own.serves(proto) and own.pool is not None:
        routes = [own] + [r for r in routes if r.id != own.id]
    return routes


def entries(db: Session, device: Device) -> list[dict]:
    """[{label, route, proto, host, port, sni, link, …}] for the device. VLESS and
    NaiveProxy (AWG configs are static). A NaiveProxy entry by gate IP has no
    plain link (the link's host is also its SNI, which must be the domain) — it
    only goes into the sing-box format, which can dial an IP with a given SNI."""
    from . import naive
    from .pool import vless_link

    proto = device.protocol
    if proto not in (PROTO_VLESS, PROTO_NAIVE):
        return []
    cfg = next((c for c in device.configs if c.protocol == proto), None)
    if cfg is None or (proto == PROTO_VLESS and not cfg.uuid) or (proto == PROTO_NAIVE and not cfg.secret):
        return []
    out: list[dict] = []
    for r in _routes_for(db, device):
        port = r.port_for(proto)
        name = r.proto(proto).client_host
        hosts: list[tuple[str, str]] = []
        if name:
            hosts.append(("авто", name))
        for i, n in enumerate(r.entry_points, 1):
            if n.public_host and all(n.public_host != h for _, h in hosts):
                hosts.append((str(i), n.public_host))
        for tag, host in hosts:
            label = f"{r.name} · {tag}"
            item = {"label": label, "route": r, "proto": proto, "host": host, "port": port}
            if proto == PROTO_VLESS:
                item["uuid"] = cfg.uuid
                item["link"] = vless_link(r.pool, cfg.uuid, host, port, label)
            else:
                item.update(user=cfg.identifier, password=cfg.secret, sni=name,
                            link=naive.link(cfg.identifier, cfg.secret, host, port, label)
                            if host == name else None)
            out.append(item)
    return out


# --- formats ------------------------------------------------------------
def pick_format(user_agent: str, requested: str = "") -> str:
    if requested in (FORMAT_BASE64, FORMAT_SINGBOX):
        return requested
    ua = (user_agent or "").lower()
    return FORMAT_SINGBOX if any(k in ua for k in _SINGBOX_UA) else FORMAT_BASE64


def render_base64(items: list[dict]) -> str:
    return base64.b64encode("\n".join(i["link"] for i in items if i.get("link")).encode()).decode()


def _singbox_outbound(item: dict, uuid: str = "") -> dict | None:
    if item.get("proto") == "naive":
        from . import naive

        return naive.singbox_outbound(item["label"], item["user"], item["password"],
                                      item["host"], item["port"], item["sni"])
    uuid = item.get("uuid") or uuid
    pool = item["route"].pool
    if pool.vless_transport != VLESS_TCP:
        return None  # sing-box has no XHTTP
    from .models import reality_template

    return {
        "type": "vless", "tag": item["label"],
        "server": item["host"], "server_port": int(item["port"]),
        "uuid": uuid, "flow": pool.vless_flow,
        "tls": {
            "enabled": True, "server_name": pool.reality_sni,
            "utls": {"enabled": True, "fingerprint": reality_template()["fp"]},
            "reality": {"enabled": True, "public_key": pool.reality_public,
                        "short_id": (pool.short_ids or [""])[0]},
        },
    }


def render_singbox(items: list[dict], uuid: str = "") -> str | None:
    outs = [o for o in (_singbox_outbound(i, uuid) for i in items) if o]
    if not outs:
        return None
    tags = [o["tag"] for o in outs]
    conf = {
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto"] + tags, "default": "auto"},
            {"type": "urltest", "tag": "auto", "outbounds": tags,
             "url": "https://www.gstatic.com/generate_204", "interval": "3m", "tolerance": 100},
            *outs,
            {"type": "direct", "tag": "direct"},
        ],
        "route": {"final": "proxy"},
    }
    return json.dumps(conf, ensure_ascii=False, indent=1)


def headers(device: Device, db: Session, title: str, update_hours: int) -> dict[str, str]:
    """Profile metadata the apps understand (title, refresh period, usage)."""
    st = db.get(TrafficStat, device.id)
    up, down = (st.up_total, st.down_total) if st else (0, 0)
    t64 = base64.b64encode(title.encode()).decode()
    return {
        "profile-title": f"base64:{t64}",
        "profile-update-interval": str(max(1, int(update_hours))),
        "subscription-userinfo": f"upload={up}; download={down}; total=0; expire=0",
        "content-disposition": f"attachment; filename*=UTF-8''{quote(title)}",
        "cache-control": "no-store",
    }
