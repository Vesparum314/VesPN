"""FastAPI panel (server A): client self-service + admin node management."""

from __future__ import annotations

import base64
import io
import logging
import time
from pathlib import Path

import qrcode
from fastapi import Depends, FastAPI, Form, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import ChoiceLoader, FileSystemLoader
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware
from starlette.status import HTTP_303_SEE_OTHER

from . import appconfig
from . import dns as dns_ops
from . import fleetkey
from . import jobs
from . import monitor
from . import nodes as node_ops
from . import pool as pool_ops
from . import subscription as sub_ops
from . import traffic as traffic_ops
from .config import settings
from .db import get_db, init_db
from .node_ssh import forget_host_key
from .models import (
    ALL_PROTOCOLS,
    DEFAULT_CLIENT_PORT,
    DNS_KINDS,
    VLESS_TCP,
    VLESS_XHTTP,
    JOB_RUNNING,
    PROTO_AWG,
    PROTO_NAIVE,
    PROTO_VLESS,
    PROTOCOL_LABELS,
    PROTOCOLS,
    ROLE_ADMIN,
    ROLE_CLIENT,
    ROLE_EXIT,
    ROLE_GATE,
    ROLE_OPERATOR,
    ROLES,
    USER_ROLES,
    APP_PLATFORMS,
    Announcement,
    ClientApp,
    Device,
    DnsProvider,
    ExitPool,
    GatePool,
    Group,
    IssuedConfig,
    NaiveCert,
    Node,
    Route,
    RouteProto,
    Setting,
    TrafficStat,
    User,
)
from .ratelimit import login_throttle
from .security import (
    PASSWORD_RULES,
    current_user,
    hash_password,
    login_session,
    logout_session,
    password_problem,
    verify_password,
)

log = logging.getLogger("vpnpanel")
logging.basicConfig(level=logging.INFO)

BASE_DIR = Path(__file__).parent
# No /docs, /redoc, /openapi.json: a public map of every admin endpoint (and a page
# that names the product) only helps someone probing the panel.
app = FastAPI(title="panel", docs_url=None, redoc_url=None, openapi_url=None)


# Errors as bare status codes, not FastAPI's JSON ({"detail": ...} and, for a bad
# form, the list of expected field names) — that JSON fingerprints the framework.
@app.exception_handler(StarletteHTTPException)
async def _http_error(request: Request, exc: StarletteHTTPException):
    return Response(status_code=exc.status_code, headers=getattr(exc, "headers", None))


@app.exception_handler(RequestValidationError)
async def _validation_error(request: Request, exc: RequestValidationError):
    return Response(status_code=400)

_PW_EXEMPT = {"/login", "/logout", "/change-password", "/healthz"}

# --- optional theme (see config.theme_dir) ----------------------------------
THEME_DIR: Path | None = Path(settings.theme_dir) if settings.theme_dir else None
if THEME_DIR is not None and not THEME_DIR.is_dir():
    log.warning("THEME_DIR=%s is not a directory — using the stock look.", THEME_DIR)
    THEME_DIR = None
THEME_TEMPLATES = THEME_DIR / "templates" if THEME_DIR and (THEME_DIR / "templates").is_dir() else None
THEME_STATIC = THEME_DIR / "static" if THEME_DIR and (THEME_DIR / "static").is_dir() else None


async def _enforce_password_change(request: Request, call_next):
    """Users flagged must_change_password are pinned to /change-password."""
    path = request.url.path
    if path in _PW_EXEMPT or path.startswith(("/static", "/theme")):
        return await call_next(request)
    try:
        uid = request.session.get("uid")
    except Exception:
        uid = None
    if uid:
        from .db import SessionLocal

        db = SessionLocal()
        try:
            u = current_user(request, db)
            if u and u.must_change_password:
                return RedirectResponse("/change-password", status_code=HTTP_303_SEE_OTHER)
        finally:
            db.close()
    return await call_next(request)


# Added before SessionMiddleware so that one wraps this (request.session is ready
# by the time this inner middleware runs).
app.add_middleware(BaseHTTPMiddleware, dispatch=_enforce_password_change)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    session_cookie=settings.session_cookie,
    https_only=settings.session_https_only,
    same_site="lax",
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
if THEME_STATIC:
    app.mount("/theme", StaticFiles(directory=THEME_STATIC), name="theme")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
if THEME_TEMPLATES:
    # Theme templates win; anything the theme doesn't ship falls back to the stock ones.
    templates.env.loader = ChoiceLoader([FileSystemLoader(str(THEME_TEMPLATES)), templates.env.loader])
templates.env.globals["brand"] = settings.brand_name
templates.env.globals["theme_css"] = bool(THEME_STATIC and (THEME_STATIC / "theme.css").is_file())


def _asset_version() -> str:
    """Cache-busting token for CSS: the newest mtime of the stylesheet(s), read at
    startup. A deploy (or a theme `restart`) changes it, so the browser/Cloudflare
    fetch the fresh file instead of showing a stale one."""
    paths = [BASE_DIR / "static" / "style.css"]
    if THEME_STATIC:
        paths.append(THEME_STATIC / "theme.css")
    try:
        return str(int(max(p.stat().st_mtime for p in paths if p.exists())))
    except Exception:
        return str(int(time.time()))


templates.env.globals["asset_v"] = _asset_version()
if THEME_DIR:
    log.info("Theme: %s (templates=%s, theme.css=%s)", THEME_DIR, bool(THEME_TEMPLATES),
             templates.env.globals["theme_css"])


def _hbytes(n) -> str:
    """Human-readable byte size for templates (1536 -> '1.5 KB')."""
    try:
        v = float(n or 0)
    except (TypeError, ValueError):
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if v < 1024 or unit == "TB":
            return f"{v:.0f} {unit}" if unit == "B" else f"{v:.1f} {unit}"
        v /= 1024
    return f"{v:.1f} TB"


templates.env.filters["hbytes"] = _hbytes


# --- flash helpers ------------------------------------------------------
def flash(request: Request, message: str, category: str = "info") -> None:
    request.session.setdefault("_flash", []).append({"m": message, "c": category})


def pop_flash(request: Request) -> list[dict]:
    return request.session.pop("_flash", [])


def active_announcements(request: Request) -> list:
    """Active admin→client announcements this viewer should see (newest first):
    untargeted ones (for everybody) plus ones targeting a group the viewer is in."""
    from .db import SessionLocal

    try:
        uid = request.session.get("uid")
    except Exception:
        uid = None
    if not uid:
        return []
    db = SessionLocal()
    try:
        user = current_user(request, db)
        if not user:
            return []
        rows = (
            db.query(Announcement)
            .filter_by(active=True)
            .order_by(Announcement.created_at.desc())
            .all()
        )
        return [a for a in rows if a.visible_to(user)]
    except Exception:
        return []
    finally:
        db.close()


def render(request: Request, name: str, **ctx) -> HTMLResponse:
    ctx.setdefault("flashes", pop_flash(request))
    ctx.setdefault("announcements", active_announcements(request))
    # Starlette's current API wants `request` as the first positional arg.
    return templates.TemplateResponse(request, name, ctx)


def qr_data_uri(text: str) -> str:
    img = qrcode.make(text)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")


def active_node(db: Session) -> Node | None:
    return db.query(Node).filter_by(is_active=True).first()


# --- startup ------------------------------------------------------------
@app.on_event("startup")
def _startup() -> None:
    init_db()
    if settings.secret_key_ephemeral:
        log.warning("PANEL_SECRET_KEY is not set — using an ephemeral key; "
                    "sessions and stored node secrets will NOT survive a restart.")
    from .db import SessionLocal

    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            pw = settings.admin_password
            if not pw:
                import secrets as _s

                pw = _s.token_urlsafe(12)
                log.warning("No ADMIN_PASSWORD set. Created admin %r with password: %s",
                            settings.admin_username, pw)
            db.add(User(username=settings.admin_username, password_hash=hash_password(pw), role=ROLE_ADMIN))
            db.commit()
            log.info("Bootstrapped admin user %r", settings.admin_username)
    finally:
        db.close()

    # Telegram bot (daily backup+stats, hourly monitoring+alerts). Dormant unless
    # TG_BOT_TOKEN + TG_ADMIN_CHAT are configured.
    try:
        from . import tgbot
        tgbot.start_bot()
    except Exception as e:  # never let the bot break panel startup
        log.warning("Telegram bot did not start: %s", e)


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True}


# --- auth ---------------------------------------------------------------
@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request, db: Session = Depends(get_db)):
    if current_user(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    return render(request, "login.html")


@app.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    ip = request.client.host if request.client else "?"
    wait = login_throttle.retry_after(ip, username)
    if wait:
        # refused before the password is even checked — a blocked client learns nothing
        log.warning("login throttled from %s (user %r, retry in %ss)", ip, username, wait)
        flash(request, f"Слишком много неудачных попыток. Повторите через {(wait + 59) // 60} мин.", "error")
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    user = db.query(User).filter_by(username=username).first()
    if not user or not verify_password(password, user.password_hash):
        login_throttle.fail(ip, username)
        log.warning("login failed from %s (user %r)", ip, username)
        flash(request, "Неверный логин или пароль", "error")
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    login_throttle.success(ip, username)
    # A password set before the current rules (or a weak ADMIN_PASSWORD) is still
    # accepted once, but the user is sent to /change-password to replace it.
    if not user.must_change_password and password_problem(password, user.username):
        user.must_change_password = True
        db.commit()
        flash(request, f"Пароль не соответствует требованиям ({PASSWORD_RULES}) — задайте новый.", "info")
    login_session(request, user)
    return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)


@app.get("/logout")
def logout(request: Request):
    logout_session(request)
    return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)


@app.get("/change-password", response_class=HTMLResponse)
def change_password_form(request: Request, db: Session = Depends(get_db)):
    user = current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    return render(request, "change_password.html", user=user, forced=user.must_change_password,
                  rules=PASSWORD_RULES)


@app.post("/change-password")
def change_password_submit(
    request: Request,
    new_password: str = Form(...),
    confirm: str = Form(...),
    db: Session = Depends(get_db),
):
    user = current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    problem = password_problem(new_password, user.username)
    if problem:
        flash(request, problem, "error")
    elif new_password != confirm:
        flash(request, "Пароли не совпадают", "error")
    elif new_password == settings.default_user_password:
        flash(request, "Выберите пароль, отличный от временного", "error")
    else:
        user.password_hash = hash_password(new_password)
        user.must_change_password = False
        user.session_epoch = (user.session_epoch or 0) + 1  # sign out every other session
        db.commit()
        login_session(request, user)  # …but keep this one
        flash(request, "Пароль изменён", "success")
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    return RedirectResponse("/change-password", status_code=HTTP_303_SEE_OTHER)


# --- client dashboard ---------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    user = current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    routes = pool_ops.accessible_routes(db, user)  # routes this client may use
    # Per route: the protocols a new device can get there right now (on, not
    # blocked) — the form offers only these after the route is picked.
    choices = [(r, [p for p in r.active_protocols if not r.proto_block_reason(p)]) for r in routes]
    choices = [(r, ps) for r, ps in choices if ps]
    return render(
        request, "dashboard.html",
        user=user, devices=user.devices, protocols=PROTOCOLS, protocol_labels=PROTOCOL_LABELS,
        service_ready=bool(choices), choices=choices,
        apps=[{"protocol": a.protocol, "platform": a.platform, "platform_label": a.platform_label,
               "name": a.name, "version": a.version, "url": a.url, "note": a.note}
              for a in db.query(ClientApp).filter_by(enabled=True)
              .order_by(ClientApp.position, ClientApp.id).all()],
    )


@app.post("/devices")
def create_device(
    request: Request,
    name: str = Form(...),
    protocol: str = Form(...),
    route_id: str = Form(""),
    db: Session = Depends(get_db),
):
    user = current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    name = name.strip()
    if not name or protocol not in PROTOCOLS:
        flash(request, "Укажите имя и протокол", "error")
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    # The client picks a route among those their groups grant access to.
    route = db.get(Route, int(route_id)) if route_id.strip().isdigit() else None
    if not route or not route.allows(user):
        flash(request, "Выберите доступный вам маршрут", "error")
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    if not route.has(protocol):
        flash(request, f"Маршрут «{route.name}» — для {route.protocol_label}, выберите другой", "error")
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    reason = route.proto_block_reason(protocol)
    if reason:
        flash(request, f"Маршрут «{route.name}» сейчас недоступен для этого протокола: {reason}", "error")
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    exists = db.query(Device).filter_by(user_id=user.id, name=name, protocol=protocol).first()
    if exists:
        flash(request, "Устройство с таким именем и протоколом уже есть", "error")
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    db.add(Device(user_id=user.id, name=name, protocol=protocol, route_id=route.id))
    db.commit()
    flash(request, f"Устройство «{name}» добавлено", "success")
    return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)


def _owned_device(request: Request, db: Session, device_id: int) -> tuple[User, Device] | None:
    user = current_user(request, db)
    if not user:
        return None
    device = db.get(Device, device_id)
    if not device or device.user_id != user.id:
        return None
    return user, device


@app.post("/devices/{device_id}/delete")
def delete_device(request: Request, device_id: int, db: Session = Depends(get_db)):
    owned = _owned_device(request, db, device_id)
    if not owned:
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    _, device = owned
    node_ops.deprovision_device(db, device)  # best-effort node-side cleanup
    db.delete(device)
    db.commit()
    flash(request, "Устройство удалено", "success")
    return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)


@app.get("/devices/{device_id}", response_class=HTMLResponse)
def device_config(request: Request, device_id: int, db: Session = Depends(get_db)):
    owned = _owned_device(request, db, device_id)
    if not owned:
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    user, device = owned
    route = device.route
    cfg = None
    error = None
    try:
        cfg = node_ops.get_or_issue_config(db, device)
    except Exception as e:
        db.rollback()  # a failed flush leaves the session unusable for rendering
        error = f"Не удалось создать конфиг: {e}"
        log.exception("issue config failed")
    qr = qr_data_uri(cfg.payload) if cfg else None
    # AmneziaWG devices also get an iOS variant: a plain WireGuard-style .conf
    # (the iOS AmneziaWG app can't import the vpn:// string).
    ios_conf = ios_qr = None
    if cfg and device.protocol == PROTO_AWG:
        try:
            from .awg import client_conf_from_vpn
            ios_conf = client_conf_from_vpn(cfg.payload)
            ios_qr = qr_data_uri(ios_conf)
        except Exception:
            log.exception("iOS .conf render failed")
    # VLESS devices also get a subscription: one URL that lists every way in and
    # follows gate changes by itself (app/subscription.py).
    sub = sub_qr = None
    sub_items: list[dict] = []
    if cfg and device.protocol in (PROTO_VLESS, PROTO_NAIVE):
        sub_ops.ensure_token(db, device)
        sub = sub_ops.sub_url(device, str(request.base_url))
        sub_qr = qr_data_uri(sub)
        sub_items = sub_ops.entries(db, device)
    return render(
        request, "device.html",
        user=user, device=device, route=route, cfg=cfg, qr=qr, error=error,
        is_awg=(device.protocol == PROTO_AWG), is_naive=(device.protocol == PROTO_NAIVE),
        paused=bool(route and route.has(device.protocol) and not route.serves(device.protocol)),
        ios_conf=ios_conf, ios_qr=ios_qr,
        sub=sub, sub_qr=sub_qr, sub_items=sub_items,
    )


@app.post("/devices/{device_id}/sub/rotate")
def device_sub_rotate(request: Request, device_id: int, db: Session = Depends(get_db)):
    """New subscription URL; the old one stops working at once."""
    owned = _owned_device(request, db, device_id)
    if not owned:
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    _, device = owned
    sub_ops.rotate_token(db, device)
    flash(request, "Ссылка подписки перевыпущена — старая больше не работает. Добавьте новую в приложение.", "success")
    return RedirectResponse(f"/devices/{device_id}", status_code=HTTP_303_SEE_OTHER)


@app.get("/s/{token}")
def subscription(request: Request, token: str, format: str = "", db: Session = Depends(get_db)):
    """A device's subscription (no login: the token is the secret). Unknown token,
    wrong host or too many requests → a bare 404, so probing learns nothing."""
    from urllib.parse import urlparse

    not_found = Response(status_code=404)
    if settings.sub_base_url:
        want = (urlparse(settings.sub_base_url).hostname or "").lower()
        if (request.url.hostname or "").lower() != want:
            return not_found
    ip = request.client.host if request.client else "?"
    if not sub_ops.allow(ip):
        return not_found
    device = sub_ops.device_by_token(db, token)
    if device is None:
        return not_found
    items = sub_ops.entries(db, device)
    title = settings.sub_title or settings.brand_name
    hdrs = sub_ops.headers(device, db, title, settings.sub_update_hours)
    fmt = sub_ops.pick_format(request.headers.get("user-agent", ""), format)
    if fmt == sub_ops.FORMAT_SINGBOX:
        body = sub_ops.render_singbox(items)
        if body is not None:
            return Response(body, media_type="application/json", headers=hdrs)
    return Response(sub_ops.render_base64(items), media_type="text/plain; charset=utf-8", headers=hdrs)


@app.get("/devices/{device_id}/download")
def device_download(request: Request, device_id: int, fmt: str = "", db: Session = Depends(get_db)):
    owned = _owned_device(request, db, device_id)
    if not owned:
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    _, device = owned
    try:
        cfg = node_ops.get_or_issue_config(db, device)
    except Exception:
        db.rollback()
        return RedirectResponse(f"/devices/{device_id}", status_code=HTTP_303_SEE_OTHER)
    content = cfg.payload
    media = "text/plain"
    if device.protocol == PROTO_AWG:
        if fmt == "ios":
            # iOS AmneziaWG app imports a plain WireGuard-style .conf (not vpn://)
            from .awg import client_conf_from_vpn
            try:
                content = client_conf_from_vpn(cfg.payload)
            except Exception:
                return RedirectResponse(f"/devices/{device_id}", status_code=HTTP_303_SEE_OTHER)
            fname = f"{device.node_identifier()}.conf"
        else:
            fname = f"{device.node_identifier()}.vpn"  # AmneziaVPN-app import file
    else:
        fname = f"{device.node_identifier()}.txt"
    return Response(
        content=content,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# --- admin --------------------------------------------------------------
def _require_staff(request: Request, db: Session) -> User | None:
    """admin|operator — may access the admin area and manage the fleet, clients,
    groups and routes."""
    user = current_user(request, db)
    return user if (user and user.is_staff) else None


def _require_admin(request: Request, db: Session) -> User | None:
    """admin only — the one power an operator lacks: managing people's roles."""
    user = current_user(request, db)
    return user if (user and user.is_admin) else None


@app.get("/admin/nodes", response_class=HTMLResponse)
def admin_nodes(request: Request, db: Session = Depends(get_db)):
    # merged into «Парк»
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/nodes")
def admin_add_node(
    request: Request,
    name: str = Form(...),
    public_host: str = Form(...),
    role: str = Form(ROLE_EXIT),
    pool_id: str = Form(""),
    ssh_host: str = Form(""),
    ssh_port: int = Form(22),
    ssh_username: str = Form("root"),
    ssh_password: str = Form(""),
    xui_path: str = Form(""),
    xui_port: int = Form(29568),
    xui_token: str = Form(""),
    awg_endpoint_host: str = Form(""),
    awg_port: str = Form(""),  # blank -> provisioning picks a fresh port
    db: Session = Depends(get_db),
):
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    role = role if role in ROLES else ROLE_EXIT
    pid = int(pool_id) if (role == ROLE_EXIT and pool_id.strip().isdigit()) else None
    if pid is not None and db.get(ExitPool, pid) is None:
        pid = None
    node = Node(
        name=name.strip(),
        public_host=public_host.strip(),
        role=role,
        pool_id=pid,
        ssh_host=(ssh_host.strip() or public_host.strip()),
        ssh_port=ssh_port,
        ssh_username=ssh_username.strip() or "root",
        xui_path=xui_path.strip() or None,
        xui_port=xui_port,
        awg_endpoint_host=awg_endpoint_host.strip() or None,
        awg_port=int(awg_port) if awg_port.strip().isdigit() else 44625,
    )
    node.ssh_password = ssh_password or None
    node.xui_token = xui_token or None
    db.add(node)
    db.commit()
    flash(request, f"Нода «{node.name}» добавлена", "success")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/nodes/{node_id}/pool")
def admin_set_node_pool(
    request: Request, node_id: int, pool_id: str = Form(""), db: Session = Depends(get_db)
):
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    node = db.get(Node, node_id)
    if node:
        pid = int(pool_id) if pool_id.strip().isdigit() else None
        if pid is not None and db.get(ExitPool, pid) is None:
            pid = None
        node.pool_id = pid
        from .models import SYNC_PENDING

        node.sync_state = SYNC_PENDING
        db.commit()
        pool = db.get(ExitPool, pid) if pid else None
        flash(request, f"«{node.name}» → пул {pool.name if pool else '— снят'}", "success")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/nodes/{node_id}/activate")
def admin_activate_node(request: Request, node_id: int, db: Session = Depends(get_db)):
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    node = db.get(Node, node_id)
    if node:
        db.query(Node).update({Node.is_active: False})
        node.is_active = True
        db.commit()
        flash(request, f"Активна нода «{node.name}»", "success")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/nodes/{node_id}/test")
def admin_test_node(
    request: Request, node_id: int, direct: bool = Form(False), db: Session = Depends(get_db)
):
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    node = db.get(Node, node_id)
    if node:
        # `direct` is the explicit «connect directly» override: bypass the gate for
        # a one-off reachability probe (Hub→exit directly). Normal checks go via gate.
        request.session["_test"] = {"node": node.name, **node_ops.test_node(node, allow_direct=direct)}
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/nodes/{node_id}/provision")
def admin_provision_node(request: Request, node_id: int, db: Session = Depends(get_db)):
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    node = db.get(Node, node_id)
    if node:
        # Provisioning is minutes of SSH — run it in the background (app/jobs.py) so
        # the response returns now (no reverse-proxy 524) and a second click is blocked.
        def _do(db: Session, node: Node) -> str:
            if node.pool_id:
                info = pool_ops.provision_pool_exit(db, node)
                rec = info.get("reconcile", {})
                return (f"Развёрнут как клон пула: {', '.join(info['installed']) or '—'}; "
                        f"синхронизация {'ok' if rec.get('ok') else rec.get('error', '—')}")
            info = node_ops.provision_node(db, node)
            return (f"Развёрнута: 3x-ui (порт {info['xui_port']}) + "
                    f"AmneziaWG (UDP {info['awg_port']})")

        if jobs.start_node_job(db, node, "provision", _do):
            flash(request, f"«{node.name}»: раскатка запущена в фоне — статус обновится на «Парке».", "success")
        else:
            flash(request, f"«{node.name}»: раскатка уже идёт — дождитесь завершения.", "error")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/nodes/{node_id}/converge")
def admin_converge_node(request: Request, node_id: int, db: Session = Depends(get_db)):
    """«Привести к пулу»: the safe re-provision for a server already serving
    clients — install only what's missing, refresh NaiveProxy, check the VLESS
    inbound, reconcile. Background job like «Развернуть»."""
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    node = db.get(Node, node_id)
    if node and node.pool_id:
        def _do(db: Session, node: Node) -> str:
            info = pool_ops.provision_pool_exit(db, node, only_missing=True)
            rec = info.get("reconcile", {})
            return (f"Приведён к пулу: {', '.join(info['installed']) or '—'}; "
                    f"синхронизация {'ok' if rec.get('ok') else rec.get('error', '—')}")

        if jobs.start_node_job(db, node, "provision", _do):
            flash(request, f"«{node.name}»: приведение к пулу запущено в фоне.", "success")
        else:
            flash(request, f"«{node.name}»: операция уже идёт — дождитесь завершения.", "error")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


# NaiveProxy certificates being issued right now (route protocol ids) and the last
# failure per protocol — in-process state (one uvicorn worker), shown on «Парк».
_CERT_BUSY: set[int] = set()
_CERT_ERR: dict[int, str] = {}
_CERT_LOCK = __import__("threading").Lock()


@app.post("/admin/routes/{route_id}/cert")
def admin_route_cert(request: Request, route_id: int, db: Session = Depends(get_db)):
    """Issue (or renew) the certificate of the route's NaiveProxy hostname on the
    Hub (DNS-01) and push it to the pool's servers — in the background (1–2 min)."""
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    route = db.get(Route, route_id)
    rp = route.proto(PROTO_NAIVE) if route else None
    if rp is None:
        return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)
    if not rp.client_host or rp.dns_provider is None:
        flash(request, "Сначала задайте NaiveProxy имя хоста и DNS-провайдер его зоны (адрес протокола)", "error")
        return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)
    import threading

    rp_id = rp.id
    with _CERT_LOCK:
        if rp_id in _CERT_BUSY:
            # A second issue would race the first one for the same TXT record.
            flash(request, f"Сертификат для {rp.client_host} уже выпускается — дождитесь окончания.", "error")
            return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)
        _CERT_BUSY.add(rp_id)
        _CERT_ERR.pop(rp_id, None)

    def _work():
        from . import naive
        from .db import SessionLocal

        s = SessionLocal()
        try:
            r = s.get(RouteProto, rp_id)
            naive.ensure_cert(s, r, force=True)
            ok, errs = naive.push_pool(s, r.route.pool)
            log.info("naive cert %s: pushed to %d servers %s", r.client_host, ok, errs or "")
        except Exception as e:
            log.exception("naive cert issue failed")
            _CERT_ERR[rp_id] = str(e)[:300]
        finally:
            s.close()
            with _CERT_LOCK:
                _CERT_BUSY.discard(rp_id)

    threading.Thread(target=_work, name="naive-cert", daemon=True).start()
    flash(request, f"Выпуск сертификата для {rp.client_host} запущен — 1–2 минуты, страница обновится "
                   f"сама; затем сертификат разошлётся на серверы пула.", "success")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.get("/admin/park/status")
def admin_park_status(request: Request, db: Session = Depends(get_db)):
    """Lightweight poll for «Парк»: ids of nodes whose job is still running. The page
    auto-reloads once a running job leaves this list, so the final result badge shows
    without a manual refresh."""
    if not _require_staff(request, db):
        return JSONResponse({"running": [], "certs": []}, status_code=403)
    running = [nid for (nid,) in db.query(Node.id).filter(Node.job_state == JOB_RUNNING).all()]
    return JSONResponse({"running": running, "certs": sorted(_CERT_BUSY)})


@app.post("/admin/nodes/{node_id}/hostkey/forget")
def admin_forget_host_key(request: Request, node_id: int, db: Session = Depends(get_db)):
    """Forget the server's recorded SSH host key (after an OS reinstall): the next
    connection records the new one (app/node_ssh.py, trust on first use)."""
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    node = db.get(Node, node_id)
    if node:
        if forget_host_key(node.ssh_host, node.ssh_port):
            flash(request, f"Ключ SSH «{node.name}» сброшен — при следующем подключении запомнится новый", "success")
        else:
            flash(request, f"У «{node.name}» ключ SSH ещё не запомнен", "info")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/nodes/{node_id}/delete")
def admin_delete_node(request: Request, node_id: int, db: Session = Depends(get_db)):
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    node = db.get(Node, node_id)
    if node:
        host, port = node.ssh_host, node.ssh_port
        db.delete(node)
        db.commit()
        # a server added again at this address later is a new machine — new key
        if not db.query(Node.id).filter_by(ssh_host=host, ssh_port=port).first():
            forget_host_key(host, port)
        flash(request, "Нода удалена", "success")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/nodes/{node_id}/priority")
def admin_set_node_priority(
    request: Request, node_id: int, priority: int = Form(100), db: Session = Depends(get_db)
):
    """Failover priority of an exit within its pool (lower = preferred)."""
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    node = db.get(Node, node_id)
    if node:
        node.priority = max(0, int(priority))
        db.commit()
        flash(request, f"Приоритет «{node.name}»: {node.priority}", "success")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


# --- admin: routes ------------------------------------------------------
@app.get("/admin/routes", response_class=HTMLResponse)
def admin_routes(request: Request, db: Session = Depends(get_db)):
    # merged into «Парк»
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


def _gate_pool_of(db: Session, gate: Node) -> GatePool:
    """The gate's pool, creating a one-gate pool named after it if it has none."""
    if gate.gate_pool_id:
        gp = db.get(GatePool, gate.gate_pool_id)
        if gp:
            return gp
    name, n = gate.name, 1
    while db.query(GatePool).filter_by(name=name).first():
        n += 1
        name = f"{gate.name}-{n}"
    gp = GatePool(name=name)
    db.add(gp)
    db.flush()
    gate.gate_pool_id = gp.id
    return gp


class _EntryError(ValueError):
    pass


def _resolve_entry(db: Session, entry: str) -> int | None:
    """Parse the route «entry» field into a gate_pool_id (None = direct).
    'gatepool:<id>' — an existing gate pool; 'gate:<id>' — a gate, pooled on the
    fly if needed; 'direct' — no gate. Raises _EntryError with a user message."""
    entry = (entry or "").strip()
    if entry == "direct":
        return None
    kind, _, raw = entry.partition(":")
    if not raw.isdigit():
        raise _EntryError("Выберите вход маршрута: пул гейтов, гейт или «напрямую»")
    if kind == "gatepool":
        gp = db.get(GatePool, int(raw))
        if gp is None:
            raise _EntryError("Пул гейтов не найден")
        return gp.id
    if kind == "gate":
        gate = db.get(Node, int(raw))
        if gate is None or gate.role != ROLE_GATE:
            raise _EntryError("Выберите gate-сервер")
        return _gate_pool_of(db, gate).id
    raise _EntryError("Непонятный вход маршрута")


@app.post("/admin/routes/{route_id}/entry")
def admin_set_route_entry(
    request: Request, route_id: int, entry: str = Form(""), db: Session = Depends(get_db)
):
    """Move a route to another gate pool (or make it direct). Clients' configs
    don't change — only where their hostname/subscription points (DNS and relays
    of the new pool must be brought up)."""
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    route = db.get(Route, route_id)
    if route:
        try:
            route.gate_pool_id = _resolve_entry(db, entry)
        except _EntryError as e:
            db.rollback()
            flash(request, str(e), "error")
        else:
            db.commit()
            where = "напрямую" if route.is_direct else f"пул гейтов «{route.gate_pool.name}»"
            flash(request, f"Маршрут «{route.name}»: вход — {where}. Поднимите релей на гейтах.", "success")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/routes/{route_id}/pool")
def admin_set_route_pool(
    request: Request, route_id: int, pool_id: str = Form(""), db: Session = Depends(get_db)
):
    """Move a route to another (free) exit pool. The pool's identity is part of
    client configs: VLESS keeps its uuid but the link changes (subscriptions follow
    by themselves), AWG configs change — single links / AWG configs must be handed
    out again. Usually it's simpler to move SERVERS between pools instead."""
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    route = db.get(Route, route_id)
    pool = db.get(ExitPool, int(pool_id)) if pool_id.strip().isdigit() else None
    if route and pool and pool.id != route.pool_id:
        if pool.routes:
            flash(request, f"Пул выходов «{pool.name}» уже занят маршрутом «{pool.routes[0].name}»", "error")
        else:
            route.pool_id = pool.id
            db.commit()
            flash(request, f"«{route.name}»: выходы — пул «{pool.name}». Нажмите «Применить». Одиночные "
                           f"VLESS-ссылки и AWG-конфиги устройств маршрута изменятся (подписки — сами).",
                  "success")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/routes/{route_id}/gates")
def admin_add_route_gate(
    request: Request, route_id: int, gate_id: str = Form(""), db: Session = Depends(get_db)
):
    """Add a gate to the route's gate pool (creating the pool for a direct route)."""
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    route = db.get(Route, route_id)
    gate = db.get(Node, int(gate_id)) if gate_id.strip().isdigit() else None
    if route and gate and gate.role == ROLE_GATE:
        if route.gate_pool_id is None:
            route.gate_pool_id = _gate_pool_of(db, gate).id
        else:
            gate.gate_pool_id = route.gate_pool_id
        db.commit()
        flash(request, f"«{gate.name}» → пул гейтов «{route.gate_pool.name}». Поднимите на нём релей.", "success")
    elif route:
        flash(request, "Выберите gate-сервер", "error")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/nodes/{node_id}/gate_pool")
def admin_set_gate_pool(
    request: Request, node_id: int, gate_pool_id: str = Form(""), db: Session = Depends(get_db)
):
    """Put a gate into a gate pool, or (empty) take it out — it stays in the fleet."""
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    node = db.get(Node, node_id)
    if node and node.role == ROLE_GATE:
        gp = db.get(GatePool, int(gate_pool_id)) if gate_pool_id.strip().isdigit() else None
        node.gate_pool_id = gp.id if gp else None
        db.commit()
        if gp:
            flash(request, f"«{node.name}» → пул гейтов «{gp.name}». Поднимите релей пула.", "success")
        else:
            flash(request, f"«{node.name}» убран из пула гейтов", "success")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


# --- admin: gate pools --------------------------------------------------
@app.post("/admin/gatepools")
def admin_add_gate_pool(request: Request, name: str = Form(...), db: Session = Depends(get_db)):
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    name = name.strip()
    if not name:
        flash(request, "Укажите имя пула гейтов", "error")
    elif db.query(GatePool).filter_by(name=name).first():
        flash(request, "Пул гейтов с таким именем уже есть", "error")
    else:
        db.add(GatePool(name=name))
        db.commit()
        flash(request, f"Пул гейтов «{name}» создан — добавьте в него гейты", "success")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/gatepools/{gp_id}/gates")
def admin_gate_pool_add_gate(
    request: Request, gp_id: int, gate_id: str = Form(""), db: Session = Depends(get_db)
):
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    gp = db.get(GatePool, gp_id)
    gate = db.get(Node, int(gate_id)) if gate_id.strip().isdigit() else None
    if gp and gate and gate.role == ROLE_GATE:
        gate.gate_pool_id = gp.id
        db.commit()
        flash(request, f"«{gate.name}» → пул гейтов «{gp.name}». Поднимите релей пула.", "success")
    elif gp:
        flash(request, "Выберите gate-сервер", "error")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/gatepools/{gp_id}/relay")
def admin_gate_pool_relay(request: Request, gp_id: int, db: Session = Depends(get_db)):
    """Raise/refresh the relay on every gate of the pool. The relay belongs to the
    gate pool (it's built from all routes the pool fronts), so it's started here."""
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    gp = db.get(GatePool, gp_id)
    if gp:
        _start_relay_jobs(request, db, gp.gates, gp.name)
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/gatepools/{gp_id}/delete")
def admin_delete_gate_pool(request: Request, gp_id: int, db: Session = Depends(get_db)):
    """Refused while any route uses the pool — deleting it would cut those
    routes' clients off in one click. Its gates become unassigned."""
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    gp = db.get(GatePool, gp_id)
    if gp:
        users = [r.name for r in gp.routes]
        if users:
            flash(request, f"Пул гейтов «{gp.name}» используют маршруты: {', '.join(users)} — "
                           f"сначала смените им вход или удалите их", "error")
        else:
            db.query(Node).filter(Node.gate_pool_id == gp.id).update({Node.gate_pool_id: None})
            db.delete(gp)
            db.commit()
            flash(request, f"Пул гейтов «{gp.name}» удалён", "success")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/routes/{route_id}/toggle")
def admin_toggle_route(request: Request, route_id: int, db: Session = Depends(get_db)):
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    route = db.get(Route, route_id)
    if route:
        route.enabled = not route.enabled
        db.commit()
        flash(request, f"Маршрут «{route.name}» {'включён' if route.enabled else 'выключен'}", "success")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/routes/{route_id}/groups")
def admin_set_route_groups(
    request: Request, route_id: int,
    group_ids: list[int] = Form(default=[]),
    db: Session = Depends(get_db),
):
    """Set which access groups may use this route (empty = nobody)."""
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    route = db.get(Route, route_id)
    if route:
        route.groups = db.query(Group).filter(Group.id.in_(group_ids)).all() if group_ids else []
        db.commit()
        flash(request, f"Доступ к «{route.name}»: групп — {len(route.groups)}", "success")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/routes/{route_id}/delete")
def admin_delete_route(request: Request, route_id: int, db: Session = Depends(get_db)):
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    route = db.get(Route, route_id)
    if route:
        # SQLite doesn't enforce ON DELETE SET NULL — unlink devices by hand so
        # they show «маршрут не выбран» instead of pointing at a ghost.
        db.query(Device).filter(Device.route_id == route.id).update(
            {Device.route_id: None}, synchronize_session=False
        )
        db.delete(route)
        db.commit()
        flash(request, "Маршрут удалён (пулы и серверы остались)", "success")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/routes/{route_id}/provision_relay")
def admin_provision_relay(request: Request, route_id: int, db: Session = Depends(get_db)):
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    route = db.get(Route, route_id)
    if route and route.gates and route.pool:
        _start_relay_jobs(request, db, route.gates, route.gate_pool.name)
    elif route:
        flash(request, "У маршрута должны быть гейты и пул выходов (прямому маршруту релей не нужен)", "error")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


def _start_relay_jobs(request: Request, db: Session, gates: list[Node], pool_name: str) -> None:
    """Raising a relay is a long op — background it on EACH gate, so every gate
    reports its own progress and can't be double-fired."""
    if not gates:
        flash(request, f"В пуле гейтов «{pool_name}» нет гейтов", "error")
        return

    def _do(db: Session, gate: Node) -> str:
        info = node_ops.provision_gate_relay(db, gate)
        sni = f", SNI-роутер {info['sni']}" if info.get("sni") else ""
        return f"Релей поднят: {info['summary']} (демон {info.get('daemon', '?')}{sni})"

    started, busy = [], []
    for gate in gates:
        (started if jobs.start_node_job(db, gate, "relay", _do) else busy).append(gate.name)
    if started:
        flash(request, f"Подъём релея запущен в фоне: {', '.join(started)} — статус на «Парке».", "success")
    if busy:
        flash(request, f"Уже идёт операция: {', '.join(busy)} — дождитесь завершения.", "error")


# --- admin: groups (managed on the «Пользователи и группы» page) --------
@app.get("/admin/groups", response_class=HTMLResponse)
def admin_groups(request: Request, db: Session = Depends(get_db)):
    # groups were merged into the users page; keep the old URL working
    return RedirectResponse("/admin/users", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/groups")
def admin_add_group(request: Request, name: str = Form(...), db: Session = Depends(get_db)):
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    name = name.strip()
    if not name:
        flash(request, "Укажите имя группы", "error")
    elif db.query(Group).filter_by(name=name).first():
        flash(request, "Группа с таким именем уже есть", "error")
    else:
        db.add(Group(name=name))
        db.commit()
        flash(request, f"Группа «{name}» создана", "success")
    return RedirectResponse("/admin/users", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/groups/{group_id}/delete")
def admin_delete_group(request: Request, group_id: int, db: Session = Depends(get_db)):
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    group = db.get(Group, group_id)
    if group:
        db.delete(group)
        db.commit()
        flash(request, "Группа удалена", "success")
    return RedirectResponse("/admin/users", status_code=HTTP_303_SEE_OTHER)


# --- admin: park (gates + exits + routes, merged into one page) ---------
@app.get("/admin/park", response_class=HTMLResponse)
def admin_park(request: Request, db: Session = Depends(get_db)):
    admin = _require_staff(request, db)
    if not admin:
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    routes = db.query(Route).order_by(Route.name).all()
    all_nodes = db.query(Node).order_by(Node.id).all()
    gate_pools = db.query(GatePool).order_by(GatePool.name).all()
    # Unassigned servers: exits outside any server pool, gates outside any gate pool.
    orphans = [
        n for n in all_nodes
        if (n.role == ROLE_EXIT and n.pool_id is None)
        or (n.role == ROLE_GATE and n.gate_pool_id is None)
    ]
    free_gates = [n for n in all_nodes if n.role == ROLE_GATE and n.gate_pool_id is None]
    groups = db.query(Group).order_by(Group.name).all()
    exit_pools = db.query(ExitPool).order_by(ExitPool.name).all()
    rps = [rp for r in routes for rp in r.protos]
    dev_counts: dict[tuple[int, str], int] = {}
    for rid, proto in db.query(Device.route_id, Device.protocol).filter(Device.route_id.isnot(None)).all():
        dev_counts[(rid, proto)] = dev_counts.get((rid, proto), 0) + 1
    from . import park

    gst = park.gate_states(db)
    crt = park.certs(db, routes)
    gp_problems = {gp.id: pool_ops.gate_pool_problem(db, gp.id) for gp in gate_pools if gp.routes}
    health = {r.id: park.route_health(r, gst, crt) for r in routes}
    gates_all = [n for n in all_nodes if n.role == ROLE_GATE and n.gate_pool_id is not None]
    return render(request, "admin_park.html", user=admin, routes=routes, orphans=orphans,
                  free_gates=free_gates, gate_pools=gate_pools, groups=groups,
                  exit_pools=exit_pools,
                  free_exit_pools=[p for p in exit_pools if not p.routes],
                  gate_pool_problems=gp_problems,
                  dns_providers=db.query(DnsProvider).order_by(DnsProvider.name).all(),
                  dns_kinds=DNS_KINDS,
                  dns_states={rp.id: dns_ops.get_state(db, rp.id) for rp in rps if rp.dns_provider_id},
                  naive_certs=crt, cert_busy=set(_CERT_BUSY), cert_err=dict(_CERT_ERR),
                  dev_counts=dev_counts,
                  gst=gst, gate_tip=park.gate_tip, health=health,
                  ready={r.id: park.readiness(r, crt, gp_problems.get(r.gate_pool_id, "")) for r in routes},
                  attention=park.attention(routes, gate_pools, orphans, gst, crt, set(_CERT_BUSY)),
                  broken=[r for r in routes if health[r.id]["state"] == "bad"],
                  # scheme: pools in the order of the routes using them (fewer crossing wires)
                  scheme_gp=_in_route_order(gate_pools, [r.gate_pool for r in routes]),
                  scheme_ep=_in_route_order(exit_pools, [r.pool for r in routes]),
                  dev_total={r.id: sum(n for (rid, _), n in dev_counts.items() if rid == r.id) for r in routes},
                  live_ids={gid for gid, st in gst.items() if st["live"]},
                  gates_live=sum(1 for g in gates_all if gst.get(g.id, {}).get("live", True)),
                  gates_total=len(gates_all),
                  protocols=ALL_PROTOCOLS, protocol_labels=PROTOCOL_LABELS,
                  fleet_pub=fleetkey.public_line(db), fleet_fp=fleetkey.fingerprint(db),
                  test_result=request.session.pop("_test", None))


def _in_route_order(pools: list, used: list) -> list:
    """`pools` reordered: first as the routes use them, then the unused ones."""
    out = []
    for p in used + pools:
        if p is not None and p not in out:
            out.append(p)
    return out


@app.post("/admin/park/route")
def admin_park_create_route(
    request: Request, name: str = Form(...), entry: str = Form(""),
    protocols: list[str] = Form(default=[]), pool_id: str = Form(""),
    client_port: str = Form(str(DEFAULT_CLIENT_PORT)),
    vless_port: int = Form(17771), awg_port: int = Form(17772),
    db: Session = Depends(get_db),
):
    """Create a route = exit pool (a free one, or a fresh empty pool named after
    the route) + entry (gate pool / gate / direct) + the protocols it runs. An exit
    pool belongs to one route; a gate pool may front several."""
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    name = name.strip()
    protos = [p for p in ALL_PROTOCOLS if p in set(protocols)]
    pool = db.get(ExitPool, int(pool_id)) if pool_id.strip().isdigit() else None
    if not name:
        flash(request, "Укажите имя маршрута", "error")
    elif db.query(Route).filter_by(name=name).first() or (
        pool is None and db.query(ExitPool).filter_by(name=name).first()
    ):
        flash(request, "Имя уже занято", "error")
    elif not protos:
        flash(request, "Выберите хотя бы один протокол", "error")
    elif pool_id.strip() and pool is None:
        flash(request, "Пул выходов не найден", "error")
    elif pool is not None and pool.routes:
        flash(request, f"Пул выходов «{pool.name}» уже занят маршрутом «{pool.routes[0].name}»", "error")
    else:
        try:
            gpid = _resolve_entry(db, entry)
        except _EntryError as e:
            db.rollback()
            flash(request, str(e), "error")
        else:
            if pool is None:
                pool = pool_ops.create_pool(db, name, vless_port=vless_port, awg_port=awg_port)
            route = Route(name=name, gate_pool_id=gpid, pool_id=pool.id)
            db.add(route)
            db.flush()
            ok_port = client_port.strip().isdigit() and 0 < int(client_port) < 65536
            cport = int(client_port) if ok_port else DEFAULT_CLIENT_PORT
            for p in protos:
                db.add(RouteProto(route_id=route.id, protocol=p, enabled=True,
                                  client_port=None if gpid is None else cport))
            db.commit()
            labels = " + ".join(PROTOCOL_LABELS[p] for p in protos)
            flash(request, f"Маршрут «{name}» ({labels}) создан. Дальше: выходы в пул «{pool.name}», "
                           f"адреса протоколов, доступ — и «Применить».", "success")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


def _after_proto_change(request: Request, db: Session, route: Route) -> str:
    """After a protocol was paused/resumed/removed: sync the pool's servers (drop or
    restore accounts) and rebuild the relay of the gate pool — in the background."""
    import threading

    pool_id = route.pool_id
    if pool_id and route.pool and route.pool.members:
        def _sync():
            from .db import SessionLocal

            s = SessionLocal()
            try:
                p = s.get(ExitPool, pool_id)
                if p is not None:
                    pool_ops.reconcile_pool(s, p)
            except Exception:
                log.exception("reconcile after protocol change failed")
            finally:
                s.close()

        threading.Thread(target=_sync, name="proto-sync", daemon=True).start()
    if route.gate_pool and route.gates:
        problem = pool_ops.gate_pool_problem(db, route.gate_pool_id)
        if problem:
            return f"релей не пересобран: {problem}"
        _start_relay_jobs(request, db, route.gates, route.gate_pool.name)
        return "серверы синхронизируются, релей пересобирается"
    return "серверы синхронизируются"


@app.post("/admin/routes/{route_id}/protos/add")
def admin_route_proto_add(
    request: Request, route_id: int, protocol: str = Form(""), db: Session = Depends(get_db)
):
    """Add a protocol to the route. It goes onto the servers with «Применить»."""
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    route = db.get(Route, route_id)
    if route and protocol in ALL_PROTOCOLS and not route.has(protocol):
        db.add(RouteProto(route_id=route.id, protocol=protocol, enabled=True,
                          client_port=None if route.is_direct else DEFAULT_CLIENT_PORT))
        db.commit()
        flash(request, f"«{route.name}»: добавлен {PROTOCOL_LABELS[protocol]}. Задайте адрес и нажмите "
                       f"«Применить» — протокол встанет на серверы, гейты пересоберут релей.", "success")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/routes/{route_id}/protos/{protocol}/toggle")
def admin_route_proto_toggle(
    request: Request, route_id: int, protocol: str, db: Session = Depends(get_db)
):
    """The protocol switch of a route (every route shows all three):
    - off → on: a protocol the route doesn't have is added; a paused one resumes;
    - on → off: with devices on it — paused (configs stay; the gate stops
      forwarding it, servers drop its accounts, subscriptions leave it out);
      without devices — removed from the route (nothing to keep)."""
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    route = db.get(Route, route_id)
    if not route or protocol not in ALL_PROTOCOLS:
        return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)
    label = PROTOCOL_LABELS[protocol]
    rp = route.proto(protocol)
    if rp is None:
        db.add(RouteProto(route_id=route.id, protocol=protocol, enabled=True,
                          client_port=None if route.is_direct else DEFAULT_CLIENT_PORT))
        db.commit()
        db.refresh(route)
        flash(request, f"«{route.name}»: {label} включён. Задайте адрес и нажмите «Применить» — "
                       f"протокол встанет на серверы, гейты пересоберут релей.", "success")
    elif not rp.enabled:
        rp.enabled = True
        db.commit()
        flash(request, f"«{route.name}»: {label} снова включён; {_after_proto_change(request, db, route)}.",
              "success")
    else:
        used = db.query(Device).filter(Device.route_id == route.id, Device.protocol == protocol).count()
        if used:
            rp.enabled = False
            what = f"на паузе — конфиги {used} устр. сохранены"
        else:
            db.delete(rp)
            what = "выключен"
        db.commit()
        db.refresh(route)
        flash(request, f"«{route.name}»: {label} {what}; {_after_proto_change(request, db, route)}.", "success")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/routes/{route_id}/protos/{protocol}/delete")
def admin_route_proto_delete(
    request: Request, route_id: int, protocol: str, db: Session = Depends(get_db)
):
    """Remove a paused protocol that no device of the route uses. It stays installed
    on the servers (harmless) until they are reinstalled."""
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    route = db.get(Route, route_id)
    rp = route.proto(protocol) if route else None
    if rp is None:
        return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)
    used = db.query(Device).filter(Device.route_id == route.id, Device.protocol == protocol).count()
    if rp.enabled:
        flash(request, f"Сначала приостановите {rp.label} на «{route.name}»", "error")
    elif used:
        flash(request, f"{rp.label} на «{route.name}» используют устройства ({used}) — удалить нельзя; "
                       f"он может оставаться приостановленным", "error")
    else:
        db.delete(rp)
        db.commit()
        flash(request, f"«{route.name}»: {PROTOCOL_LABELS.get(protocol, protocol)} убран из маршрута", "success")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/routes/{route_id}/protos/{protocol}/address")
def admin_route_proto_address(
    request: Request, route_id: int, protocol: str, client_host: str = Form(""),
    client_port: str = Form(""), dns_provider_id: str = Form(""), db: Session = Depends(get_db),
):
    """What client configs name for this protocol of the route: hostname
    (optionally kept in sync with a DNS provider) and port. Already issued configs
    keep what they had until re-issued; subscriptions update by themselves."""
    from . import journal

    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    route = db.get(Route, route_id)
    rp = route.proto(protocol) if route else None
    if rp is None:
        return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)
    host = client_host.strip().rstrip(".").lower()
    port = int(client_port) if client_port.strip().isdigit() else None
    p = db.get(DnsProvider, int(dns_provider_id)) if dns_provider_id.strip().isdigit() else None
    if port is not None and not 1 <= port <= 65535:
        flash(request, "Порт — от 1 до 65535", "error")
    elif p and not host:
        flash(request, "Для DNS-синхронизации укажите имя хоста", "error")
    elif p and host != p.zone and not host.endswith("." + p.zone):
        flash(request, f"Имя {host} не в зоне {p.zone} провайдера «{p.name}»", "error")
    else:
        rp.client_host = host
        rp.client_port = port
        rp.dns_provider_id = p.id if p else None
        db.commit()
        msg = f"«{route.name}» · {rp.label}: {rp.host or '—'}:{rp.port}"
        st = {}
        if p:
            st = dns_ops.sync_proto(db, rp, journal.live_gate_ids(db), force=True)
            msg += (f"; DNS → {', '.join(st.get('ips', []))}" if not st.get("error")
                    else f"; DNS не обновлён: {st['error']}")
        if not route.is_direct:
            msg += ". На гейтах это вступит в силу после «Применить»"
        flash(request, msg, "error" if st.get("error") else "success")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/routes/{route_id}/apply")
def admin_route_apply(request: Request, route_id: int, db: Session = Depends(get_db)):
    """«Применить»: bring the route's servers to its protocols (new servers are
    installed, deployed ones only get what's missing — nothing working is
    reinstalled) and rebuild the relay on its gates. Background jobs per node."""
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    route = db.get(Route, route_id)
    if not route:
        return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)
    pool = route.pool
    nrp = route.proto(PROTO_NAIVE)
    if pool is None or not pool.members:
        flash(request, f"В пуле выходов маршрута «{route.name}» нет серверов", "error")
    elif not route.protos:
        flash(request, f"У маршрута «{route.name}» нет протоколов", "error")
    elif nrp is not None and (not nrp.client_host or db.get(NaiveCert, nrp.client_host.lower()) is None):
        flash(request, "Сначала задайте NaiveProxy имя хоста и выпустите сертификат — "
                       "без него NaiveProxy на серверах не запустить", "error")
    else:
        def _do(db: Session, node: Node) -> str:
            deployed = node.has_xui or node.key_installed
            info = pool_ops.provision_pool_exit(db, node, only_missing=deployed)
            rec = info.get("reconcile", {})
            verb = "Приведён к маршруту" if deployed else "Развёрнут"
            return (f"{verb}: {', '.join(info['installed']) or '—'}; "
                    f"синхронизация {'ok' if rec.get('ok') else rec.get('error', '—')}")

        started, busy = [], []
        for n in pool.members:
            (started if jobs.start_node_job(db, n, "provision", _do) else busy).append(n.name)
        if started:
            flash(request, f"«{route.name}»: раскатка на {', '.join(started)} запущена в фоне.", "success")
        if busy:
            flash(request, f"Уже идёт операция: {', '.join(busy)} — дождитесь завершения.", "error")
        if not route.is_direct:
            problem = pool_ops.gate_pool_problem(db, route.gate_pool_id)
            if problem:
                flash(request, f"Релей пула гейтов «{route.gate_pool.name}» не собрать: {problem}", "error")
            else:
                _start_relay_jobs(request, db, route.gates, route.gate_pool.name)
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/routes/{route_id}/reconcile")
def admin_route_reconcile(request: Request, route_id: int, db: Session = Depends(get_db)):
    route = db.get(Route, route_id)
    if not _require_staff(request, db) or not route or not route.pool:
        return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)
    return admin_reconcile_pool(request, route.pool_id, db)


@app.get("/admin/pools", response_class=HTMLResponse)
def admin_pools(request: Request, db: Session = Depends(get_db)):
    # merged into «Парк»
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/pools")
def admin_add_pool(
    request: Request,
    name: str = Form(...),
    vless_port: int = Form(17771),
    awg_port: int = Form(17772),
    db: Session = Depends(get_db),
):
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    name = name.strip()
    if not name:
        flash(request, "Укажите имя пула", "error")
    elif db.query(ExitPool).filter_by(name=name).first():
        flash(request, "Пул с таким именем уже есть", "error")
    else:
        pool = pool_ops.create_pool(db, name, vless_port=vless_port, awg_port=awg_port)
        flash(request, f"Пул выходов «{pool.name}» создан — добавьте в него серверы", "success")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/pools/{pool_id}/vless")
def admin_pool_vless(
    request: Request, pool_id: int, transport: str = Form(VLESS_XHTTP), xhttp_path: str = Form(""),
    reality_target: str = Form(""), reality_names: str = Form(""), db: Session = Depends(get_db),
):
    """VLESS settings of a server pool: transport and Reality masquerade. They are
    part of every client config — after a change the servers must be redeployed and
    the pool's VLESS configs re-issued (subscriptions pick it up by themselves)."""
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    pool = db.get(ExitPool, pool_id)
    if not pool:
        return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)
    target = reality_target.strip()
    names = [n for n in reality_names.replace(",", " ").split() if n]
    path = xhttp_path.strip()
    if transport not in (VLESS_TCP, VLESS_XHTTP):
        flash(request, "Неизвестный транспорт", "error")
    elif target and (":" not in target or not target.rsplit(":", 1)[1].isdigit()):
        flash(request, "Сайт-маска — в виде host:port, например www.example.com:443", "error")
    elif path and not path.startswith("/"):
        flash(request, "Путь XHTTP начинается с «/»", "error")
    else:
        pool.vless_transport = transport
        if transport == VLESS_XHTTP:
            pool.xhttp_path = path or pool.xhttp_path or ("/" + __import__("secrets").token_hex(6))
        pool.reality_target = target
        pool.reality_names = names
        db.commit()
        flash(request, f"VLESS пула «{pool.name}»: {transport.upper()}, маска {pool.reality_dest}. "
                       f"Переразверните серверы пула и поднимите релей пулов гейтов; выданные "
                       f"VLESS-конфиги пула нужно перевыпустить.", "success")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/pools/{pool_id}/reconcile")
def admin_reconcile_pool(request: Request, pool_id: int, db: Session = Depends(get_db)):
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    pool = db.get(ExitPool, pool_id)
    if pool:
        try:
            results = pool_ops.reconcile_pool(db, pool)
            ok = sum(1 for r in results if r.get("ok"))
            flash(request, f"Синхронизация пула «{pool.name}»: {ok}/{len(results)} выходов ok", "success")
        except Exception as e:
            log.exception("reconcile failed")
            flash(request, f"Синхронизация не удалась: {e}", "error")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/pools/{pool_id}/delete")
def admin_delete_pool(request: Request, pool_id: int, db: Session = Depends(get_db)):
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    pool = db.get(ExitPool, pool_id)
    if pool:
        users = [r.name for r in pool.routes]
        if users:
            # Refused while routes use it: deleting would cut their clients off in
            # one click (and drop the pool identity their configs are built on).
            flash(request, f"Пул «{pool.name}» используют маршруты: {', '.join(users)} — "
                           f"сначала удалите их", "error")
            return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)
        # SQLite doesn't enforce ON DELETE, so detach member nodes by hand.
        db.query(Node).filter(Node.pool_id == pool.id).update(
            {Node.pool_id: None, Node.sync_state: "pending"}
        )
        db.delete(pool)
        db.commit()
        flash(request, "Пул удалён", "success")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


# --- admin: monitoring --------------------------------------------------
@app.get("/admin/monitor", response_class=HTMLResponse)
def admin_monitor(request: Request, db: Session = Depends(get_db)):
    admin = _require_staff(request, db)
    if not admin:
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    nodes_all = db.query(Node).order_by(Node.id).all()
    history = [(n, monitor.node_history(db, n.id, limit=12)) for n in nodes_all]
    return render(request, "admin_monitor.html", user=admin,
                  snap=monitor.get_state(db), tg=appconfig.tg_config(db), history=history)


@app.get("/admin/journal", response_class=HTMLResponse)
def admin_journal(request: Request, days: int = 30, db: Session = Depends(get_db)):
    """Gate journal: per gate — reachable from the Hub / from abroad, since when,
    traffic and clients while it lived, recent flips (see app/journal.py)."""
    from . import journal

    admin = _require_staff(request, db)
    if not admin:
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    days = max(1, min(int(days), 90))
    gates = db.query(Node).filter(Node.role == ROLE_GATE).order_by(Node.id).all()
    reports = [journal.gate_report(db, g, days) for g in gates]
    return render(request, "admin_journal.html", user=admin, reports=reports, days=days,
                  every=settings.journal_minutes)


@app.post("/admin/journal/run")
def admin_journal_run(request: Request, db: Session = Depends(get_db)):
    """Take a journal sample now (in the background: one SSH per gate)."""
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    import threading
    from . import tgbot

    threading.Thread(target=tgbot._journal_cycle, name="journal-now", daemon=True).start()
    flash(request, "Замер запущен — обновите страницу через минуту", "success")
    return RedirectResponse("/admin/journal", status_code=HTTP_303_SEE_OTHER)


# --- admin: DNS providers + route client address ------------------------
@app.post("/admin/dns")
def admin_add_dns(
    request: Request, name: str = Form(...), kind: str = Form(...), zone: str = Form(...),
    token: str = Form(""), db: Session = Depends(get_db),
):
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    name, zone = name.strip(), zone.strip().rstrip(".").lower()
    if not name or not zone or kind not in DNS_KINDS or not token.strip():
        flash(request, "Укажите имя, тип, зону и API-токен", "error")
    elif db.query(DnsProvider).filter_by(name=name).first():
        flash(request, "DNS-провайдер с таким именем уже есть", "error")
    else:
        p = DnsProvider(name=name, kind=kind, zone=zone)
        p.token = token.strip()  # encrypted via setter
        db.add(p)
        db.commit()
        flash(request, f"DNS-провайдер «{name}» ({zone}) добавлен", "success")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/dns/{pid}/delete")
def admin_delete_dns(request: Request, pid: int, db: Session = Depends(get_db)):
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    p = db.get(DnsProvider, pid)
    if p:
        users = sorted({rp.route.name for rp in
                        db.query(RouteProto).filter(RouteProto.dns_provider_id == p.id).all()})
        if users:
            flash(request, f"DNS-провайдер «{p.name}» используют маршруты: {', '.join(users)}", "error")
        else:
            db.delete(p)
            db.commit()
            flash(request, f"DNS-провайдер «{p.name}» удалён", "success")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/monitor/check")
def admin_monitor_check(request: Request, db: Session = Depends(get_db)):
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    try:
        monitor.run_checks(db)
        flash(request, "Проверка выполнена", "success")
    except Exception as e:
        log.exception("monitor check failed")
        flash(request, f"Проверка не удалась: {e}", "error")
    return RedirectResponse("/admin/monitor", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/monitor/settings")
def admin_monitor_settings(
    request: Request,
    token: str = Form(""),
    chats: str = Form(""),
    backup_hour: int = Form(6),
    monitor_minutes: int = Form(60),
    api_base: str = Form("https://api.telegram.org"),
    clear_token: str = Form(""),
    db: Session = Depends(get_db),
):
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    # Blank token field keeps the current token; the "очистить" checkbox clears it.
    tok: str | None
    if clear_token:
        tok = ""
    elif token.strip():
        tok = token.strip()
    else:
        tok = None
    appconfig.set_tg_config(db, token=tok, chats=chats, backup_hour=backup_hour,
                            monitor_minutes=monitor_minutes,
                            api_base=api_base.strip() or "https://api.telegram.org")
    flash(request, "Настройки бота сохранены (применятся в течение минуты)", "success")
    return RedirectResponse("/admin/monitor", status_code=HTTP_303_SEE_OTHER)


# --- admin: traffic -----------------------------------------------------
@app.get("/admin/traffic", response_class=HTMLResponse)
def admin_traffic(request: Request, db: Session = Depends(get_db)):
    admin = _require_staff(request, db)
    if not admin:
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    users = db.query(User).order_by(User.username).all()
    stats = {s.device_id: s for s in db.query(TrafficStat).all()}
    return render(request, "admin_traffic.html", user=admin, users=users, stats=stats,
                  updated=traffic_ops.last_updated(db))


@app.post("/admin/traffic/collect")
def admin_traffic_collect(request: Request, db: Session = Depends(get_db)):
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    try:
        info = traffic_ops.collect_traffic(db)
        flash(request, f"Трафик собран (ноды: ok {info['members_ok']}, ошибок {info['members_fail']})", "success")
    except Exception as e:
        log.exception("traffic collect failed")
        flash(request, f"Сбор трафика не удался: {e}", "error")
    return RedirectResponse("/admin/traffic", status_code=HTTP_303_SEE_OTHER)


@app.get("/admin/users", response_class=HTMLResponse)
def admin_users(request: Request, db: Session = Depends(get_db)):
    admin = _require_staff(request, db)
    if not admin:
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    users = db.query(User).order_by(User.id).all()
    groups = db.query(Group).order_by(Group.name).all()
    return render(request, "admin_users.html", user=admin, users=users, groups=groups)


# --- admin: notifications (admin -> clients) ----------------------------
@app.get("/admin/notifications", response_class=HTMLResponse)
def admin_notifications(request: Request, db: Session = Depends(get_db)):
    admin = _require_staff(request, db)
    if not admin:
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    items = db.query(Announcement).order_by(Announcement.created_at.desc()).all()
    groups = db.query(Group).order_by(Group.name).all()
    return render(request, "admin_notifications.html", user=admin, items=items, groups=groups)


@app.post("/admin/notifications")
def admin_add_notification(
    request: Request, text: str = Form(""),
    group_ids: list[int] = Form(default=[]),
    db: Session = Depends(get_db),
):
    staff = _require_staff(request, db)
    if not staff:
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    text = text.strip()
    if not text:
        flash(request, "Пустое уведомление", "error")
    else:
        a = Announcement(text=text, active=True, created_by=staff.id)
        if group_ids:
            a.groups = db.query(Group).filter(Group.id.in_(group_ids)).all()
        db.add(a)
        db.commit()
        target = "всем клиентам" if not group_ids else f"группам: {', '.join(g.name for g in a.groups)}"
        flash(request, f"Уведомление опубликовано — {target}", "success")
    return RedirectResponse("/admin/notifications", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/notifications/{item_id}/toggle")
def admin_toggle_notification(request: Request, item_id: int, db: Session = Depends(get_db)):
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    a = db.get(Announcement, item_id)
    if a:
        a.active = not a.active
        db.commit()
        flash(request, "Показано клиентам" if a.active else "Снято с показа (осталось в журнале)", "success")
    return RedirectResponse("/admin/notifications", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/notifications/{item_id}/delete")
def admin_delete_notification(request: Request, item_id: int, db: Session = Depends(get_db)):
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    a = db.get(Announcement, item_id)
    if a:
        db.delete(a)
        db.commit()
        flash(request, "Уведомление удалено из журнала", "success")
    return RedirectResponse("/admin/notifications", status_code=HTTP_303_SEE_OTHER)


# --- admin: recommended client apps (shown in the «add device» form) ------
def _app_fields(protocol: str, platform: str, name: str, version: str, url: str, note: str,
                position: str) -> tuple[dict | None, str]:
    """Validate a client-app form; (fields, '') or (None, error)."""
    name, url = name.strip(), url.strip()
    if protocol not in ALL_PROTOCOLS:
        return None, "Выберите протокол"
    if platform not in APP_PLATFORMS:
        return None, "Выберите платформу"
    if not name:
        return None, "Укажите название приложения"
    if not (url.startswith("https://") or url.startswith("http://")):
        return None, "Ссылка должна начинаться с https://"
    pos = int(position) if position.strip().lstrip("-").isdigit() else 100
    return {"protocol": protocol, "platform": platform, "name": name[:64],
            "version": version.strip()[:32], "url": url[:512], "note": note.strip()[:255],
            "position": pos}, ""


@app.get("/admin/apps", response_class=HTMLResponse)
def admin_apps(request: Request, db: Session = Depends(get_db)):
    admin = _require_staff(request, db)
    if not admin:
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    apps = db.query(ClientApp).order_by(ClientApp.protocol, ClientApp.position, ClientApp.id).all()
    return render(request, "admin_apps.html", user=admin, apps=apps, protocols=ALL_PROTOCOLS,
                  protocol_labels=PROTOCOL_LABELS, platforms=APP_PLATFORMS)


@app.post("/admin/apps")
def admin_add_app(
    request: Request, protocol: str = Form(""), platform: str = Form(""), name: str = Form(""),
    version: str = Form(""), url: str = Form(""), note: str = Form(""), position: str = Form("100"),
    db: Session = Depends(get_db),
):
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    f, err = _app_fields(protocol, platform, name, version, url, note, position)
    if err:
        flash(request, err, "error")
    else:
        db.add(ClientApp(**f))
        db.commit()
        flash(request, f"«{f['name']}» добавлено в рекомендованные для {PROTOCOL_LABELS[f['protocol']]}", "success")
    return RedirectResponse("/admin/apps", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/apps/{app_id}")
def admin_edit_app(
    request: Request, app_id: int, protocol: str = Form(""), platform: str = Form(""),
    name: str = Form(""), version: str = Form(""), url: str = Form(""), note: str = Form(""),
    position: str = Form("100"), db: Session = Depends(get_db),
):
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    a = db.get(ClientApp, app_id)
    f, err = _app_fields(protocol, platform, name, version, url, note, position)
    if a is None:
        return RedirectResponse("/admin/apps", status_code=HTTP_303_SEE_OTHER)
    if err:
        flash(request, err, "error")
    else:
        for k, v in f.items():
            setattr(a, k, v)
        db.commit()
        flash(request, f"«{a.name}» сохранено", "success")
    return RedirectResponse("/admin/apps", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/apps/{app_id}/toggle")
def admin_toggle_app(request: Request, app_id: int, db: Session = Depends(get_db)):
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    a = db.get(ClientApp, app_id)
    if a:
        a.enabled = not a.enabled
        db.commit()
        flash(request, f"«{a.name}» {'показывается клиентам' if a.enabled else 'скрыто от клиентов'}", "success")
    return RedirectResponse("/admin/apps", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/apps/{app_id}/delete")
def admin_delete_app(request: Request, app_id: int, db: Session = Depends(get_db)):
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    a = db.get(ClientApp, app_id)
    if a:
        db.delete(a)
        db.commit()
        flash(request, f"«{a.name}» удалено из списка", "success")
    return RedirectResponse("/admin/apps", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/users")
def admin_add_user(
    request: Request,
    username: str = Form(...),
    role: str = Form(ROLE_CLIENT),
    db: Session = Depends(get_db),
):
    staff = _require_staff(request, db)
    if not staff:
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    username = username.strip()
    role = role if role in USER_ROLES else ROLE_CLIENT
    if role in (ROLE_ADMIN, ROLE_OPERATOR) and not staff.is_admin:
        flash(request, "Заводить операторов/админов может только админ", "error")
    elif not username:
        flash(request, "Укажите логин", "error")
    elif db.query(User).filter_by(username=username).first():
        flash(request, "Пользователь уже существует", "error")
    else:
        db.add(User(
            username=username,
            password_hash=hash_password(settings.default_user_password),
            role=role,
            created_by=staff.id,
            must_change_password=True,
        ))
        db.commit()
        flash(request,
              f"Пользователь «{username}» (роль: {role}) создан. Временный пароль: "
              f"{settings.default_user_password} — сменит при первом входе.", "success")
    return RedirectResponse("/admin/users", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/users/{user_id}/role")
def admin_set_user_role(
    request: Request, user_id: int, role: str = Form(...), db: Session = Depends(get_db)
):
    """Change a user's role — admin only (the one power operators lack)."""
    admin = _require_admin(request, db)
    if not admin:
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    target = db.get(User, user_id)
    if not target or role not in USER_ROLES:
        flash(request, "Пользователь не найден или роль неверна", "error")
    elif target.role == ROLE_ADMIN and role != ROLE_ADMIN and _admin_count(db) <= 1:
        flash(request, "Нельзя снять последнего админа", "error")
    else:
        target.role = role
        db.commit()
        flash(request, f"Роль «{target.username}»: {role}", "success")
    return RedirectResponse("/admin/users", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/users/{user_id}/group")
def admin_toggle_user_group(
    request: Request, user_id: int,
    group_id: int = Form(...), action: str = Form("add"),
    db: Session = Depends(get_db),
):
    """Add or remove ONE group on a user — the per-user, scalable way to manage
    membership (a chip to drop, a dropdown to add), instead of a users×groups grid."""
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    target = db.get(User, user_id)
    group = db.get(Group, group_id)
    if target and group:
        if action == "remove" and group in target.groups:
            target.groups.remove(group)
            db.commit()
            flash(request, f"«{target.username}» убран из «{group.name}»", "success")
        elif action == "add" and group not in target.groups:
            target.groups.append(group)
            db.commit()
            flash(request, f"«{target.username}» добавлен в «{group.name}»", "success")
    return RedirectResponse("/admin/users", status_code=HTTP_303_SEE_OTHER)


def _admin_count(db: Session) -> int:
    return db.query(User).filter_by(role=ROLE_ADMIN).count()


@app.post("/admin/users/{user_id}/delete")
def admin_delete_user(request: Request, user_id: int, db: Session = Depends(get_db)):
    staff = _require_staff(request, db)
    if not staff:
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    target = db.get(User, user_id)
    if not target:
        flash(request, "Пользователь не найден", "error")
    elif target.id == staff.id:
        flash(request, "Нельзя удалить самого себя", "error")
    elif target.is_staff and not staff.is_admin:
        flash(request, "Удалять операторов/админов может только админ", "error")
    elif target.role == ROLE_ADMIN and _admin_count(db) <= 1:
        flash(request, "Нельзя удалить последнего админа", "error")
    else:
        db.delete(target)
        db.commit()
        flash(request, "Пользователь удалён", "success")
    return RedirectResponse("/admin/users", status_code=HTTP_303_SEE_OTHER)
