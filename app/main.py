"""FastAPI panel (server A): client self-service + admin node management."""

from __future__ import annotations

import base64
import io
import logging
import time
from pathlib import Path

import qrcode
from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import ChoiceLoader, FileSystemLoader
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.status import HTTP_303_SEE_OTHER

from . import appconfig
from . import fleetkey
from . import jobs
from . import monitor
from . import nodes as node_ops
from . import pool as pool_ops
from . import traffic as traffic_ops
from .config import settings
from .db import get_db, init_db
from .models import (
    JOB_RUNNING,
    PROTO_AWG,
    PROTO_VLESS,
    PROTOCOLS,
    ROLE_ADMIN,
    ROLE_CLIENT,
    ROLE_EXIT,
    ROLE_GATE,
    ROLE_OPERATOR,
    ROLES,
    USER_ROLES,
    Announcement,
    Device,
    ExitPool,
    Group,
    IssuedConfig,
    Node,
    Route,
    Setting,
    TrafficStat,
    User,
)
from .security import current_user, hash_password, login_session, logout_session, verify_password

log = logging.getLogger("vpnpanel")
logging.basicConfig(level=logging.INFO)

BASE_DIR = Path(__file__).parent
app = FastAPI(title="VPN self-service panel")

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
            u = db.get(User, uid)
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
        user = db.get(User, uid)
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
    user = db.query(User).filter_by(username=username).first()
    if not user or not verify_password(password, user.password_hash):
        flash(request, "Неверный логин или пароль", "error")
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
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
    return render(request, "change_password.html", user=user, forced=user.must_change_password)


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
    if len(new_password) < 6:
        flash(request, "Пароль должен быть не короче 6 символов", "error")
    elif new_password != confirm:
        flash(request, "Пароли не совпадают", "error")
    elif new_password == settings.default_user_password:
        flash(request, "Выберите пароль, отличный от временного", "error")
    else:
        user.password_hash = hash_password(new_password)
        user.must_change_password = False
        db.commit()
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
    usable = [r for r in routes if not r.is_blocked]
    return render(
        request, "dashboard.html",
        user=user, devices=user.devices, protocols=PROTOCOLS,
        service_ready=bool(usable), routes=routes,
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
    if route.is_blocked:
        flash(request, "Маршрут временно недоступен — попробуйте позже", "error")
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
    return render(
        request, "device.html",
        user=user, device=device, route=route, cfg=cfg, qr=qr, error=error,
        is_awg=(device.protocol == PROTO_AWG), ios_conf=ios_conf, ios_qr=ios_qr,
    )


@app.get("/devices/{device_id}/download")
def device_download(request: Request, device_id: int, fmt: str = "", db: Session = Depends(get_db)):
    owned = _owned_device(request, db, device_id)
    if not owned:
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    _, device = owned
    try:
        cfg = node_ops.get_or_issue_config(db, device)
    except Exception:
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
                return (f"Развёрнут как клон пула: 3x-ui (:{info['xui_port']}) + "
                        f"AmneziaWG (UDP :{info['awg_port']}); синхронизация "
                        f"{'ok' if rec.get('ok') else rec.get('error', '—')}")
            info = node_ops.provision_node(db, node)
            return (f"Развёрнута: 3x-ui (порт {info['xui_port']}) + "
                    f"AmneziaWG (UDP {info['awg_port']})")

        if jobs.start_node_job(db, node, "provision", _do):
            flash(request, f"«{node.name}»: раскатка запущена в фоне — статус обновится на «Парке».", "success")
        else:
            flash(request, f"«{node.name}»: раскатка уже идёт — дождитесь завершения.", "error")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.get("/admin/park/status")
def admin_park_status(request: Request, db: Session = Depends(get_db)):
    """Lightweight poll for «Парк»: ids of nodes whose job is still running. The page
    auto-reloads once a running job leaves this list, so the final result badge shows
    without a manual refresh."""
    if not _require_staff(request, db):
        return JSONResponse({"running": []}, status_code=403)
    running = [nid for (nid,) in db.query(Node.id).filter(Node.job_state == JOB_RUNNING).all()]
    return JSONResponse({"running": running})


@app.post("/admin/nodes/{node_id}/delete")
def admin_delete_node(request: Request, node_id: int, db: Session = Depends(get_db)):
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    node = db.get(Node, node_id)
    if node:
        db.delete(node)
        db.commit()
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


@app.post("/admin/routes")
def admin_add_route(
    request: Request,
    name: str = Form(...),
    gate_id: str = Form(""),
    pool_id: str = Form(""),
    db: Session = Depends(get_db),
):
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    name = name.strip()
    gate_node = db.get(Node, int(gate_id)) if gate_id.strip().isdigit() else None
    pool = db.get(ExitPool, int(pool_id)) if pool_id.strip().isdigit() else None
    if not name:
        flash(request, "Укажите имя маршрута", "error")
    elif db.query(Route).filter_by(name=name).first():
        flash(request, "Маршрут с таким именем уже есть", "error")
    elif not gate_node or gate_node.role != ROLE_GATE:
        flash(request, "Выберите входной сервер (gate)", "error")
    elif not pool:
        flash(request, "Выберите пул выходов", "error")
    else:
        db.add(Route(name=name, gate_id=gate_node.id, pool_id=pool.id))
        db.commit()
        flash(request, f"Маршрут «{name}» создан", "success")
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
        db.delete(route)
        db.commit()
        flash(request, "Маршрут удалён", "success")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/routes/{route_id}/provision_relay")
def admin_provision_relay(request: Request, route_id: int, db: Session = Depends(get_db)):
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    route = db.get(Route, route_id)
    if route and route.gate_node and route.pool:
        gate = route.gate_node
        rid = route.id

        # Raising the relay is a long op too — background it on the gate node, so the
        # «Поднять релей» button reports progress and can't be double-fired.
        def _do(db: Session, gate: Node) -> str:
            route = db.get(Route, rid)
            info = node_ops.provision_gate_for_route(db, route)
            return (f"Релей поднят → пул {info['pool']} "
                    f"({len(info['exits'])} exit, демон {info.get('daemon', '?')})")

        if jobs.start_node_job(db, gate, "relay", _do):
            flash(request, f"«{gate.name}»: подъём релея запущен в фоне — статус на «Парке».", "success")
        else:
            flash(request, f"«{gate.name}»: операция уже идёт — дождитесь завершения.", "error")
    elif route:
        flash(request, "У маршрута должны быть и gate, и пул выходов", "error")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


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
    route_gate_ids = {r.gate_id for r in routes if r.gate_id}
    orphans = [
        n for n in all_nodes
        if (n.role == ROLE_EXIT and n.pool_id is None)
        or (n.role == ROLE_GATE and n.id not in route_gate_ids)
    ]
    free_gates = [n for n in all_nodes if n.role == ROLE_GATE and n.id not in route_gate_ids]
    groups = db.query(Group).order_by(Group.name).all()
    return render(request, "admin_park.html", user=admin, routes=routes, orphans=orphans,
                  free_gates=free_gates, groups=groups,
                  fleet_pub=fleetkey.public_line(db), fleet_fp=fleetkey.fingerprint(db),
                  test_result=request.session.pop("_test", None))


@app.post("/admin/park/route")
def admin_park_create_route(
    request: Request, name: str = Form(...), gate_id: str = Form(""),
    vless_port: int = Form(17771), awg_port: int = Form(17772),
    db: Session = Depends(get_db),
):
    """Create a route = gate + a fresh pool (its shared identity). Exits are added after."""
    if not _require_staff(request, db):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    name = name.strip()
    gate = db.get(Node, int(gate_id)) if gate_id.strip().isdigit() else None
    if not name:
        flash(request, "Укажите имя маршрута", "error")
    elif db.query(Route).filter_by(name=name).first() or db.query(ExitPool).filter_by(name=name).first():
        flash(request, "Имя уже занято", "error")
    elif not gate or gate.role != ROLE_GATE:
        flash(request, "Выберите gate-сервер", "error")
    else:
        pool = pool_ops.create_pool(db, name, vless_port=vless_port, awg_port=awg_port)
        db.add(Route(name=name, gate_id=gate.id, pool_id=pool.id))
        db.commit()
        flash(request, f"Маршрут «{name}» создан. Добавьте выходы и «Поднимите релей».", "success")
    return RedirectResponse("/admin/park", status_code=HTTP_303_SEE_OTHER)


# --- admin: pools -------------------------------------------------------
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
        flash(request, f"Пул «{pool.name}» создан (идентичность сгенерирована)", "success")
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
        # SQLite doesn't enforce ON DELETE, so detach references by hand: unbind
        # member nodes, drop routes on this pool (and unlink their devices).
        db.query(Node).filter(Node.pool_id == pool.id).update(
            {Node.pool_id: None, Node.sync_state: "pending"}
        )
        dead_routes = [r.id for r in db.query(Route).filter(Route.pool_id == pool.id).all()]
        if dead_routes:
            db.query(Device).filter(Device.route_id.in_(dead_routes)).update(
                {Device.route_id: None}, synchronize_session=False
            )
            db.query(Route).filter(Route.id.in_(dead_routes)).delete(synchronize_session=False)
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
