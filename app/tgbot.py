"""Telegram bot (optional) running as background threads in the panel process.

Closes two audit items:
  A. daily message with a BACKUP (panel.db + the secrets needed to restore it)
     plus a stats summary.
  B. MONITORING — hourly checks (via `monitor`), alerts to the admin on change,
     and on-demand /check from Telegram (the admin page has its own button).

Stays dormant unless TG_BOT_TOKEN + TG_ADMIN_CHAT are set. Assumes a single panel
worker (one poller); a module flag guards against a double start in-process.
"""

from __future__ import annotations

import io
import json
import logging
import os
import sqlite3
import tarfile
import tempfile
import threading
import time
from datetime import datetime, timezone

import requests

from . import monitor
from . import nodes as node_ops
from . import traffic
from .config import settings
from .provisioning import TG_PROXY_PORT

log = logging.getLogger("vpnpanel.tgbot")

_started = False

# Live config (token / chats / schedule / api base), refreshed from the DB each
# loop so the UI can enable/change the bot without a restart.
_cfg: dict = {"token": "", "chats": [], "backup_hour": 6, "monitor_minutes": 60,
              "api_base": "https://api.telegram.org", "enabled": False}


def _refresh_cfg() -> None:
    from .db import SessionLocal
    from . import appconfig
    db = SessionLocal()
    try:
        _cfg.update(appconfig.tg_config(db))
    except Exception as e:
        log.warning("tg config read failed: %s", e)
    finally:
        db.close()


# --- Telegram transport: a gate SSH tunnel to an exit's localhost proxy --------
# The bot never reaches Telegram directly (RU blocks it) nor an exit directly (no
# direct Hub→exit). It tunnels Hub→gate→exit (ProxyJump) to the exit's 127.0.0.1
# Caddy proxy. Exits are tried in priority order; the first reachable one is kept,
# with failover to the next on error.
_proxy: dict = {"ssh": None, "fwd": None, "port": None, "exit_id": None, "exit_name": None}
_proxy_lock = threading.Lock()


def _candidate_exits(db):
    from .models import Node, ROLE_EXIT
    return (
        db.query(Node)
        .filter(Node.role == ROLE_EXIT, Node.pool_id.isnot(None))
        .order_by(Node.priority, Node.id)
        .all()
    )


def _probe_proxy(port: int) -> bool:
    try:
        r = requests.get(f"http://127.0.0.1:{port}/bot{_cfg['token']}/getMe", timeout=15)
        return bool(r.json().get("ok"))
    except Exception:
        return False


def _drop_proxy() -> None:
    with _proxy_lock:
        fwd, ssh = _proxy.get("fwd"), _proxy.get("ssh")
        if fwd is not None:
            try:
                fwd.stop()
            except Exception:
                pass
        if ssh is not None:
            try:
                ssh.close()
            except Exception:
                pass
        _proxy.update(ssh=None, fwd=None, port=None, exit_id=None, exit_name=None)


def _ensure_proxy() -> str | None:
    """Local base URL of a live gate→exit TG tunnel, establishing one by exit
    priority if needed. None if no exit is reachable."""
    with _proxy_lock:
        if _proxy["ssh"] is not None and _proxy["port"]:
            return f"http://127.0.0.1:{_proxy['port']}"
    from .db import SessionLocal
    db = SessionLocal()
    try:
        exits = _candidate_exits(db)
    finally:
        db.close()
    for ex in exits:
        try:
            n, port, fwd = node_ops.open_proxy_tunnel(ex, TG_PROXY_PORT)
        except Exception as e:
            log.warning("tg: tunnel to %s failed: %s", ex.name, e)
            continue
        if _probe_proxy(port):
            with _proxy_lock:
                _proxy.update(ssh=n, fwd=fwd, port=port, exit_id=ex.id, exit_name=ex.name)
            log.info("tg: proxying via exit %s", ex.name)
            return f"http://127.0.0.1:{port}"
        try:
            fwd.stop()
        finally:
            n.close()
    log.warning("tg: no reachable exit proxy")
    return None


# --- Telegram API -------------------------------------------------------
def _api(method: str, retries: int = 4, **kw):
    """Call the Telegram API, with retries. Default path: through a gate→exit tunnel
    (exits tried by priority, failover on error). If `api_base` is set to an explicit
    non-default URL it is used directly (manual override). Returns parsed JSON or {}."""
    manual = (_cfg.get("api_base") or "").strip().rstrip("/")
    direct = bool(manual and manual != "https://api.telegram.org")
    last = None
    for _attempt in range(max(1, retries)):
        if direct:
            base = manual
        else:
            base = _ensure_proxy()
            if base is None:
                last = "no reachable exit proxy"
                time.sleep(1.5)
                continue
        try:
            r = requests.post(f"{base}/bot{_cfg['token']}/{method}", timeout=40, **kw)
            return r.json()
        except Exception as e:
            last = e
            if not direct:
                _drop_proxy()  # next attempt re-selects an exit (failover)
            time.sleep(1.5)
    log.warning("tg %s failed after %d tries: %s", method, retries, last)
    return {}


def send_message(chat: str, text: str) -> bool:
    # Telegram caps messages at 4096 chars.
    r = _api("sendMessage", data={"chat_id": chat, "text": text[:4000], "disable_web_page_preview": True})
    return bool(r.get("ok"))


def send_document(chat: str, fname: str, data: bytes, caption: str = "") -> bool:
    # a bigger retry budget — the file upload is the most sensitive to resets
    r = _api("sendDocument", retries=8, data={"chat_id": chat, "caption": caption[:1000]},
             files={"document": (fname, data)})
    return bool(r.get("ok"))


def broadcast(text: str) -> bool:
    """Send to all admin chats; True if at least one delivery succeeded."""
    ok = False
    for c in _cfg["chats"]:
        ok = send_message(c, text) or ok
    return ok


# --- backup + stats (item A) -------------------------------------------
def make_backup() -> tuple[str, bytes]:
    """A restorable backup: a consistent copy of panel.db + the env secrets needed
    to decrypt it (PANEL_SECRET_KEY etc.), as a .tar.gz. SENSITIVE — it lets the
    holder decrypt every stored node credential, so keep the chat private."""
    dbpath = os.path.abspath(settings.database_url.split("sqlite:///", 1)[-1])
    tmp = tempfile.mktemp(suffix=".db")
    try:
        src = sqlite3.connect(dbpath)
        dst = sqlite3.connect(tmp)
        with dst:
            src.backup(dst)  # online backup = never a torn file
        dst.close()
        src.close()
        keys = ["PANEL_SECRET_KEY", "ADMIN_USERNAME", "ADMIN_PASSWORD", "DEFAULT_USER_PASSWORD",
                "PANEL_DOMAIN", "DUCKDNS_TOKEN", "TG_BOT_TOKEN", "TG_ADMIN_CHAT", "DATABASE_URL"]
        env = "\n".join(f"{k}={os.environ[k]}" for k in keys if os.environ.get(k)) + "\n"
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            tar.add(tmp, arcname="panel.db")
            ed = env.encode()
            ti = tarfile.TarInfo("env.txt")
            ti.size = len(ed)
            tar.addfile(ti, io.BytesIO(ed))
        return f"vespn-backup-{datetime.now(timezone.utc):%Y%m%d-%H%M}.tar.gz", buf.getvalue()
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def daily_stats(db) -> str:
    from .models import User, Device, IssuedConfig, Route
    users = db.query(User).count()
    devs = db.query(Device).count()
    vless = db.query(IssuedConfig).filter_by(protocol="vless").count()
    awg = db.query(IssuedConfig).filter_by(protocol="awg").count()
    lines = [
        f"📊 VesPN · сводка {datetime.now(timezone.utc):%Y-%m-%d}",
        f"Пользователей: {users}",
        f"Устройств: {devs} (VLESS {vless}, AWG {awg})",
    ]
    for r in db.query(Route).order_by(Route.name).all():
        pool = r.pool
        synced = len(pool.synced_exits) if pool else 0
        total = len(pool.members) if pool else 0
        lines.append(f"Маршрут {r.name}: пул {pool.name if pool else '—'} — {synced}/{total} выходов синхронизировано")
    return "\n".join(lines)


def _send_backup() -> None:
    from .db import SessionLocal
    db = SessionLocal()
    try:
        stats = daily_stats(db)
    finally:
        db.close()
    fname, data = make_backup()
    for c in _cfg["chats"]:
        send_document(c, fname, data, caption=stats + "\n\n🔐 Бэкап во вложении (храните приватно).")


# --- monitoring + alerts (item B) --------------------------------------
def _monitor_cycle(alert: bool) -> None:
    """Run the checks (always, so the page snapshot stays fresh) and, if the bot
    is enabled, alert the admin when the set of problems changes."""
    from .db import SessionLocal
    from .models import Setting
    db = SessionLocal()
    try:
        snap = monitor.run_checks(db)
        if not alert:
            return
        probs = snap.get("problems", [])
        sig = json.dumps(sorted(probs), ensure_ascii=False)
        s = db.get(Setting, "monitor_last_alert")
        prev = s.value if s else ""
        if sig != prev:
            sent = True
            if probs:
                sent = broadcast("🚨 VesPN мониторинг:\n\n" + monitor.summarize(snap))
            elif prev not in ("", "[]"):
                sent = broadcast("✅ VesPN: проблемы устранены.\n\n" + monitor.summarize(snap))
            if sent:  # only remember the alert once it actually went out (else retry next cycle)
                if s is None:
                    db.add(Setting(key="monitor_last_alert", value=sig))
                else:
                    s.value = sig
                db.commit()
    except Exception as e:
        log.warning("monitor cycle failed: %s", e)
    finally:
        db.close()


def _traffic_cycle() -> None:
    """Collect per-device traffic from the pool (through the gate). Runs regardless
    of whether the bot is enabled — the admin wants the numbers either way."""
    from .db import SessionLocal
    db = SessionLocal()
    try:
        traffic.collect_traffic(db)
    except Exception as e:
        log.warning("traffic cycle failed: %s", e)
    finally:
        db.close()


# --- command handling ---------------------------------------------------
_HELP = (
    "VesPN бот:\n"
    "/check — проверить все серверы сейчас\n"
    "/status — последний результат мониторинга\n"
    "/backup — прислать бэкап + сводку сейчас\n"
    "/help — эта справка"
)


def _handle(chat: str, text: str) -> None:
    from .db import SessionLocal
    cmd = text.split()[0].lower().split("@")[0] if text else ""
    if cmd in ("/start", "/help"):
        send_message(chat, _HELP)
    elif cmd == "/check":
        send_message(chat, "Проверяю…")
        db = SessionLocal()
        try:
            snap = monitor.run_checks(db)
        finally:
            db.close()
        send_message(chat, monitor.summarize(snap))
    elif cmd == "/status":
        db = SessionLocal()
        try:
            snap = monitor.get_state(db)
        finally:
            db.close()
        send_message(chat, monitor.summarize(snap))
    elif cmd == "/backup":
        send_message(chat, "Готовлю бэкап…")
        _send_backup()
    elif cmd:
        send_message(chat, "Не понял. " + _HELP)


def _poll() -> None:
    offset = None
    while True:
        _refresh_cfg()
        if not _cfg["enabled"]:
            time.sleep(15)
            continue
        try:
            r = _api("getUpdates", data={"offset": offset, "timeout": 30})
            for u in r.get("result", []):
                offset = u["update_id"] + 1
                msg = u.get("message") or u.get("edited_message") or {}
                chat = str(msg.get("chat", {}).get("id", ""))
                text = (msg.get("text") or "").strip()
                if chat and chat in _cfg["chats"] and text:
                    try:
                        _handle(chat, text)
                    except Exception as e:
                        log.warning("handle failed: %s", e)
                        send_message(chat, f"Ошибка: {e}")
        except Exception as e:
            log.warning("poll failed: %s", e)
            time.sleep(5)


def _scheduler() -> None:
    last_monitor = 0.0
    last_backup_day = None
    time.sleep(20)  # settle before the first probe
    while True:
        _refresh_cfg()
        try:
            now = datetime.now(timezone.utc)
            # monitoring runs on its cadence regardless (keeps the page fresh);
            # alerts fire only when the bot is enabled.
            if time.monotonic() - last_monitor >= max(60, _cfg["monitor_minutes"] * 60):
                last_monitor = time.monotonic()
                _monitor_cycle(alert=_cfg["enabled"])
                _traffic_cycle()
            if _cfg["enabled"] and now.hour == _cfg["backup_hour"] and last_backup_day != now.date():
                last_backup_day = now.date()
                _send_backup()
        except Exception as e:
            log.warning("scheduler tick failed: %s", e)
        time.sleep(30)


def start_bot() -> None:
    """Start the bot threads once. They self-gate on the live DB config, so they
    idle until a token + chat is configured (UI or .env) — no restart needed."""
    global _started
    if _started:
        return
    _started = True
    threading.Thread(target=_poll, name="tg-poll", daemon=True).start()
    threading.Thread(target=_scheduler, name="tg-sched", daemon=True).start()
    log.info("Telegram bot threads started (idle until configured)")
