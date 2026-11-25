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
# Liveness, not priority, picks the exit: the one that worked last goes first, and an
# exit whose proxy didn't answer is skipped for BAD_FOR seconds (an exit whose network
# can't reach Telegram reliably would otherwise be tried — and waited on — first every
# time). If every exit is benched, all are tried anyway.
BAD_FOR = 1800
_last_good: dict = {"id": None}
_bad_until: dict[int, float] = {}


def _candidate_exits(db):
    from .models import Node, ROLE_EXIT
    exits = (
        db.query(Node)
        .filter(Node.role == ROLE_EXIT, Node.pool_id.isnot(None))
        .order_by(Node.priority, Node.id)
        .all()
    )
    now = time.monotonic()
    fresh = [e for e in exits if _bad_until.get(e.id, 0) <= now] or exits
    fresh.sort(key=lambda e: 0 if e.id == _last_good["id"] else 1)  # stable: priority after
    return fresh


def _bench(exit_id) -> None:
    if exit_id is not None:
        _bad_until[exit_id] = time.monotonic() + BAD_FOR


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
    # Keep the session open while tunnelling: open_proxy_tunnel resolves the exit's
    # gate through the node's session (pool → route → gate). A detached node has no
    # session, so the gate lookup came back empty and every exit failed with
    # «гейт не определён» — the bot never reached Telegram.
    db = SessionLocal()
    try:
        for ex in _candidate_exits(db):
            try:
                n, port, fwd = node_ops.open_proxy_tunnel(ex, TG_PROXY_PORT)
            except Exception as e:
                _bench(ex.id)
                log.warning("tg: tunnel to %s failed: %s", ex.name, e)
                continue
            if _probe_proxy(port):
                with _proxy_lock:
                    _proxy.update(ssh=n, fwd=fwd, port=port, exit_id=ex.id, exit_name=ex.name)
                _last_good["id"] = ex.id
                _bad_until.pop(ex.id, None)
                log.info("tg: proxying via exit %s", ex.name)
                return f"http://127.0.0.1:{port}"
            _bench(ex.id)
            log.warning("tg: tunnel to %s is up but its Telegram proxy did not answer — "
                        "skipped for %d min", ex.name, BAD_FOR // 60)
            try:
                fwd.stop()
            finally:
                n.close()
    finally:
        db.close()
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
                _bench(_proxy.get("exit_id"))
                if _last_good["id"] == _proxy.get("exit_id"):
                    _last_good["id"] = None
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


def enabled() -> bool:
    return bool(_cfg.get("enabled"))


def broadcast(text: str) -> bool:
    """Send to all admin chats; True if at least one delivery succeeded."""
    ok = False
    for c in _cfg["chats"]:
        ok = send_message(c, text) or ok
    return ok


# --- backup + stats (item A) -------------------------------------------
# Telegram bots may send files up to 50 MB.
TG_FILE_LIMIT = 50 * 1024 * 1024
BACKUP_WARN = 40 * 1024 * 1024
# Telemetry: re-collected by itself, not needed to restore the panel — and growing
# fast (server vitals every 5 minutes). Left out of the backup copy; the gate journal
# keeps its last 14 days (recent ban timeline).
_TELEMETRY = ("node_samples", "probe_samples", "probe_incidents")
_ENV_KEYS = ("PANEL_SECRET_KEY", "ADMIN_USERNAME", "ADMIN_PASSWORD", "DEFAULT_USER_PASSWORD",
             "DATABASE_URL", "BRAND_NAME", "THEME_DIR", "SESSION_COOKIE", "SESSION_HTTPS_ONLY",
             "SUB_BASE_URL", "SUB_TITLE", "TG_BOT_TOKEN", "TG_ADMIN_CHAT", "TG_API_BASE",
             "PANEL_DOMAIN", "DUCKDNS_TOKEN")


def make_backup() -> tuple[str, bytes]:
    """A restorable backup: a consistent copy of panel.db (without telemetry) + the
    env secrets needed to decrypt it (PANEL_SECRET_KEY etc.) + the servers' SSH host
    keys, as a .tar.gz. SENSITIVE — it lets the holder decrypt every stored node
    credential, so keep the chat private."""
    dbpath = os.path.abspath(settings.database_url.split("sqlite:///", 1)[-1])
    fd, tmp = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        src = sqlite3.connect(dbpath)
        dst = sqlite3.connect(tmp)
        with dst:
            src.backup(dst)  # online backup = never a torn file
        src.close()
        tables = {r[0] for r in dst.execute("select name from sqlite_master where type='table'")}
        for t in _TELEMETRY:
            if t in tables:
                dst.execute(f"delete from {t}")
        if "gate_samples" in tables:
            dst.execute("delete from gate_samples where at < datetime('now', '-14 days')")
        dst.commit()
        dst.execute("vacuum")
        dst.close()
        env = "\n".join(f"{k}={os.environ[k]}" for k in _ENV_KEYS if os.environ.get(k)) + "\n"
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            tar.add(tmp, arcname="panel.db")
            ed = env.encode()
            ti = tarfile.TarInfo("env.txt")
            ti.size = len(ed)
            tar.addfile(ti, io.BytesIO(ed))
            if os.path.isfile(settings.known_hosts_file):
                tar.add(settings.known_hosts_file, arcname="ssh_known_hosts")
        return f"backup-{datetime.now(timezone.utc):%Y%m%d-%H%M}.tar.gz", buf.getvalue()
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _mb(n: int) -> str:
    return f"{n / 1024 / 1024:.1f} МБ".replace(".", ",")


def daily_stats(db) -> str:
    """The evening summary: people and devices, yesterday's traffic (Moscow day, whole),
    speed incidents of the last 24 h, what needs attention, routes."""
    from datetime import timedelta

    from . import pool as pool_ops, speed
    from .models import Device, ProbeIncident, Route, User
    from .traffic import msk_today

    brand = settings.brand_name
    users = db.query(User).count()
    devices = db.query(Device).all()
    by_proto = {p: sum(1 for d in devices if d.protocol == p) for p in ("vless", "naive", "awg")}
    lines = [
        f"📊 {brand} · сводка {msk_today():%d.%m.%Y}",
        f"Люди: {users} · устройств: {len(devices)} (VLESS {by_proto['vless']}, "
        f"Naive {by_proto['naive']}, AWG {by_proto['awg']})",
    ]
    day = (msk_today() - timedelta(days=1)).isoformat()
    from .traffic import _traffic_for_day
    tot, servers = _traffic_for_day(db, day)
    if tot:
        top = ", ".join(f"{n} {_gb(b)}" for n, b in servers[:4])
        lines.append(f"Трафик за {day[8:10]}.{day[5:7]}: {_gb(tot)} — {top}")
    else:
        lines.append(f"Трафик за {day[8:10]}.{day[5:7]}: нет данных")
    if speed.enabled(db):
        since = datetime.now(timezone.utc) - timedelta(days=1)
        inc = db.query(ProbeIncident).filter(ProbeIncident.at >= since).count()
        lines.append(f"Скорость: провалов за сутки — {inc}" if inc else "Скорость: провалов за сутки нет")
    acc: dict = {}
    lost = sum(1 for d in devices if not pool_ops.device_routes(db, d, acc))
    retiring = [d for d in devices if d.retire_at]
    if lost:
        lines.append(f"⚠️ Устройств без доступа к маршруту: {lost}")
    if retiring:
        first = min(d.retire_at for d in retiring)
        lines.append(f"🗑 Помечено «будет удалено»: {len(retiring)} (с {first:%d.%m})")
    for r in db.query(Route).order_by(Route.name).all():
        pool = r.pool
        synced = len(pool.synced_exits) if pool else 0
        total = len(pool.members) if pool else 0
        state = "" if r.enabled else " · выключен"
        lines.append(f"Маршрут {r.name}: {r.protocol_label} · выходов в строю {synced}/{total}{state}")
    return "\n".join(lines)


def _gb(n: int) -> str:
    return f"{n / 1024 ** 3:.1f} ГБ".replace(".", ",")


def _send_backup() -> None:
    from .db import SessionLocal
    db = SessionLocal()
    try:
        stats = daily_stats(db)
    finally:
        db.close()
    fname, data = make_backup()
    size = len(data)
    if size >= TG_FILE_LIMIT:
        broadcast(stats + f"\n\n⚠️ Бэкап не отправлен: {_mb(size)} — больше лимита Telegram (50 МБ). "
                          "Снимите копию /data/panel.db с Хаба вручную.")
        return
    note = f"🔐 Бэкап во вложении ({_mb(size)}), храните приватно."
    if size >= BACKUP_WARN:
        note += f"\n⚠️ Размер близок к лимиту Telegram в 50 МБ."
    for c in _cfg["chats"]:
        send_document(c, fname, data, caption=(stats + "\n\n" + note)[-1000:])


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
                sent = broadcast(f"🚨 {settings.brand_name} · мониторинг:\n\n" + monitor.summarize(snap))
            elif prev not in ("", "[]"):
                sent = broadcast(f"✅ {settings.brand_name}: проблемы устранены.\n\n" + monitor.summarize(snap))
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
    "Команды:\n"
    "/check — проверить все серверы сейчас\n"
    "/status — последний результат мониторинга\n"
    "/traffic — трафик за сегодня: серверы и люди\n"
    "/speed — скорость маршрутов и провалы за сутки\n"
    "/backup — прислать бэкап + сводку сейчас\n"
    "/help — эта справка"
)


def traffic_text(db) -> str:
    from .traffic import overview

    ov = overview(db, "today")
    lines = [f"📶 Трафик сегодня (МСК): {_gb(ov['exits_total'])} через выходы"]
    for g in ov["groups"]:
        if not g["total"] and not any(e["total"] for e in g["gates"]):
            continue
        lines.append(f"\n{g['name']}: {_gb(g['total'])}")
        for e in g["exits"]:
            name = e["node"].name if e["node"] else e["name"]
            stale = " ⚠️ не ответил" if e.get("stale") else ""
            lines.append(f"  выход {name}: {_gb(e['total'])}{stale}")
        for e in g["gates"]:
            lines.append(f"  гейт {e['node'].name}: {_gb(e['total'])}")
    people = [p for p in ov["people"] if p["total"]][:5]
    if people:
        lines.append("\nБольше всех:")
        for p in people:
            who = p["user"].username if p["user"] else p["username"]
            lines.append(f"  {who}: {_gb(p['total'])}")
    return "\n".join(lines)


def speed_text(db) -> str:
    from datetime import timedelta

    from . import speed
    from .models import PROTOCOL_LABELS, ProbeIncident

    if not speed.enabled(db):
        return "🐢 Замеры скорости выключены (вкладка «Скорость»)."
    ov = speed.overview(db, 1)
    lines = ["🐢 Скорость маршрутов (последний тяжёлый замер · медиана за сутки):"]
    for r in ov["rows"]:
        h = r["last_heavy"]
        now = (f"{h.mbps:g} Мбит/с" if h and h.ok and h.mbps is not None else
               ("ошибка" if h else "нет замера"))
        med = f" · медиана {r['median']:.0f}" if r["median"] else ""
        lines.append(f"  {r['route'].name} · {PROTOCOL_LABELS.get(r['proto'], r['proto'])} · "
                     f"{r['entry'].name}: {now}{med}")
    since = datetime.now(timezone.utc) - timedelta(days=1)
    inc = (db.query(ProbeIncident).filter(ProbeIncident.at >= since)
           .order_by(ProbeIncident.id.desc()).all())
    if inc:
        lines.append(f"\nПровалов за сутки: {len(inc)}")
        for i in inc[:3]:
            lines.append(f"  {i.at:%H:%M} UTC {i.route.name if i.route else '—'}: {i.reason}")
    else:
        lines.append("\nПровалов за сутки нет.")
    return "\n".join(lines)


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
    elif cmd in ("/traffic", "/speed"):
        db = SessionLocal()
        try:
            send_message(chat, traffic_text(db) if cmd == "/traffic" else speed_text(db))
        finally:
            db.close()
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


def _journal_cycle() -> None:
    """Gate journal + DNS sync (app/journal.py) — runs regardless of the bot."""
    from .db import SessionLocal
    from . import journal

    db = SessionLocal()
    try:
        journal.run_cycle(db)
    except Exception as e:
        log.warning("journal cycle failed: %s", e)
    finally:
        db.close()


def _scheduler() -> None:
    from .config import settings

    last_monitor = 0.0
    last_journal = 0.0
    last_backup_day = None
    last_cert_day = None
    time.sleep(20)  # settle before the first probe
    while True:
        _refresh_cfg()
        try:
            if time.monotonic() - last_journal >= max(60, settings.journal_minutes * 60):
                last_journal = time.monotonic()
                _journal_cycle()
        except Exception as e:
            log.warning("journal tick failed: %s", e)
        try:
            today = datetime.now(timezone.utc).date()
            if last_cert_day != today:  # NaiveProxy certificates: renew what's due
                last_cert_day = today
                from .db import SessionLocal
                from . import naive

                s = SessionLocal()
                try:
                    for msg in naive.renew_all(s):
                        log.info("naive: %s", msg)
                        if _cfg["enabled"]:
                            broadcast(f"🔐 {msg}")
                finally:
                    s.close()
        except Exception as e:
            log.warning("cert tick failed: %s", e)
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
