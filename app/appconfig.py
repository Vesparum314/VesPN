"""Runtime (DB-backed) configuration for the Telegram bot + monitoring, editable
from the admin UI. Values live in the `settings` key/value table (the bot token
encrypted via Fernet); env vars act as a fallback/bootstrap. The bot reads this
live each loop, so enabling/changing it in the UI takes effect without a restart.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from .config import settings as env
from .crypto import decrypt, encrypt
from .models import Setting

_K_TOKEN = "tg_bot_token"
_K_CHAT = "tg_admin_chat"
_K_BACKUP_HOUR = "tg_backup_hour"
_K_MONITOR_MIN = "tg_monitor_minutes"
_K_API_BASE = "tg_api_base"


def _raw(db: Session, key: str) -> str | None:
    s = db.get(Setting, key)
    v = s.value if s else None
    return v if v not in (None, "") else None


def _norm_base(s: str | None) -> str:
    """Normalize the Telegram API base URL: trim, drop trailing slash, and add
    https:// if the scheme was omitted (a common paste mistake)."""
    s = (s or "").strip().rstrip("/")
    if s and not s.startswith(("http://", "https://")):
        s = "https://" + s
    return s or "https://api.telegram.org"


def tg_config(db: Session) -> dict:
    """Effective config: DB override, else env fallback."""
    tok_enc = _raw(db, _K_TOKEN)
    token = (decrypt(tok_enc) or "") if tok_enc else (env.tg_bot_token or "")
    chat = _raw(db, _K_CHAT) if _raw(db, _K_CHAT) is not None else (env.tg_admin_chat or "")
    chats = [c.strip() for c in (chat or "").split(",") if c.strip()]
    try:
        bh = int(_raw(db, _K_BACKUP_HOUR) or env.tg_backup_hour)
    except (TypeError, ValueError):
        bh = env.tg_backup_hour
    try:
        mm = int(_raw(db, _K_MONITOR_MIN) or env.tg_monitor_minutes)
    except (TypeError, ValueError):
        mm = env.tg_monitor_minutes
    api_base = _norm_base(_raw(db, _K_API_BASE) or env.tg_api_base or "https://api.telegram.org")
    return {
        "token": token,
        "chats": chats,
        "chat_raw": chat or "",
        "backup_hour": max(0, min(23, bh)),
        "monitor_minutes": max(1, mm),
        "api_base": api_base,
        "enabled": bool(token and chats),
        "token_set": bool(token),
    }


def set_tg_config(db: Session, *, token: str | None = None, chats: str | None = None,
                  backup_hour: int | None = None, monitor_minutes: int | None = None,
                  api_base: str | None = None) -> None:
    """Persist UI changes. `token=None` keeps the current token (blank field in a
    form); `token=""` clears it. Everything else is set when provided."""
    def put(key: str, value: str) -> None:
        s = db.get(Setting, key)
        if s is None:
            db.add(Setting(key=key, value=value))
        else:
            s.value = value

    if token is not None:
        put(_K_TOKEN, encrypt(token) or "" if token else "")
    if chats is not None:
        put(_K_CHAT, chats.strip())
    if backup_hour is not None:
        put(_K_BACKUP_HOUR, str(max(0, min(23, int(backup_hour)))))
    if monitor_minutes is not None:
        put(_K_MONITOR_MIN, str(max(1, int(monitor_minutes))))
    if api_base is not None:
        put(_K_API_BASE, _norm_base(api_base))
    db.commit()


# --- temporary password for new / reset accounts ----------------------------
# One for everybody, changeable by the admin from the users page (stored encrypted);
# DEFAULT_USER_PASSWORD from the env until it is set there. Changing it does not touch
# accounts that still carry the previous one — they keep it and stay flagged
# must_change_password until their owner sets a password of their own.
_K_TEMP_PW = "default_user_password"


def temp_password(db: Session) -> str:
    enc = _raw(db, _K_TEMP_PW)
    return (decrypt(enc) or env.default_user_password) if enc else env.default_user_password


def set_temp_password(db: Session, password: str) -> None:
    s = db.get(Setting, _K_TEMP_PW)
    if s is None:
        db.add(Setting(key=_K_TEMP_PW, value=encrypt(password)))
    else:
        s.value = encrypt(password)
    db.commit()


# --- protocol descriptions on the «Мои устройства» form ---------------------
# One line per protocol under the protocol switch, edited by the admin on the
# «Приложения» page; these are the defaults until then.
PROTO_DESC_DEFAULT = {
    "vless": "С подпиской: приложение само переключится, если вход заблокируют.",
    "naive": "Выглядит как обычный HTTPS-сайт, тоже с подпиской.",
    "awg": "Быстрый, без подписки: конфиг на один маршрут, при бане гейта имя само укажет "
           "на живой гейт этого маршрута.",
}
_K_DESC = "proto_desc_{}"


def proto_desc(db: Session) -> dict[str, str]:
    return {p: (_raw(db, _K_DESC.format(p)) or d) for p, d in PROTO_DESC_DEFAULT.items()}


def set_proto_desc(db: Session, protocol: str, text: str) -> None:
    """Empty text restores the default."""
    key = _K_DESC.format(protocol)
    s = db.get(Setting, key)
    text = " ".join(text.split())[:300]
    if s is None:
        db.add(Setting(key=key, value=text))
    else:
        s.value = text
    db.commit()
