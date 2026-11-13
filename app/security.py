"""Password hashing + session helpers."""

from __future__ import annotations

import bcrypt
from starlette.requests import Request

from .models import User


def _b(password: str) -> bytes:
    # bcrypt limit is 72 bytes; truncating is standard and avoids backend errors.
    return password.encode("utf-8")[:72]


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_b(password), bcrypt.gensalt()).decode("ascii")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(_b(password), hashed.encode("ascii"))
    except (ValueError, TypeError):
        return False


# --- password policy ------------------------------------------------------
# Deliberately modest: length + letters and digits. No special characters required.
MIN_PASSWORD_LEN = 8
PASSWORD_RULES = f"не короче {MIN_PASSWORD_LEN} символов, буквы и цифры"
# Passwords that technically pass the rules but sit at the top of every guess list.
_COMMON = {
    "password1", "password12", "password123", "passw0rd", "qwerty12", "qwerty123", "qwerty1234",
    "1q2w3e4r", "1q2w3e4r5t", "1qaz2wsx", "zaq12wsx", "q1w2e3r4", "qwe12345", "abc12345",
    "abcd1234", "a1234567", "a12345678", "12345678a", "123456789a", "admin123", "admin1234",
    "iloveyou1", "welcome1", "letmein1", "changeme1", "change-me-123", "йцукен123",
}


def password_problem(password: str, username: str | None = None) -> str | None:
    """Why `password` is not acceptable (Russian, for the UI), or None if it is."""
    if len(password) < MIN_PASSWORD_LEN:
        return f"Пароль должен быть не короче {MIN_PASSWORD_LEN} символов"
    if not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password):
        return "Пароль должен содержать и буквы, и цифры"
    low = password.lower()
    login = (username or "").strip().lower()
    if len(login) >= 3 and login in low:
        return "Пароль не должен содержать логин"
    if low in _COMMON:
        return "Этот пароль слишком распространён — выберите другой"
    return None


def login_session(request: Request, user: User) -> None:
    request.session["uid"] = user.id


def logout_session(request: Request) -> None:
    request.session.clear()


def current_user(request: Request, db) -> User | None:
    uid = request.session.get("uid")
    if not uid:
        return None
    return db.get(User, uid)
