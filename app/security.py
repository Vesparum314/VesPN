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


def login_session(request: Request, user: User) -> None:
    request.session["uid"] = user.id


def logout_session(request: Request) -> None:
    request.session.clear()


def current_user(request: Request, db) -> User | None:
    uid = request.session.get("uid")
    if not uid:
        return None
    return db.get(User, uid)
