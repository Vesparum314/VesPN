"""Symmetric encryption for secrets stored in the DB (node SSH passwords,
3x-ui API tokens). Key is derived from PANEL_SECRET_KEY so there is nothing
extra to manage; rotating PANEL_SECRET_KEY invalidates stored secrets (re-enter
them), which is the intended safety property."""

from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from .config import settings


def _fernet() -> Fernet:
    digest = hashlib.sha256(settings.secret_key.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt(plaintext: str | None) -> str | None:
    if plaintext is None or plaintext == "":
        return plaintext
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(token: str | None) -> str | None:
    if token is None or token == "":
        return token
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except InvalidToken:
        # Wrong/rotated key — treat as unset so the UI prompts to re-enter.
        return None
