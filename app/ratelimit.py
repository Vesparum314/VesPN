"""Brute-force throttle for the login form.

Failed logins are counted in a sliding window under two keys:
  * (client IP, username) — PER_ACCOUNT failures, then that pair must wait;
  * client IP             — PER_IP failures across any usernames, then the IP waits.
While a key is over its limit the login is refused *without* checking the password,
so a blocked client learns nothing. Nothing is keyed on the username alone: an
attacker must not be able to lock a real user out from elsewhere.

State lives in process memory: it resets on restart, which is fine for slowing
down online guessing (the panel runs a single uvicorn worker). The client IP is
whatever uvicorn resolved — behind a reverse proxy in another container set
FORWARDED_ALLOW_IPS so it is the visitor's address, not the proxy's (README).
"""

from __future__ import annotations

import threading
import time
from collections import deque

WINDOW = 15 * 60       # seconds
PER_ACCOUNT = 5        # failures per (ip, username) within WINDOW
PER_IP = 20            # failures per ip within WINDOW
_SWEEP_AT = 10_000     # prune stale keys once the table grows past this


class LoginThrottle:
    def __init__(self, window: int = WINDOW, per_account: int = PER_ACCOUNT, per_ip: int = PER_IP):
        self.window = window
        self.per_account = per_account
        self.per_ip = per_ip
        self._fails: dict[tuple, deque[float]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _keys(ip: str, username: str) -> tuple[tuple, tuple]:
        return ("acct", ip, username.strip().lower()), ("ip", ip)

    def _recent(self, key: tuple, now: float) -> deque[float] | None:
        dq = self._fails.get(key)
        if dq is None:
            return None
        while dq and dq[0] <= now - self.window:
            dq.popleft()
        if not dq:
            del self._fails[key]
            return None
        return dq

    def retry_after(self, ip: str, username: str) -> int:
        """Seconds until this ip/username may try again; 0 if allowed now."""
        now = time.monotonic()
        acct, per_ip = self._keys(ip, username)
        wait = 0.0
        with self._lock:
            for key, limit in ((acct, self.per_account), (per_ip, self.per_ip)):
                dq = self._recent(key, now)
                if dq is not None and len(dq) >= limit:
                    # the window frees a slot when the oldest counted failure ages out
                    wait = max(wait, dq[-limit] + self.window - now)
        return int(wait) + 1 if wait > 0 else 0

    def fail(self, ip: str, username: str) -> None:
        now = time.monotonic()
        with self._lock:
            for key in self._keys(ip, username):
                self._fails.setdefault(key, deque()).append(now)
            if len(self._fails) > _SWEEP_AT:
                for key in list(self._fails):
                    self._recent(key, now)

    def success(self, ip: str, username: str) -> None:
        """A correct password clears that pair's record (the per-IP one stays)."""
        acct, _ = self._keys(ip, username)
        with self._lock:
            self._fails.pop(acct, None)


login_throttle = LoginThrottle()
