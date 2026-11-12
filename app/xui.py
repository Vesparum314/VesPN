"""Client for the 3x-ui panel API (token-authenticated, client-centric fork).

This fork of 3x-ui:
  * authenticates the whole `/panel/api/...` surface with
    `Authorization: Bearer <XUI_API_TOKEN>` (no login/session needed);
  * models clients as first-class entities (by `email`) attached to one or more
    inbounds via `inboundIds`, under `/panel/api/clients/*`;
  * builds share links server-side: `GET /panel/api/clients/links/{email}`
    returns ready, correct `vless://` links (right SNI/shortId/spiderX/fp), so
    we never hand-assemble them.

The panel reaches the API over an SSH tunnel to the node's 127.0.0.1:<panel_port>.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

import requests

log = logging.getLogger("vpnpanel.xui")

# 3x-ui keeps its own SQLite (WAL) and writes to it constantly (traffic stats,
# xray reloads), so a write of ours (add/update client, edit inbound) can land on
# a momentary "database is locked" even though the node is healthy. It clears in
# well under a second, so we retry the API call a few times before giving up.
_LOCK_HINT = "database is locked"


class XUIError(RuntimeError):
    pass


@dataclass
class VlessInbound:
    inbound_id: int
    port: int
    remark: str


class XUIClient:
    def __init__(self, base_url: str, token: str, timeout: int = 20, retries: int = 5):
        # base_url e.g. http://127.0.0.1:<localport>/<webBasePath>
        self.base = base_url.rstrip("/")
        self.s = requests.Session()
        self.s.headers["Authorization"] = f"Bearer {token}"
        self.s.headers["Accept"] = "application/json"
        self.timeout = timeout
        self.retries = max(1, retries)

    # --- low level -------------------------------------------------------
    def _get(self, path: str) -> dict:
        return self._request("get", path)

    def _post_json(self, path: str, payload: dict | None = None) -> dict:
        return self._request("post", path, payload)

    def _request(self, method: str, path: str, payload: dict | None = None) -> dict:
        """One API call, retrying only a transient 'database is locked' from 3x-ui's
        SQLite with a short backoff."""
        url = self.base + path
        delay, last_msg = 0.3, ""
        for attempt in range(self.retries):
            if method == "post":
                r = self.s.post(url, json=payload or {}, timeout=self.timeout)
            else:
                r = self.s.get(url, timeout=self.timeout)
            r.raise_for_status()
            resp = r.json()
            if resp.get("success"):
                return resp
            msg = resp.get("msg") or "3x-ui API returned success=false"
            if _LOCK_HINT in msg.lower() and attempt < self.retries - 1:
                last_msg = msg
                log.info("3x-ui locked on %s, retry %d/%d", path, attempt + 1, self.retries - 1)
                time.sleep(delay)
                delay = min(delay * 1.6, 2.0)
                continue
            raise XUIError(msg)
        raise XUIError(last_msg or "3x-ui API returned success=false")

    # --- inbounds --------------------------------------------------------
    def list_inbounds(self) -> list[dict]:
        return self._get("/panel/api/inbounds/list")["obj"]

    def find_vless_inbound(self) -> VlessInbound:
        """First enabled VLESS+Reality inbound (the one clients attach to)."""
        for ib in self.list_inbounds():
            if ib.get("protocol") != "vless" or not ib.get("enable", True):
                continue
            stream = ib.get("streamSettings") or {}
            if isinstance(stream, str):
                import json

                stream = json.loads(stream or "{}")
            if stream.get("security") != "reality":
                continue
            return VlessInbound(inbound_id=ib["id"], port=ib["port"], remark=ib.get("remark", ""))
        raise XUIError("no enabled VLESS+Reality inbound found")

    def add_inbound(self, payload: dict) -> dict:
        """Create an inbound. `settings`/`streamSettings`/`sniffing` must be
        JSON strings in the payload (mainline 3x-ui contract)."""
        return self._post_json("/panel/api/inbounds/add", payload)

    def del_inbound(self, inbound_id: int) -> None:
        """Delete an inbound (and its clients). Used to replace an inbound whose
        Reality identity doesn't match the pool's when re-provisioning a clone."""
        self._post_json(f"/panel/api/inbounds/del/{inbound_id}")

    def inbound_reality_private(self, inbound_id: int) -> str | None:
        """The inbound's Reality privateKey (to check it carries the pool identity)."""
        import json

        ib = next((x for x in self.list_inbounds() if x.get("id") == inbound_id), None)
        if ib is None:
            return None
        ss = ib.get("streamSettings") or {}
        if isinstance(ss, str):
            ss = json.loads(ss or "{}")
        return (ss.get("realitySettings") or {}).get("privateKey")

    def update_inbound_port(self, inbound_id: int, new_port: int) -> None:
        """Change an existing inbound's listen port (keeps all other settings).
        3x-ui re-applies the Xray config on update. Used to move VLESS off a
        DPI-blocked port (e.g. 443) so a gate relay can reach the exit."""
        import json

        ib = next((x for x in self.list_inbounds() if x.get("id") == inbound_id), None)
        if ib is None:
            raise XUIError(f"inbound {inbound_id} not found")
        ib["port"] = int(new_port)
        for k in ("settings", "streamSettings", "sniffing"):
            v = ib.get(k)
            if isinstance(v, (dict, list)):
                ib[k] = json.dumps(v)
        self._post_json(f"/panel/api/inbounds/update/{inbound_id}", ib)

    # --- clients ---------------------------------------------------------
    def list_clients(self) -> list[dict]:
        return self._get("/panel/api/clients/list")["obj"]

    def get_client(self, email: str) -> dict | None:
        """Return the client record (or None). The API nests it as obj.client
        alongside externalLinks/inboundIds/usedTraffic."""
        try:
            obj = self._get(f"/panel/api/clients/get/{email}")["obj"]
        except XUIError:
            return None  # "record not found"
        if not obj:
            return None
        return obj.get("client", obj)

    def client_exists(self, email: str) -> bool:
        return self.get_client(email) is not None

    def get_client_traffic(self, email: str) -> tuple[int, int]:
        """(up, down) bytes for a client, cumulative since the last counter reset.
        The fork exposes split up/down at clients/traffic/<email> (obj.up / obj.down);
        `clients/get` only carries a combined `usedTraffic` int. (0, 0) if unknown.
        up = client→server, down = server→client."""
        try:
            obj = self._get(f"/panel/api/clients/traffic/{email}")["obj"]
        except Exception:
            return (0, 0)
        if not isinstance(obj, dict):
            return (0, 0)
        try:
            return (int(obj.get("up", 0) or 0), int(obj.get("down", 0) or 0))
        except (TypeError, ValueError):
            return (0, 0)

    def add_client(
        self,
        email: str,
        inbound_ids: list[int],
        flow: str = "xtls-rprx-vision",
        enable: bool = True,
        client_id: str | None = None,
        sub_id: str | None = None,
    ) -> dict:
        """Create one client attached to the given inbounds.

        For a POOL of cloned exits the client's UUID (`id`) must be identical on
        every exit — otherwise a `vless://` link issued against one exit would not
        authenticate on another after a failover. So the panel generates the uuid
        (and subId) itself and forces them here; when omitted the server assigns
        them (standalone use). Returns the created client record."""
        client: dict = {"email": email, "flow": flow, "enable": enable}
        if client_id:
            client["id"] = client_id
        if sub_id:
            client["subId"] = sub_id
        payload = {"client": client, "inboundIds": inbound_ids}
        self._post_json("/panel/api/clients/add", payload)
        created = self.get_client(email)
        if created is None:
            raise XUIError(f"client {email!r} not found after add")
        return created

    def list_client_emails(self) -> set[str]:
        """Emails of all clients on the panel (a pool exit has only ours), used
        to converge an exit to the pool's desired client set during reconcile."""
        return {c.get("email", "") for c in self.list_clients() if c.get("email")}

    def get_client_links(self, email: str) -> list[str]:
        """Ready-made share links (vless://...) built by the panel server."""
        return self._get(f"/panel/api/clients/links/{email}")["obj"] or []

    def get_sub_links(self, sub_id: str) -> list[str]:
        return self._get(f"/panel/api/clients/subLinks/{sub_id}")["obj"] or []

    def del_client(self, email: str) -> None:
        self._post_json(f"/panel/api/clients/del/{email}")
