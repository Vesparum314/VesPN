"""SSH access to a VPN node + on-demand local port-forward tunnels.

The panel manages every node purely over SSH (root). Two things are needed:
  * run shell commands on the node (install 3x-ui, manage the AmneziaWG
    container, read config files);
  * reach services that the node only exposes on 127.0.0.1 (the 3x-ui panel /
    API on 127.0.0.1:29568) by forwarding a local port through the SSH
    transport, exactly like `ssh -L`.

Implemented with paramiko so the panel has no dependency on a system ssh client
and works the same on any OS.
"""

from __future__ import annotations

import select
import socket
import threading
from contextlib import contextmanager
from dataclasses import dataclass

import paramiko


@dataclass
class NodeCredentials:
    host: str
    port: int = 22
    username: str = "root"
    password: str | None = None
    key_filename: str | None = None


class _LocalForward:
    """Listens on a random localhost port and pumps each accepted connection
    through a direct-tcpip channel to (remote_host, remote_port) on the node."""

    def __init__(self, transport: paramiko.Transport, remote_host: str, remote_port: int):
        self.transport = transport
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.local_port: int | None = None
        self._srv: socket.socket | None = None
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self) -> int:
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(16)
        self.local_port = self._srv.getsockname()[1]
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return self.local_port

    def _accept_loop(self) -> None:
        assert self._srv is not None
        self._srv.settimeout(1.0)
        while self._running:
            try:
                conn, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            chan = self.transport.open_channel(
                "direct-tcpip", (self.remote_host, self.remote_port), conn.getpeername()
            )
        except Exception:
            conn.close()
            return
        if chan is None:
            conn.close()
            return
        try:
            while True:
                r, _, _ = select.select([conn, chan], [], [], 1.0)
                if conn in r:
                    data = conn.recv(4096)
                    if not data:
                        break
                    chan.sendall(data)
                if chan in r:
                    data = chan.recv(4096)
                    if not data:
                        break
                    conn.sendall(data)
        except (OSError, EOFError):
            pass
        finally:
            try:
                chan.close()
            finally:
                conn.close()

    def stop(self) -> None:
        self._running = False
        if self._srv is not None:
            try:
                self._srv.close()
            except OSError:
                pass


class SSHNode:
    """A live SSH connection to one node. Reusable for the duration of an operation."""

    def __init__(self, creds: NodeCredentials, jump: NodeCredentials | None = None):
        self.creds = creds
        self.jump = jump  # optional SSH jump host (gate) to tunnel through
        self.client: paramiko.SSHClient | None = None
        self._jump_node: "SSHNode | None" = None

    @property
    def transport(self) -> paramiko.Transport:
        assert self.client is not None, "not connected"
        t = self.client.get_transport()
        assert t is not None
        return t

    def connect(self, timeout: int = 30) -> "SSHNode":
        sock = None
        if self.jump is not None:
            # ProxyJump: open an SSH session to the gate and tunnel a direct-tcpip
            # channel to the target through it. Needed because RU DPI drops the
            # direct Hub→exit handshake for flagged ranges, while the gate reaches
            # the exit fine. The gate only forwards bytes — it never authenticates
            # us to the exit (the exit's own password still applies end to end).
            self._jump_node = SSHNode(self.jump).connect(timeout=timeout)
            sock = self._jump_node.transport.open_channel(
                "direct-tcpip",
                (self.creds.host, self.creds.port),
                ("127.0.0.1", 0),
                timeout=timeout,
            )
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(
            self.creds.host,
            port=self.creds.port,
            username=self.creds.username,
            password=self.creds.password,
            key_filename=self.creds.key_filename,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
            sock=sock,
        )
        self.client = c
        return self

    def run(self, cmd: str, timeout: int = 120) -> tuple[int, str, str]:
        """Run a command; return (exit_code, stdout, stderr)."""
        assert self.client is not None, "not connected"
        stdin, stdout, stderr = self.client.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        rc = stdout.channel.recv_exit_status()
        return rc, out, err

    @contextmanager
    def tunnel(self, remote_port: int, remote_host: str = "127.0.0.1"):
        """Context manager yielding a localhost port forwarded to the node's
        (remote_host, remote_port). Use it to talk to 127.0.0.1-only services."""
        fwd = _LocalForward(self.transport, remote_host, remote_port)
        port = fwd.start()
        try:
            yield port
        finally:
            fwd.stop()

    def close(self) -> None:
        if self.client is not None:
            try:
                self.client.close()
            except Exception:
                pass
            self.client = None
        if self._jump_node is not None:
            try:
                self._jump_node.close()
            except Exception:
                pass
            self._jump_node = None

    def __enter__(self) -> "SSHNode":
        return self.connect()

    def __exit__(self, *exc) -> None:
        self.close()
