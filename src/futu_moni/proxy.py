"""PF-based MITM proxy for intercepting FTNN's FT protocol login.

Sets up macOS route + PF rdr rules to redirect FTNN's outbound connections
through a local proxy. When FTNN logs in, the proxy captures the authenticated
remote socket for query injection.

Requires root privileges for pfctl and route commands.
"""

from __future__ import annotations

import logging
import select
import socket
import struct
import subprocess
import threading
from dataclasses import dataclass

from futu_moni.protocol import (
    CMD_LOGIN,
    HEADER_LENGTH,
    MAX_BODY_LENGTH,
    SocketLike,
    decode_varint,
)

logger = logging.getLogger(__name__)

KNOWN_FUTU_SERVERS = (
    "170.106.62.204", "170.106.48.217", "170.106.49.111",
    "170.106.201.247", "170.106.201.73",
    "43.130.30.145", "43.130.30.93",
    "43.175.134.104",
    "43.135.64.109", "43.135.82.18",
    "43.132.138.67",
    "43.152.136.145", "43.152.2.73",
    "43.159.177.6",
    "119.28.37.206", "119.28.37.77",
    "49.51.78.222", "49.51.78.82", "49.51.78.83",
    "49.234.241.65",
    "124.156.234.231", "124.156.233.215",
    "129.226.111.140",
)

DEFAULT_FORWARD_SERVER = "119.28.37.206"
PROXY_PORT = 19443


@dataclass
class ProxyConfig:
    forward_server: str = DEFAULT_FORWARD_SERVER
    forward_port: int = 443
    proxy_port: int = PROXY_PORT
    login_timeout_seconds: float = 120.0
    extra_servers: tuple[str, ...] = ()


@dataclass
class ProxySession:
    socket: SocketLike
    user_id: int


def _ft_frame(data: bytes | bytearray, offset: int = 0):
    if len(data) - offset < HEADER_LENGTH:
        return None, offset
    if data[offset:offset + 2] != b"FT" or data[offset + 2] != 0x27:
        return None, offset
    body_len = struct.unpack(">I", data[offset + 18:offset + 22])[0]
    if body_len > MAX_BODY_LENGTH:
        return None, offset
    total = HEADER_LENGTH + body_len
    if len(data) - offset < total:
        return None, offset
    cmd = struct.unpack(">H", data[offset + 16:offset + 18])[0]
    ext = struct.unpack(">H", data[offset + 30:offset + 32])[0]
    return (cmd, bytes(data[offset:offset + total]), ext), offset + total


class _ProxyBridge:
    """Manages the PF rules, routes, and proxy listener for one login cycle."""

    def __init__(self, config: ProxyConfig) -> None:
        self.config = config
        self._stop = threading.Event()
        self._login_done = threading.Event()
        self._session: ProxySession | None = None
        self._lock = threading.Lock()
        all_servers = set(KNOWN_FUTU_SERVERS) | set(config.extra_servers)
        self._trap_ips = sorted(ip for ip in all_servers if ip != config.forward_server)

    def _setup_routes(self) -> None:
        for ip in self._trap_ips:
            subprocess.run(
                ["route", "add", "-host", ip, "-interface", "lo0"],
                capture_output=True,
            )

    def _setup_pf(self) -> None:
        rule = f"rdr pass on lo0 proto tcp from any to any port 443 -> 127.0.0.1 port {self.config.proxy_port}\n"
        subprocess.run(["pfctl", "-ef", "-"], input=rule, capture_output=True, text=True)

    def _cleanup_routes(self) -> None:
        for ip in self._trap_ips:
            subprocess.run(
                ["route", "delete", "-host", ip],
                capture_output=True,
            )

    def _cleanup_pf(self) -> None:
        subprocess.run(["pfctl", "-d"], capture_output=True)

    def _handle_connection(self, csock: socket.socket) -> None:
        try:
            rsock = socket.create_connection(
                (self.config.forward_server, self.config.forward_port),
                timeout=10,
            )
        except OSError:
            csock.close()
            return

        uid = None
        logged = False

        try:
            while not self._stop.is_set():
                readable, _, _ = select.select([csock, rsock], [], [], 1.0)
                for s in readable:
                    if s is csock:
                        d = csock.recv(65536)
                        if not d:
                            return
                        buf = bytearray(d)
                        off = 0
                        while off < len(buf):
                            res, noff = _ft_frame(buf, off)
                            if not res:
                                break
                            cmd, fb, ext = res
                            off = noff
                            if cmd == CMD_LOGIN:
                                uid = struct.unpack(">I", fb[8:12])[0] >> 8
                                logger.debug("proxy: LOGIN detected user=***%s", str(uid)[-3:])
                        rsock.sendall(d)
                    elif s is rsock:
                        d = rsock.recv(65536)
                        if not d:
                            return
                        buf = bytearray(d)
                        off = 0
                        while off < len(buf):
                            res, noff = _ft_frame(buf, off)
                            if not res:
                                break
                            cmd, fb, ext = res
                            off = noff
                            if cmd == CMD_LOGIN and uid:
                                payload = fb[HEADER_LENGTH + ext:]
                                if len(payload) >= 2:
                                    _, p = decode_varint(payload, 0)
                                    rv, _ = decode_varint(payload, p)
                                    if rv == 0:
                                        logged = True
                                        with self._lock:
                                            self._session = ProxySession(socket=rsock, user_id=uid)
                                        logger.info("proxy: LOGIN success")
                                        self._login_done.set()
                                    else:
                                        logger.warning("proxy: LOGIN rejected (0x%x)", rv)
                        csock.sendall(d)
                        if logged:
                            csock.close()
                            return
        except OSError:
            pass
        finally:
            csock.close()
            if not logged:
                rsock.close()

    def intercept_login(self) -> ProxySession | None:
        """Set up proxy, launch FTNN, wait for login. Returns session or None on timeout."""
        self._setup_routes()
        self._setup_pf()
        logger.info("proxy: PF rules and routes configured (%d IPs trapped)", len(self._trap_ips))

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", self.config.proxy_port))
        srv.listen(20)
        srv.settimeout(2.0)

        def accept_loop():
            while not self._stop.is_set():
                try:
                    c, _ = srv.accept()
                    threading.Thread(target=self._handle_connection, args=(c,), daemon=True).start()
                except socket.timeout:
                    continue
                except OSError:
                    break
            srv.close()

        accept_thread = threading.Thread(target=accept_loop, daemon=True)
        accept_thread.start()

        subprocess.Popen(["open", "/Applications/富途牛牛.app"])
        logger.info("proxy: FTNN launched, waiting for login...")

        self._login_done.wait(timeout=self.config.login_timeout_seconds)
        self._stop.set()

        self._cleanup_routes()
        self._cleanup_pf()

        with self._lock:
            return self._session

    def cleanup(self) -> None:
        self._stop.set()
        self._cleanup_routes()
        self._cleanup_pf()


def obtain_authenticated_session(config: ProxyConfig | None = None) -> ProxySession | None:
    """High-level: intercept FTNN login via MITM proxy, return authenticated session."""
    cfg = config or ProxyConfig()
    bridge = _ProxyBridge(cfg)
    try:
        return bridge.intercept_login()
    except Exception:
        bridge.cleanup()
        raise
