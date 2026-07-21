"""Hosts-based MITM proxy for intercepting FTNN's FT protocol login.

Temporarily redirects FTNN's server domains to localhost via /etc/hosts,
captures the authenticated TCP socket when FTNN logs in, then restores
DNS and injects QUOTE queries on the hijacked connection.

Requires root privileges for /etc/hosts and binding port 443.
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

FUTU_PROXY_DOMAINS = ("nnproxy.futunn.com", "nnproxy2.futunn.com")
HOSTS_MARKER = "# futu-moni-proxy"
HOSTS_PATH = "/etc/hosts"


@dataclass
class ProxyConfig:
    forward_server: str = ""
    forward_port: int = 443
    login_timeout_seconds: float = 120.0
    domains: tuple[str, ...] = FUTU_PROXY_DOMAINS


@dataclass
class ProxySession:
    socket: SocketLike
    user_id: int


def _resolve_forward_server(domains: tuple[str, ...], port: int) -> str:
    """Resolve real server IP from DNS before we modify /etc/hosts."""
    for domain in domains:
        try:
            results = socket.getaddrinfo(domain, port, socket.AF_INET, socket.SOCK_STREAM)
            if results:
                ip = results[0][4][0]
                logger.info("resolved %s -> %s", domain, ip)
                return ip
        except socket.gaierror:
            continue
    raise RuntimeError(f"cannot resolve any of {domains}")


def _flush_dns() -> None:
    subprocess.run(["dscacheutil", "-flushcache"], capture_output=True)
    subprocess.run(["killall", "-HUP", "mDNSResponder"], capture_output=True)


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
    """Manages /etc/hosts redirect and proxy listener for one login cycle."""

    def __init__(self, config: ProxyConfig) -> None:
        self.config = config
        self._stop = threading.Event()
        self._login_done = threading.Event()
        self._session: ProxySession | None = None
        self._lock = threading.Lock()

        if config.forward_server:
            self._forward_ip = config.forward_server
        else:
            self._forward_ip = _resolve_forward_server(
                config.domains, config.forward_port,
            )

    def _setup_hosts(self) -> None:
        domains_str = " ".join(self.config.domains)
        entry = f"127.0.0.1 {domains_str} {HOSTS_MARKER}\n"
        with open(HOSTS_PATH, "r") as f:
            lines = f.readlines()
        lines = [l for l in lines if HOSTS_MARKER not in l]
        lines.append(entry)
        with open(HOSTS_PATH, "w") as f:
            f.writelines(lines)
        _flush_dns()
        logger.info("hosts: redirected %s -> 127.0.0.1", ", ".join(self.config.domains))

    def _cleanup_hosts(self) -> None:
        try:
            with open(HOSTS_PATH, "r") as f:
                lines = f.readlines()
            clean = [l for l in lines if HOSTS_MARKER not in l]
            if len(clean) != len(lines):
                with open(HOSTS_PATH, "w") as f:
                    f.writelines(clean)
                _flush_dns()
                logger.info("hosts: restored")
        except OSError:
            pass

    def _handle_connection(self, csock: socket.socket) -> None:
        try:
            rsock = socket.create_connection(
                (self._forward_ip, self.config.forward_port),
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
        """Set up hosts redirect, launch FTNN, wait for login."""
        self._setup_hosts()

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", self.config.forward_port))
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

        self._cleanup_hosts()

        with self._lock:
            return self._session

    def cleanup(self) -> None:
        self._stop.set()
        self._cleanup_hosts()


def obtain_authenticated_session(config: ProxyConfig | None = None) -> ProxySession | None:
    """High-level: intercept FTNN login via hosts redirect, return authenticated session."""
    cfg = config or ProxyConfig()
    bridge = _ProxyBridge(cfg)
    try:
        return bridge.intercept_login()
    except Exception:
        bridge.cleanup()
        raise
