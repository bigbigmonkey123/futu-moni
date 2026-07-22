"""Single-phase MITM proxy for intercepting FTNN's FT protocol login.

Preloads candidate IPs from F3CLogin.framework (hardcoded) and
CommonConfig.db (guaranteed_ip_for_conn), routes ALL to lo0, PF-anchor
redirects port 443 → local proxy.  Launches FTNN once (no kill/restart
discovery cycle).  lsof live-monitors for ConnIpRsp dynamic IPs.

Requires root privileges for route/pfctl and lsof.
"""

from __future__ import annotations

import json
import logging
import os
import re
import select
import socket
import struct
import subprocess
import threading
import time
from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path

from futu_moni.protocol import (
    CMD_LOGIN,
    HEADER_LENGTH,
    MAX_BODY_LENGTH,
    SocketLike,
    decode_varint,
)

logger = logging.getLogger(__name__)

PROXY_PORT = 19443
PF_ANCHOR = "stock-moni"
CMD_CONNIP = frozenset({0xFFE1, 0x0529, 0x4EB3})
_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

F3CLOGIN_PATH = (
    "/Applications/富途牛牛.app/Contents/Frameworks/F3CLogin.framework/F3CLogin"
)
COMMONCONFIG_DB_PATH = (
    "~/Library/Containers/cn.futu.niuniu.nx/Data/Library/"
    "Application Support/Common/CommonConfig.db"
)


@dataclass
class ProxyConfig:
    forward_server: str = ""
    forward_port: int = 443
    proxy_port: int = PROXY_PORT
    login_timeout_seconds: float = 120.0


@dataclass
class ProxySession:
    socket: SocketLike
    user_id: int


def _is_public_ip(ip_str: str) -> bool:
    try:
        return IPv4Address(ip_str).is_global
    except ValueError:
        return False


def extract_connip_ips(payload: bytes) -> set[str]:
    """Parse ConnIpRsp protobuf and return server_ip values.

    ConnIpRsp.items is field 3 (tag 0x1a, len-delimited).
    Each ConnIpItem.server_ip is field 1 (tag 0x0a, len-delimited string).
    """
    ips: set[str] = set()
    pos = 0
    while pos < len(payload):
        try:
            tag, pos = decode_varint(payload, pos)
        except Exception:
            break
        field_num, wire_type = tag >> 3, tag & 7
        if wire_type == 0:
            _, pos = decode_varint(payload, pos)
        elif wire_type == 2:
            length, pos = decode_varint(payload, pos)
            if pos + length > len(payload):
                break
            if field_num == 3:
                ips |= _parse_connip_item(payload[pos : pos + length])
            pos += length
        elif wire_type == 1:
            pos += 8
        elif wire_type == 5:
            pos += 4
        else:
            break
    return ips


def _parse_connip_item(data: bytes) -> set[str]:
    """Extract server_ip (field 1) from a single ConnIpItem."""
    ips: set[str] = set()
    pos = 0
    while pos < len(data):
        try:
            tag, pos = decode_varint(data, pos)
        except Exception:
            break
        field_num, wire_type = tag >> 3, tag & 7
        if wire_type == 0:
            _, pos = decode_varint(data, pos)
        elif wire_type == 2:
            length, pos = decode_varint(data, pos)
            if pos + length > len(data):
                break
            if field_num == 1:
                try:
                    ip_str = data[pos : pos + length].decode("ascii")
                    if _is_public_ip(ip_str):
                        ips.add(ip_str)
                except (UnicodeDecodeError, ValueError):
                    pass
            pos += length
        elif wire_type == 1:
            pos += 8
        elif wire_type == 5:
            pos += 4
        else:
            break
    return ips


# ── IP Pool Loading ───────────────────────────────────────


def _load_f3clogin_ips(binary_path: str = F3CLOGIN_PATH) -> set[str]:
    if not Path(binary_path).exists():
        logger.warning("F3CLogin binary not found: %s", binary_path)
        return set()
    result = subprocess.run(
        ["strings", binary_path], capture_output=True, text=True, timeout=30,
    )
    ips = {m.group(1) for m in _IP_RE.finditer(result.stdout) if _is_public_ip(m.group(1))}
    logger.info("loaded %d public IPs from F3CLogin binary", len(ips))
    return ips


def _load_guaranteed_ips(db_path: str = COMMONCONFIG_DB_PATH) -> set[str]:
    expanded = Path(db_path).expanduser()
    if not expanded.exists():
        logger.warning("CommonConfig.db not found: %s", expanded)
        return set()
    result = subprocess.run(
        [
            "sqlite3", str(expanded),
            "SELECT conf_value FROM commonConfigTb WHERE conf_name='guaranteed_ip_for_conn'",
        ],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return set()
    try:
        entries = json.loads(result.stdout)
    except json.JSONDecodeError:
        return set()
    ips: set[str] = set()
    for entry in entries:
        for ip in entry.get("ip", []):
            if _is_public_ip(ip):
                ips.add(ip)
    logger.info("loaded %d IPs from guaranteed_ip_for_conn", len(ips))
    return ips


def load_ip_pool() -> set[str]:
    pool = _load_f3clogin_ips() | _load_guaranteed_ips()
    logger.info("total IP pool: %d candidates", len(pool))
    return pool


# ── Proxy Bridge ──────────────────────────────────────────


class _ProxyBridge:
    def __init__(self, config: ProxyConfig, ip_pool: set[str]) -> None:
        self.config = config
        self._stop = threading.Event()
        self._login_done = threading.Event()
        self._session: ProxySession | None = None
        self._lock = threading.Lock()
        self._routes: list[str] = []
        self._pf_anchor_active = False
        self._ip_pool = set(ip_pool)
        self._trap_ips = sorted(self._ip_pool)
        self._fallback_ip = config.forward_server or self._trap_ips[0]

    def _setup_routes(self) -> None:
        for ip in self._trap_ips:
            result = subprocess.run(
                ["route", "add", "-host", ip, "-interface", "lo0"],
                capture_output=True, text=True,
            )
            if result.returncode == 0:
                self._routes.append(ip)
            else:
                logger.warning("route add %s failed: %s", ip, result.stderr.strip())

    def _hot_add_route(self, ip: str) -> bool:
        if ip in self._ip_pool or not _is_public_ip(ip):
            return False
        result = subprocess.run(
            ["route", "add", "-host", ip, "-interface", "lo0"],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            self._ip_pool.add(ip)
            self._routes.append(ip)
            logger.info("hot-added route for ConnIpRsp IP: %s", ip)
            return True
        return False

    def _hot_add_login_redirect_ips(self, payload: bytes) -> None:
        """Parse LOGIN rejection response protobuf for redirect server IPs."""
        pos = 0
        while pos < len(payload):
            try:
                tag, pos = decode_varint(payload, pos)
            except Exception:
                break
            wire_type = tag & 7
            if wire_type == 0:
                _, pos = decode_varint(payload, pos)
            elif wire_type == 2:
                length, pos = decode_varint(payload, pos)
                if pos + length > len(payload):
                    break
                try:
                    candidate = payload[pos : pos + length].decode("ascii")
                    if _is_public_ip(candidate):
                        if self._hot_add_route(candidate):
                            logger.info("hot-added route for LOGIN redirect IP: %s", candidate)
                except (UnicodeDecodeError, ValueError):
                    pass
                pos += length
            elif wire_type == 1:
                pos += 8
            elif wire_type == 5:
                pos += 4
            else:
                break

    def _setup_pf_anchor(self) -> None:
        rule = (
            f"rdr pass on lo0 proto tcp from any to any port 443 "
            f"-> 127.0.0.1 port {self.config.proxy_port}\n"
        )
        subprocess.run(
            ["pfctl", "-a", PF_ANCHOR, "-f", "-"],
            input=rule, capture_output=True, text=True,
        )
        subprocess.run(["pfctl", "-e"], capture_output=True, text=True)
        self._pf_anchor_active = True

    def _cleanup(self) -> None:
        for ip in reversed(self._routes):
            subprocess.run(["route", "delete", "-host", ip], capture_output=True)
        self._routes.clear()
        if self._pf_anchor_active:
            subprocess.run(
                ["pfctl", "-a", PF_ANCHOR, "-F", "all"],
                capture_output=True, text=True,
            )
            self._pf_anchor_active = False

    def _resolve_original_dst(self, client_sock: socket.socket) -> str:
        try:
            peer = client_sock.getpeername()
            result = subprocess.run(
                ["pfctl", "-s", "state"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                if str(peer[1]) in line and "443" in line:
                    for m in _IP_RE.finditer(line):
                        ip = m.group(1)
                        if ip in self._ip_pool:
                            return ip
        except Exception:
            pass
        return self._fallback_ip

    def _connect_forward(self, forward_ip: str) -> socket.socket:
        """Connect upstream by temporarily lifting the lo0 route trap."""
        upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            subprocess.run(
                ["route", "delete", "-host", forward_ip],
                capture_output=True, text=True,
            )
            upstream.settimeout(10)
            upstream.connect((forward_ip, self.config.forward_port))
            subprocess.run(
                ["route", "add", "-host", forward_ip, "-interface", "lo0"],
                capture_output=True, text=True,
            )
            return upstream
        except Exception:
            subprocess.run(
                ["route", "add", "-host", forward_ip, "-interface", "lo0"],
                capture_output=True, text=True,
            )
            upstream.close()
            raise

    def _handle_connection(self, csock: socket.socket) -> None:
        forward_ip = self._resolve_original_dst(csock)
        logger.info("proxy: accepted connection, forward_ip=%s", forward_ip)
        try:
            rsock = self._connect_forward(forward_ip)
        except OSError:
            csock.close()
            return
        logger.info("proxy: upstream connected to %s:%d", forward_ip, self.config.forward_port)

        uid = None
        logged = False
        buf_c = bytearray()
        buf_r = bytearray()
        passthrough_c = False
        passthrough_r = False

        try:
            while not self._stop.is_set():
                readable, _, _ = select.select([csock, rsock], [], [], 1.0)
                for s in readable:
                    if s is csock:
                        d = csock.recv(65536)
                        if not d:
                            return
                        if not passthrough_c:
                            buf_c.extend(d)
                            while True:
                                if len(buf_c) < HEADER_LENGTH:
                                    break
                                if buf_c[:2] != b"FT":
                                    passthrough_c = True
                                    buf_c.clear()
                                    break
                                bl = struct.unpack(">I", buf_c[18:22])[0]
                                if bl > MAX_BODY_LENGTH:
                                    passthrough_c = True
                                    buf_c.clear()
                                    break
                                total = HEADER_LENGTH + bl
                                if len(buf_c) < total:
                                    break
                                cmd = struct.unpack(">H", buf_c[16:18])[0]
                                if cmd == CMD_LOGIN:
                                    uid = struct.unpack(">I", buf_c[8:12])[0] >> 8
                                    logger.debug("proxy: LOGIN detected")
                                del buf_c[:total]
                        rsock.sendall(d)
                    elif s is rsock:
                        d = rsock.recv(65536)
                        if not d:
                            return
                        if not passthrough_r:
                            buf_r.extend(d)
                            while True:
                                if len(buf_r) < HEADER_LENGTH:
                                    break
                                if buf_r[:2] != b"FT":
                                    passthrough_r = True
                                    buf_r.clear()
                                    break
                                bl = struct.unpack(">I", buf_r[18:22])[0]
                                ext = struct.unpack(">H", buf_r[30:32])[0]
                                if bl > MAX_BODY_LENGTH:
                                    passthrough_r = True
                                    buf_r.clear()
                                    break
                                total = HEADER_LENGTH + bl
                                if len(buf_r) < total:
                                    break
                                cmd = struct.unpack(">H", buf_r[16:18])[0]
                                if cmd == CMD_LOGIN and uid:
                                    payload = bytes(buf_r[HEADER_LENGTH + ext:total])
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
                                            logger.info("proxy: LOGIN rejected on %s, waiting for retry on other server", forward_ip)
                                            self._hot_add_login_redirect_ips(payload)
                                elif cmd in CMD_CONNIP:
                                    payload = bytes(buf_r[HEADER_LENGTH + ext:total])
                                    new_ips = extract_connip_ips(payload)
                                    if new_ips:
                                        logger.info(
                                            "ConnIpRsp cmd=0x%04X: %d IPs parsed: %s",
                                            cmd, len(new_ips), sorted(new_ips),
                                        )
                                    for ip in new_ips:
                                        self._hot_add_route(ip)
                                del buf_r[:total]
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

    def _lsof_monitor(self) -> None:
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["lsof", "-nP", "-iTCP:443", "-sTCP:ESTABLISHED,SYN_SENT"],
                    capture_output=True, text=True, timeout=10,
                )
                for line in result.stdout.splitlines():
                    if "FTNN" not in line and "FutuOpenD" not in line:
                        continue
                    for part in line.split():
                        if "->" in part:
                            remote = part.split("->")[-1]
                            if remote.endswith(":443"):
                                ip = remote.rsplit(":", 1)[0]
                                self._hot_add_route(ip)
            except Exception:
                pass
            self._stop.wait(3)

    def intercept_login(self) -> ProxySession | None:
        self._setup_routes()
        self._setup_pf_anchor()
        logger.info(
            "proxy: %d IPs routed, PF anchor=%s, proxy=:%d",
            len(self._routes), PF_ANCHOR, self.config.proxy_port,
        )

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
        monitor_thread = threading.Thread(target=self._lsof_monitor, daemon=True)
        monitor_thread.start()

        subprocess.run(["killall", "FTNN"], capture_output=True, text=True)
        for _ in range(20):
            r = subprocess.run(
                ["pgrep", "-x", "FTNN"], capture_output=True, text=True,
            )
            if r.returncode != 0:
                break
            time.sleep(0.5)
        else:
            subprocess.run(["killall", "-9", "FTNN"], capture_output=True, text=True)
            time.sleep(1)
        subprocess.run(["open", "-a", "/Applications/富途牛牛.app"], capture_output=True, text=True)
        logger.info("FTNN launched, waiting for auto-login...")

        self._login_done.wait(timeout=self.config.login_timeout_seconds)
        self._stop.set()
        self._cleanup()

        with self._lock:
            return self._session

    def cleanup(self) -> None:
        self._stop.set()
        self._cleanup()


def obtain_authenticated_session(config: ProxyConfig | None = None) -> ProxySession | None:
    """Single-phase: preload IP pool, trap all, launch FTNN, intercept login."""
    cfg = config or ProxyConfig()
    ip_pool = load_ip_pool()
    if not ip_pool:
        logger.error("no IPs in pool — is FTNN installed?")
        return None

    bridge = _ProxyBridge(cfg, ip_pool)
    try:
        return bridge.intercept_login()
    except Exception:
        bridge.cleanup()
        raise
