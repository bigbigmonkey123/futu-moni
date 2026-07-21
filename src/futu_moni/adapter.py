"""Read-only adapter and redacted report assembly for the Futu native POC."""

from __future__ import annotations

import os
import socket
import sqlite3
import stat
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Literal, Protocol, cast

from futu_moni.models import (
    TARGET_SYMBOLS,
    Decision,
    FutuNativeReport,
    LoginPacketMetadata,
    MappingStatus,
    PathPolicy,
    Quality,
    QualityStatus,
    QuoteObservation,
    QuoteStatus,
    SecListMetadata,
    SecurityMapping,
    SessionStatus,
    SizeBucket,
    TargetSymbol,
    utc_now,
)
from futu_moni.protocol import (
    CMD_QUOTE,
    HEADER_LENGTH,
    MAX_BODY_LENGTH,
    NativeSessionError,
    SocketLike,
    build_extend_head,
    build_init_request,
    build_quote_request,
    parse_login_result,
    parse_quote_prices,
    read_frame,
    read_frame_for_command,
    validate_login_packet,
)

DEFAULT_LOGIN_PACKET = Path.home() / ".futu-moni" / "login_replay.bin"
DEFAULT_SECLIST_PATHS = (
    Path.home() / ".com.futunn.FutuOpenD/F3CNN/SecListDB.v13.dat",
    Path.home() / ".com.futunn.FutuOpenD/F3CNN/SecListDB.v12.dat",
)
DEFAULT_SERVER = "49.51.78.83"
JP_MARKET_CODE = 830
JP_ROUTE = 1001


@dataclass(frozen=True)
class FutuNativeConfig:
    login_packet_path: Path = DEFAULT_LOGIN_PACKET
    login_path_policy: Literal["default", "environment", "cli"] = "default"
    seclist_paths: tuple[Path, ...] = DEFAULT_SECLIST_PATHS
    server: str = DEFAULT_SERVER
    server_allowlist: tuple[str, ...] = (DEFAULT_SERVER,)
    port: int = 443
    connect_timeout_seconds: float = 5.0
    read_timeout_seconds: float = 5.0
    total_deadline_seconds: float = 30.0
    minimum_interval_seconds: float = 0.25
    max_queries: int = 3

    def __post_init__(self) -> None:
        if not self.server or any(character.isspace() for character in self.server):
            raise ValueError("server must be a non-empty host without whitespace")
        if not self.server_allowlist or any(
            not host or any(character.isspace() for character in host)
            for host in self.server_allowlist
        ):
            raise ValueError("server allowlist must contain valid hosts")
        if not 1 <= self.port <= 65535:
            raise ValueError("port must be in 1..65535")
        if (
            min(
                self.connect_timeout_seconds,
                self.read_timeout_seconds,
                self.total_deadline_seconds,
            )
            <= 0
        ):
            raise ValueError("timeouts must be positive")
        if self.minimum_interval_seconds < 0 or not 1 <= self.max_queries <= 3:
            raise ValueError("invalid native-session rate limit")


@dataclass(frozen=True)
class _PacketInspection:
    metadata: LoginPacketMetadata
    packet: bytes | None = None
    user_id: int | None = None


@dataclass(frozen=True)
class _ResolvedSecurity:
    symbol: TargetSymbol
    security_id: int | None
    mapping: SecurityMapping


def _size_bucket(size: int) -> SizeBucket:
    if size == 0:
        return "0"
    if size <= 512:
        return "1-512"
    if size <= 2048:
        return "513-2048"
    if size <= 8192:
        return "2049-8192"
    return ">8192"


def inspect_login_packet(path: Path, *, path_policy: PathPolicy) -> _PacketInspection:
    """Inspect metadata before reading; unsafe material is never returned or logged."""
    try:
        details = path.lstat()
    except FileNotFoundError:
        return _PacketInspection(
            LoginPacketMetadata(
                exists=False,
                size_bucket="absent",
                path_policy=path_policy,
                session_status=SessionStatus.ABSENT,
            )
        )
    is_symlink = stat.S_ISLNK(details.st_mode)
    is_regular = stat.S_ISREG(details.st_mode)
    mode = stat.S_IMODE(details.st_mode)

    def metadata(status: SessionStatus, format_valid: bool | None) -> LoginPacketMetadata:
        return LoginPacketMetadata(
            exists=True,
            is_regular_file=is_regular,
            symlink=is_symlink,
            mode_octal=f"{mode:04o}",
            size_bucket=_size_bucket(details.st_size),
            path_policy=path_policy,
            format_valid=format_valid,
            session_status=status,
        )

    if is_symlink:
        return _PacketInspection(metadata(SessionStatus.SYMLINK, None))
    if not is_regular:
        return _PacketInspection(metadata(SessionStatus.NOT_REGULAR, None))
    if mode != 0o600:
        return _PacketInspection(metadata(SessionStatus.PERMISSION_INSECURE, None))
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or stat.S_IMODE(opened.st_mode) != 0o600
                or (opened.st_dev, opened.st_ino) != (details.st_dev, details.st_ino)
            ):
                return _PacketInspection(metadata(SessionStatus.READ_ERROR, None))
            packet = stream.read(HEADER_LENGTH + MAX_BODY_LENGTH + 1)
        user_id = validate_login_packet(packet)
    except OSError:
        return _PacketInspection(metadata(SessionStatus.READ_ERROR, None))
    except NativeSessionError:
        return _PacketInspection(metadata(SessionStatus.INVALID_FORMAT, False))
    return _PacketInspection(
        metadata(SessionStatus.NOT_ATTEMPTED, True),
        packet,
        user_id,
    )


def resolve_jp_securities(
    paths: tuple[Path, ...], symbols: tuple[TargetSymbol, ...] = TARGET_SYMBOLS
) -> tuple[SecListMetadata, list[_ResolvedSecurity]]:
    database = next((path for path in paths if path.is_file()), None)
    if database is None:
        mappings = [
            SecurityMapping(symbol=symbol, status=MappingStatus.DB_UNAVAILABLE)
            for symbol in symbols
        ]
        return SecListMetadata(database_status="unavailable", mappings=mappings), [
            _ResolvedSecurity(symbol, None, mapping)
            for symbol, mapping in zip(symbols, mappings, strict=True)
        ]
    try:
        connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
        try:
            placeholders = ",".join("?" for _ in symbols)
            rows = connection.execute(
                "SELECT id, code, name_en FROM security "
                f"WHERE code IN ({placeholders}) AND market_code=? "
                "AND delete_flag=0 AND delisted=0 ORDER BY code, id",
                (*symbols, JP_MARKET_CODE),
            ).fetchall()
        finally:
            connection.close()
    except sqlite3.Error:
        mappings = [
            SecurityMapping(symbol=symbol, status=MappingStatus.DB_UNAVAILABLE)
            for symbol in symbols
        ]
        return SecListMetadata(database_status="unavailable", mappings=mappings), [
            _ResolvedSecurity(symbol, None, mapping)
            for symbol, mapping in zip(symbols, mappings, strict=True)
        ]

    grouped: dict[TargetSymbol, list[tuple[int, str | None]]] = {symbol: [] for symbol in symbols}
    for security_id, symbol, name in rows:
        if symbol in TARGET_SYMBOLS:
            grouped[cast(TargetSymbol, symbol)].append((int(security_id), name))
    resolved: list[_ResolvedSecurity] = []
    for symbol in symbols:
        matches = grouped[symbol]
        if len(matches) == 1:
            security_id, name = matches[0]
            mapping = SecurityMapping(
                symbol=symbol,
                status=MappingStatus.RESOLVED,
                active=True,
                name_present=bool(name),
            )
            resolved.append(_ResolvedSecurity(symbol, security_id, mapping))
        elif matches:
            mapping = SecurityMapping(symbol=symbol, status=MappingStatus.AMBIGUOUS)
            resolved.append(_ResolvedSecurity(symbol, None, mapping))
        else:
            mapping = SecurityMapping(symbol=symbol, status=MappingStatus.MISSING)
            resolved.append(_ResolvedSecurity(symbol, None, mapping))
    return (
        SecListMetadata(
            database_status="available_readonly",
            mappings=[item.mapping for item in resolved],
        ),
        resolved,
    )


def _create_socket(address: tuple[str, int], timeout: float) -> SocketLike:
    return cast(SocketLike, socket.create_connection(address, timeout))


class NativeClient(Protocol):
    def login(self, packet: bytes, user_id: int) -> None: ...

    def query(self, security_id: int) -> tuple[Decimal, Decimal]: ...

    def reset_cycle(self) -> None: ...

    def close(self) -> None: ...


class NativeQuoteClient:
    def __init__(
        self,
        config: FutuNativeConfig,
        *,
        socket_factory: Callable[[tuple[str, int], float], SocketLike] = _create_socket,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        random_bytes: Callable[[int], bytes] = os.urandom,
    ) -> None:
        self.config = config
        self.socket_factory = socket_factory
        self.monotonic = monotonic
        self.sleep = sleep
        self.random_bytes = random_bytes
        self.socket: SocketLike | None = None
        self.user_id = 0
        self.sequence = 301
        self.started_at = 0.0
        self.last_query_at: float | None = None
        self.query_count = 0

    def _deadline(self) -> None:
        if self.monotonic() - self.started_at > self.config.total_deadline_seconds:
            raise NativeSessionError("timeout")

    def login(self, packet: bytes, user_id: int) -> None:
        if self.config.server not in self.config.server_allowlist:
            raise NativeSessionError("server_not_allowlisted")
        self.started_at = self.monotonic()
        self.user_id = user_id
        try:
            self.socket = self.socket_factory(
                (self.config.server, self.config.port), self.config.connect_timeout_seconds
            )
            self.socket.sendall(packet)
        except TimeoutError as exc:
            raise NativeSessionError("timeout") from exc
        except OSError as exc:
            raise NativeSessionError("network_error") from exc
        parse_login_result(
            read_frame(self.socket, timeout_seconds=self.config.read_timeout_seconds)
        )
        self.sequence = 302
        extend = build_extend_head(self.random_bytes(32))
        self.socket.sendall(
            build_init_request(sequence=self.sequence, user_id=self.user_id, extend_head=extend)
        )
        self.sequence += 1
        read_frame(self.socket, timeout_seconds=self.config.read_timeout_seconds)
        self._deadline()

    def query(self, security_id: int) -> tuple[Decimal, Decimal]:
        if self.socket is None:
            raise NativeSessionError("login_required")
        if self.query_count >= self.config.max_queries:
            raise NativeSessionError("rate_limited")
        if self.last_query_at is not None:
            wait = self.config.minimum_interval_seconds - (self.monotonic() - self.last_query_at)
            if wait > 0:
                self.sleep(wait)
        self._deadline()
        extend = build_extend_head(self.random_bytes(32))
        request = build_quote_request(
            security_id=security_id,
            route=JP_ROUTE,
            sequence=self.sequence,
            user_id=self.user_id,
            extend_head=extend,
        )
        try:
            self.socket.sendall(request)
        except TimeoutError as exc:
            raise NativeSessionError("timeout") from exc
        except OSError as exc:
            raise NativeSessionError("network_error") from exc
        self.sequence += 1
        self.query_count += 1
        self.last_query_at = self.monotonic()
        frame = read_frame(self.socket, timeout_seconds=self.config.read_timeout_seconds)
        self._deadline()
        return parse_quote_prices(frame, security_id=security_id)

    def reset_cycle(self) -> None:
        self.query_count = 0
        self.last_query_at = None
        self.started_at = self.monotonic()

    def close(self) -> None:
        if self.socket is not None:
            with suppress(OSError):
                self.socket.close()


class ProxyQuoteClient:
    """Client that uses a pre-authenticated socket from the MITM proxy."""

    def __init__(
        self,
        socket: SocketLike,
        user_id: int,
        *,
        read_timeout_seconds: float = 5.0,
        total_deadline_seconds: float = 30.0,
        minimum_interval_seconds: float = 0.25,
        max_queries: int = 3,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        random_bytes: Callable[[int], bytes] = os.urandom,
    ) -> None:
        self.socket: SocketLike | None = socket
        self.user_id = user_id
        self.read_timeout = read_timeout_seconds
        self.total_deadline = total_deadline_seconds
        self.minimum_interval = minimum_interval_seconds
        self.max_queries = max_queries
        self.monotonic = monotonic
        self.sleep = sleep
        self.random_bytes = random_bytes
        self.sequence = 9001
        self.started_at = monotonic()
        self.last_query_at: float | None = None
        self.query_count = 0

    def _deadline(self) -> None:
        if self.monotonic() - self.started_at > self.total_deadline:
            raise NativeSessionError("timeout")

    def login(self, packet: bytes, user_id: int) -> None:
        pass

    def query(self, security_id: int) -> tuple[Decimal, Decimal]:
        if self.socket is None:
            raise NativeSessionError("login_required")
        if self.query_count >= self.max_queries:
            raise NativeSessionError("rate_limited")
        if self.last_query_at is not None:
            wait = self.minimum_interval - (self.monotonic() - self.last_query_at)
            if wait > 0:
                self.sleep(wait)
        self._deadline()
        extend = build_extend_head(self.random_bytes(32))
        my_seq = self.sequence
        request = build_quote_request(
            security_id=security_id,
            route=JP_ROUTE,
            sequence=my_seq,
            user_id=self.user_id,
            extend_head=extend,
        )
        try:
            self.socket.sendall(request)
        except TimeoutError as exc:
            raise NativeSessionError("timeout") from exc
        except OSError as exc:
            raise NativeSessionError("network_error") from exc
        self.sequence += 1
        self.query_count += 1
        self.last_query_at = self.monotonic()
        frame = read_frame_for_command(
            self.socket,
            timeout_seconds=self.read_timeout,
            command=CMD_QUOTE,
            sequence=my_seq,
        )
        self._deadline()
        return parse_quote_prices(frame, security_id=security_id)

    def reset_cycle(self) -> None:
        self.query_count = 0
        self.last_query_at = None
        self.started_at = self.monotonic()

    def close(self) -> None:
        if self.socket is not None:
            with suppress(OSError):
                self.socket.close()


def _session_status(kind: str) -> SessionStatus:
    return {
        "server_not_allowlisted": SessionStatus.SERVER_NOT_ALLOWLISTED,
        "login_rejected": SessionStatus.LOGIN_REJECTED,
        "login_busy": SessionStatus.LOGIN_BUSY,
        "network_error": SessionStatus.NETWORK_ERROR,
        "timeout": SessionStatus.TIMEOUT,
        "framing_error": SessionStatus.FRAMING_ERROR,
        "parse_error": SessionStatus.PARSE_ERROR,
    }.get(kind, SessionStatus.PARSE_ERROR)


def _quote_status(kind: str) -> QuoteStatus:
    return {
        "server_not_allowlisted": QuoteStatus.SERVER_NOT_ALLOWLISTED,
        "login_required": QuoteStatus.LOGIN_REQUIRED,
        "login_rejected": QuoteStatus.LOGIN_REQUIRED,
        "login_busy": QuoteStatus.LOGIN_REQUIRED,
        "network_error": QuoteStatus.NETWORK_ERROR,
        "timeout": QuoteStatus.TIMEOUT,
        "framing_error": QuoteStatus.FRAMING_ERROR,
        "parse_error": QuoteStatus.PARSE_ERROR,
        "rate_limited": QuoteStatus.RATE_LIMITED,
    }.get(kind, QuoteStatus.PARSE_ERROR)


def _failed_quotes(
    resolved: list[_ResolvedSecurity], observed_at: datetime, *, default_status: QuoteStatus
) -> list[QuoteObservation]:
    output = []
    for item in resolved:
        status = default_status
        if item.mapping.status is MappingStatus.MISSING:
            status = QuoteStatus.SECLIST_MISSING
        elif item.mapping.status is MappingStatus.AMBIGUOUS:
            status = QuoteStatus.SECLIST_AMBIGUOUS
        elif item.mapping.status is MappingStatus.DB_UNAVAILABLE:
            status = QuoteStatus.SECLIST_UNAVAILABLE
        output.append(
            QuoteObservation(
                symbol=item.symbol,
                observed_at=observed_at,
                status=status,
                issues=[status.value],
            )
        )
    return output


def run_futu_native_poc(
    config: FutuNativeConfig,
    *,
    check_login_only: bool = False,
    now: Callable[[], datetime] = utc_now,
    client_factory: Callable[[FutuNativeConfig], NativeClient] = NativeQuoteClient,
) -> FutuNativeReport:
    observed_at = now()
    packet = inspect_login_packet(config.login_packet_path, path_policy=config.login_path_policy)
    seclist, resolved = resolve_jp_securities(config.seclist_paths)
    issues = [
        mapping.status.value
        for mapping in seclist.mappings
        if mapping.status is not MappingStatus.RESOLVED
    ]
    server_allowlisted = config.server in config.server_allowlist
    if not server_allowlisted:
        auth = packet.metadata.model_copy(
            update={"session_status": SessionStatus.SERVER_NOT_ALLOWLISTED}
        )
        issues.insert(0, SessionStatus.SERVER_NOT_ALLOWLISTED.value)
        quotes = _failed_quotes(
            resolved,
            observed_at,
            default_status=QuoteStatus.SERVER_NOT_ALLOWLISTED,
        )
        return _report(
            observed_at,
            auth,
            seclist,
            quotes,
            issues,
            server_allowlisted=False,
        )
    if packet.packet is None or packet.user_id is None:
        issues.insert(0, packet.metadata.session_status.value)
        quotes = _failed_quotes(resolved, observed_at, default_status=QuoteStatus.LOGIN_REQUIRED)
        return _report(
            observed_at,
            packet.metadata,
            seclist,
            quotes,
            issues,
            server_allowlisted=server_allowlisted,
        )

    client = client_factory(config)
    try:
        try:
            client.login(packet.packet, packet.user_id)
        except NativeSessionError as exc:
            auth = packet.metadata.model_copy(
                update={
                    "session_status": _session_status(exc.kind),
                    "check_login_attempted": True,
                }
            )
            issues.insert(0, exc.kind)
            quotes = _failed_quotes(resolved, observed_at, default_status=_quote_status(exc.kind))
            return _report(
                observed_at,
                auth,
                seclist,
                quotes,
                issues,
                server_allowlisted=server_allowlisted,
            )

        auth = packet.metadata.model_copy(
            update={"session_status": SessionStatus.LOGIN_OK, "check_login_attempted": True}
        )
        if check_login_only:
            quotes = _failed_quotes(resolved, observed_at, default_status=QuoteStatus.NOT_ATTEMPTED)
            return _report(
                observed_at,
                auth,
                seclist,
                quotes,
                issues + ["query_not_attempted"],
                server_allowlisted=server_allowlisted,
            )

        quotes: list[QuoteObservation] = []
        transport_failed: QuoteStatus | None = None
        for item in resolved:
            if item.security_id is None:
                status = {
                    MappingStatus.MISSING: QuoteStatus.SECLIST_MISSING,
                    MappingStatus.AMBIGUOUS: QuoteStatus.SECLIST_AMBIGUOUS,
                    MappingStatus.DB_UNAVAILABLE: QuoteStatus.SECLIST_UNAVAILABLE,
                }[item.mapping.status]
                quotes.append(
                    QuoteObservation(
                        symbol=item.symbol,
                        observed_at=observed_at,
                        status=status,
                        issues=[status.value],
                    )
                )
                continue
            if transport_failed is not None:
                quotes.append(
                    QuoteObservation(
                        symbol=item.symbol,
                        observed_at=observed_at,
                        status=transport_failed,
                        issues=[transport_failed.value],
                    )
                )
                continue
            try:
                last, previous = client.query(item.security_id)
            except NativeSessionError as exc:
                status = _quote_status(exc.kind)
                issues.append(exc.kind)
                transport_failed = status
                quotes.append(
                    QuoteObservation(
                        symbol=item.symbol,
                        observed_at=observed_at,
                        status=status,
                        issues=[exc.kind],
                    )
                )
            else:
                quotes.append(
                    QuoteObservation(
                        symbol=item.symbol,
                        last=last,
                        prev_close=previous,
                        observed_at=observed_at,
                        status=QuoteStatus.SUCCESS,
                        unit="nanounits_1e9",
                        issues=["market_as_of_unknown"],
                    )
                )
        issues.append("market_as_of_unknown")
        return _report(
            observed_at,
            auth,
            seclist,
            quotes,
            issues,
            server_allowlisted=server_allowlisted,
        )
    finally:
        client.close()


def _report(
    observed_at: datetime,
    auth: LoginPacketMetadata,
    seclist: SecListMetadata,
    quotes: list[QuoteObservation],
    issues: list[str],
    *,
    server_allowlisted: bool,
) -> FutuNativeReport:
    success_count = sum(item.status is QuoteStatus.SUCCESS for item in quotes)
    completeness = success_count / len(TARGET_SYMBOLS)
    mappings_ok = all(item.status is MappingStatus.RESOLVED for item in seclist.mappings)
    conditional = (
        auth.session_status is SessionStatus.LOGIN_OK
        and mappings_ok
        and success_count == len(TARGET_SYMBOLS)
        and len(quotes) == len(TARGET_SYMBOLS)
        and server_allowlisted
    )
    quality_status = QualityStatus.WARN if conditional else QualityStatus.FAIL
    return FutuNativeReport(
        observed_at=observed_at,
        symbols_requested=list(TARGET_SYMBOLS),
        auth=auth,
        seclist=seclist,
        quotes=quotes,
        quality=Quality(
            status=quality_status,
            completeness=completeness,
            issues=list(dict.fromkeys(issues)),
        ),
        decision=Decision.CONDITIONAL_GO if conditional else Decision.NO_GO,
        server_allowlisted=server_allowlisted,
    )
