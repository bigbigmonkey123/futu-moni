"""Long-running polling service for continuous Futu native session JP quotes.

Supports two connection modes:
- Packet replay (legacy): reads a captured LOGIN packet file
- Proxy MITM (active): intercepts FTNN's live LOGIN via PF rdr + route rules
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Callable

from futu_moni.adapter import (
    FutuNativeConfig,
    NativeClient,
    NativeQuoteClient,
    ProxyQuoteClient,
    _ResolvedSecurity,
    _failed_quotes,
    _quote_status,
    _report,
    _session_status,
    inspect_login_packet,
    resolve_jp_securities,
)
from futu_moni.models import (
    Decision,
    FutuNativeReport,
    LoginPacketMetadata,
    MappingStatus,
    QuoteObservation,
    QuoteStatus,
    SessionStatus,
    utc_now,
)
from futu_moni.proxy import (
    ProxyConfig,
    ProxySession,
    obtain_authenticated_session,
)

logger = logging.getLogger(__name__)


class ServiceState(StrEnum):
    POLLING = "polling"
    WAITING_FOR_LOGIN = "waiting_for_login"
    BACKOFF = "backoff"
    STOPPED = "stopped"


_SESSION_TERMINAL = frozenset(
    {
        SessionStatus.LOGIN_REJECTED,
        SessionStatus.ABSENT,
        SessionStatus.INVALID_FORMAT,
        SessionStatus.PERMISSION_INSECURE,
        SessionStatus.SYMLINK,
        SessionStatus.NOT_REGULAR,
    }
)


@dataclass(frozen=True)
class ServiceConfig:
    native: FutuNativeConfig = field(default_factory=FutuNativeConfig)
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    use_proxy: bool = False
    poll_interval_seconds: float = 60.0
    packet_retry_interval_seconds: float = 30.0
    backoff_base_seconds: float = 5.0
    backoff_max_seconds: float = 300.0
    results_path: Path | None = None

    def __post_init__(self) -> None:
        if self.poll_interval_seconds <= 0:
            raise ValueError("poll_interval_seconds must be positive")
        if self.packet_retry_interval_seconds <= 0:
            raise ValueError("packet_retry_interval_seconds must be positive")
        if self.backoff_base_seconds <= 0 or self.backoff_max_seconds <= 0:
            raise ValueError("backoff seconds must be positive")


@dataclass
class ServiceHealth:
    state: ServiceState = ServiceState.POLLING
    consecutive_failures: int = 0
    total_cycles: int = 0
    total_successes: int = 0
    last_success_at: datetime | None = None
    last_failure_at: datetime | None = None
    last_failure_reason: str | None = None
    packet_file_mtime: float | None = None
    packet_reloads: int = 0


class FutuNativeService:
    """Loops quote queries with persistent connection and adaptive retry."""

    def __init__(
        self,
        config: ServiceConfig,
        *,
        on_report: Callable[[FutuNativeReport, ServiceHealth], None] | None = None,
        now: Callable[[], datetime] = utc_now,
        sleep: Callable[[float], None] = time.sleep,
        client_factory: Callable[[FutuNativeConfig], NativeClient] = NativeQuoteClient,
    ) -> None:
        self.config = config
        self.on_report = on_report
        self._now = now
        self._sleep = sleep
        self._client_factory = client_factory
        self.health = ServiceHealth()
        self._stop_requested = False
        self._client: NativeClient | None = None
        self._resolved: list[_ResolvedSecurity] | None = None

    def _packet_mtime(self) -> float | None:
        try:
            return self.config.native.login_packet_path.lstat().st_mtime
        except OSError:
            return None

    def _check_packet_change(self) -> bool:
        if self.config.use_proxy:
            return False
        mtime = self._packet_mtime()
        if mtime is None or self.health.packet_file_mtime is None:
            self.health.packet_file_mtime = mtime
            return False
        if mtime != self.health.packet_file_mtime:
            self.health.packet_file_mtime = mtime
            self.health.packet_reloads += 1
            return True
        return False

    def _backoff_interval(self) -> float:
        exponent = min(self.health.consecutive_failures, 6)
        return min(
            self.config.backoff_base_seconds * (2**exponent),
            self.config.backoff_max_seconds,
        )

    def _next_interval(self) -> float:
        if self.health.state is ServiceState.WAITING_FOR_LOGIN:
            return self.config.packet_retry_interval_seconds
        if self.health.state is ServiceState.BACKOFF:
            return self._backoff_interval()
        return self.config.poll_interval_seconds

    def _disconnect(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def _try_connect_proxy(self) -> FutuNativeReport | None:
        """Connect via MITM proxy: intercept FTNN's login, get authenticated socket."""
        observed_at = self._now()
        seclist, resolved = resolve_jp_securities(self.config.native.seclist_paths)
        issues = [
            m.status.value
            for m in seclist.mappings
            if m.status is not MappingStatus.RESOLVED
        ]

        auth_meta = LoginPacketMetadata(
            exists=True,
            size_bucket="0",
            path_policy="default",
            session_status=SessionStatus.NOT_ATTEMPTED,
        )

        logger.info("starting MITM proxy to intercept FTNN login...")
        session = obtain_authenticated_session(self.config.proxy)

        if session is None:
            auth = auth_meta.model_copy(
                update={"session_status": SessionStatus.TIMEOUT, "check_login_attempted": True}
            )
            issues.insert(0, "timeout")
            return _report(
                observed_at, auth, seclist,
                _failed_quotes(resolved, observed_at, default_status=QuoteStatus.TIMEOUT),
                issues, server_allowlisted=True,
            )

        logger.info("proxy login successful, user=***%s", str(session.user_id)[-3:])
        client = ProxyQuoteClient(
            session.socket,
            session.user_id,
            read_timeout_seconds=self.config.native.read_timeout_seconds,
            total_deadline_seconds=self.config.native.total_deadline_seconds,
            minimum_interval_seconds=self.config.native.minimum_interval_seconds,
            max_queries=self.config.native.max_queries,
        )
        self._client = client
        self._resolved = resolved
        return None

    def _try_connect_packet(self) -> FutuNativeReport | None:
        """Connect via packet replay (legacy mode)."""
        from futu_moni.protocol import (
            NativeSessionError,
        )

        observed_at = self._now()
        packet = inspect_login_packet(
            self.config.native.login_packet_path,
            path_policy=self.config.native.login_path_policy,
        )
        seclist, resolved = resolve_jp_securities(self.config.native.seclist_paths)
        issues = [
            m.status.value
            for m in seclist.mappings
            if m.status is not MappingStatus.RESOLVED
        ]
        server_allowlisted = (
            self.config.native.server in self.config.native.server_allowlist
        )

        if not server_allowlisted:
            auth = packet.metadata.model_copy(
                update={"session_status": SessionStatus.SERVER_NOT_ALLOWLISTED}
            )
            issues.insert(0, SessionStatus.SERVER_NOT_ALLOWLISTED.value)
            return _report(
                observed_at, auth, seclist,
                _failed_quotes(resolved, observed_at, default_status=QuoteStatus.SERVER_NOT_ALLOWLISTED),
                issues, server_allowlisted=False,
            )

        if packet.packet is None or packet.user_id is None:
            issues.insert(0, packet.metadata.session_status.value)
            return _report(
                observed_at, packet.metadata, seclist,
                _failed_quotes(resolved, observed_at, default_status=QuoteStatus.LOGIN_REQUIRED),
                issues, server_allowlisted=server_allowlisted,
            )

        client = self._client_factory(self.config.native)
        try:
            client.login(packet.packet, packet.user_id)
        except NativeSessionError as exc:
            client.close()
            auth = packet.metadata.model_copy(
                update={
                    "session_status": _session_status(exc.kind),
                    "check_login_attempted": True,
                }
            )
            issues.insert(0, exc.kind)
            return _report(
                observed_at, auth, seclist,
                _failed_quotes(resolved, observed_at, default_status=_quote_status(exc.kind)),
                issues, server_allowlisted=server_allowlisted,
            )

        self._client = client
        self._resolved = resolved
        return None

    def _try_connect(self) -> FutuNativeReport | None:
        if self.config.use_proxy:
            return self._try_connect_proxy()
        return self._try_connect_packet()

    def _query_cycle(self) -> FutuNativeReport:
        """Query all securities on existing connection."""
        from futu_moni.protocol import (
            NativeSessionError,
        )

        assert self._client is not None
        assert self._resolved is not None

        self._client.reset_cycle()
        observed_at = self._now()
        seclist, resolved = resolve_jp_securities(self.config.native.seclist_paths)
        self._resolved = resolved

        issues: list[str] = [
            m.status.value
            for m in seclist.mappings
            if m.status is not MappingStatus.RESOLVED
        ]
        server_allowlisted = self.config.use_proxy or (
            self.config.native.server in self.config.native.server_allowlist
        )

        packet = inspect_login_packet(
            self.config.native.login_packet_path,
            path_policy=self.config.native.login_path_policy,
        )
        auth = packet.metadata.model_copy(
            update={"session_status": SessionStatus.LOGIN_OK, "check_login_attempted": True}
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
                quotes.append(QuoteObservation(
                    symbol=item.symbol, observed_at=observed_at,
                    status=status, issues=[status.value],
                ))
                continue
            if transport_failed is not None:
                quotes.append(QuoteObservation(
                    symbol=item.symbol, observed_at=observed_at,
                    status=transport_failed, issues=[transport_failed.value],
                ))
                continue
            try:
                last, previous = self._client.query(item.security_id)
            except NativeSessionError as exc:
                self._disconnect()
                status = _quote_status(exc.kind)
                issues.append(exc.kind)
                transport_failed = status
                quotes.append(QuoteObservation(
                    symbol=item.symbol, observed_at=observed_at,
                    status=status, issues=[exc.kind],
                ))
            else:
                quotes.append(QuoteObservation(
                    symbol=item.symbol, last=last, prev_close=previous,
                    observed_at=observed_at, status=QuoteStatus.SUCCESS,
                    unit="nanounits_1e9", issues=["market_as_of_unknown"],
                ))

        issues.append("market_as_of_unknown")
        return _report(
            observed_at, auth, seclist, quotes, issues,
            server_allowlisted=server_allowlisted,
        )

    def _process(self, report: FutuNativeReport) -> None:
        self.health.total_cycles += 1

        if report.decision is Decision.CONDITIONAL_GO:
            self.health.state = ServiceState.POLLING
            self.health.consecutive_failures = 0
            self.health.total_successes += 1
            self.health.last_success_at = report.observed_at
        else:
            self.health.consecutive_failures += 1
            self.health.last_failure_at = report.observed_at
            self.health.last_failure_reason = (
                report.quality.issues[0] if report.quality.issues else "unknown"
            )
            if report.auth.session_status in _SESSION_TERMINAL:
                self.health.state = ServiceState.WAITING_FOR_LOGIN
            else:
                self.health.state = ServiceState.BACKOFF

        if self.on_report:
            self.on_report(report, self.health)

        if self.config.results_path is not None:
            self.config.results_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config.results_path, "a", encoding="utf-8") as handle:
                handle.write(report.model_dump_json() + "\n")

    def stop(self) -> None:
        self._stop_requested = True

    def run(self) -> None:
        """Block until ``stop()`` is called. Maintains a persistent connection."""
        mode = "proxy" if self.config.use_proxy else "packet"
        self.health.state = ServiceState.POLLING
        self.health.packet_file_mtime = self._packet_mtime()
        logger.info(
            "futu native service starting, mode=%s poll_interval=%.0fs",
            mode, self.config.poll_interval_seconds,
        )

        while not self._stop_requested:
            if self._check_packet_change():
                logger.info("login packet file changed, reconnecting")
                self._disconnect()
                self.health.state = ServiceState.POLLING
                self.health.consecutive_failures = 0

            if self._client is None:
                error_report = self._try_connect()
                if error_report is not None:
                    self._process(error_report)
                    interval = self._next_interval()
                    logger.debug(
                        "cycle %d: connect failed, state=%s next_in=%.0fs",
                        self.health.total_cycles, self.health.state, interval,
                    )
                    self._sleep(interval)
                    continue
                logger.info("connected and authenticated (mode=%s)", mode)

            report = self._query_cycle()
            self._process(report)

            interval = self._next_interval()
            logger.debug(
                "cycle %d: decision=%s state=%s next_in=%.0fs",
                self.health.total_cycles, report.decision.value,
                self.health.state, interval,
            )
            self._sleep(interval)

        self._disconnect()
        self.health.state = ServiceState.STOPPED
        logger.info(
            "futu native service stopped after %d cycles (%d successes)",
            self.health.total_cycles,
            self.health.total_successes,
        )
