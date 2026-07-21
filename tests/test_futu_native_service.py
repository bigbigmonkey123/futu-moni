from __future__ import annotations

import json
import sqlite3
import struct
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest

from futu_moni.adapter import FutuNativeConfig
from futu_moni.models import (
    Decision,
    FutuNativeReport,
    QuoteStatus,
    SessionStatus,
)
from futu_moni.protocol import (
    CMD_INIT,
    CMD_LOGIN,
    CMD_QUOTE,
    HEADER_LENGTH,
    NativeSessionError,
    encode_varint,
)
from futu_moni.service import (
    FutuNativeService,
    ServiceConfig,
    ServiceHealth,
    ServiceState,
)

OBSERVED = datetime(2026, 7, 20, 10, 0, tzinfo=UTC)


def _frame(command: int, payload: bytes, *, extend: bytes = b"") -> bytes:
    body = extend + payload
    header = bytearray(HEADER_LENGTH)
    header[:2] = b"FT"
    struct.pack_into(">H", header, 16, command)
    struct.pack_into(">I", header, 18, len(body))
    struct.pack_into(">H", header, 30, len(extend))
    return bytes(header) + body


def _login_packet() -> bytes:
    packet = bytearray(_frame(CMD_LOGIN, b"\x08\x00"))
    struct.pack_into(">I", packet, 8, 12345 << 8)
    return bytes(packet)


def _quote_frame(security_id: int, current: int, previous: int) -> bytes:
    prices = b"\x08" + encode_varint(current) + b"\x10" + encode_varint(previous)
    typed = b"\x08\x00\x12" + encode_varint(len(prices)) + prices
    item = b"\x08" + encode_varint(security_id)
    item += b"\x12" + encode_varint(len(typed)) + typed
    payload = b"\x0a" + encode_varint(len(item)) + item
    return _frame(CMD_QUOTE, payload)


class FakeSocket:
    def __init__(self, responses: list[bytes]):
        self.buffer = bytearray().join(responses)
        self.sent: list[bytes] = []
        self.closed = False

    def settimeout(self, value: float) -> None:
        pass

    def recv(self, size: int) -> bytes:
        if not self.buffer:
            return b""
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def close(self) -> None:
        self.closed = True


def _setup_material(tmp_path: Path) -> tuple[Path, Path]:
    packet = tmp_path / "session.bin"
    packet.write_bytes(_login_packet())
    packet.chmod(0o600)
    database = tmp_path / "SecListDB.dat"
    connection = sqlite3.connect(database)
    connection.execute(
        "CREATE TABLE security (id INTEGER, code TEXT, name_en TEXT, "
        "market_code INTEGER, delete_flag INTEGER, delisted INTEGER)"
    )
    connection.executemany(
        "INSERT INTO security VALUES (?,?,?,?,?,?)",
        [
            (101, "1306", "ETF 1306", 830, 0, 0),
            (102, "1321", "ETF 1321", 830, 0, 0),
            (103, "1489", "ETF 1489", 830, 0, 0),
        ],
    )
    connection.commit()
    connection.close()
    return packet, database


class SuccessClient:
    """Client that succeeds login once, then produces repeatable query results."""

    def __init__(self, config: FutuNativeConfig):
        self._cycle = 0

    def login(self, packet: bytes, user_id: int) -> None:
        pass

    def query(self, security_id: int) -> tuple[Decimal, Decimal]:
        return (Decimal("100") + self._cycle, Decimal("99") + self._cycle)

    def reset_cycle(self) -> None:
        self._cycle += 1

    def close(self) -> None:
        pass


class RejectClient:
    def __init__(self, config: FutuNativeConfig):
        pass

    def login(self, packet: bytes, user_id: int) -> None:
        raise NativeSessionError("login_rejected")

    def query(self, security_id: int) -> tuple[Decimal, Decimal]:
        raise AssertionError("should not query after login rejection")

    def reset_cycle(self) -> None:
        pass

    def close(self) -> None:
        pass


class NetworkErrorClient:
    def __init__(self, config: FutuNativeConfig):
        pass

    def login(self, packet: bytes, user_id: int) -> None:
        raise NativeSessionError("network_error")

    def query(self, security_id: int) -> tuple[Decimal, Decimal]:
        raise AssertionError("unreachable")

    def reset_cycle(self) -> None:
        pass

    def close(self) -> None:
        pass


class QueryFailClient:
    """Login succeeds, but query fails with network_error (simulates connection drop)."""

    def __init__(self, config: FutuNativeConfig):
        pass

    def login(self, packet: bytes, user_id: int) -> None:
        pass

    def query(self, security_id: int) -> tuple[Decimal, Decimal]:
        raise NativeSessionError("network_error")

    def reset_cycle(self) -> None:
        pass

    def close(self) -> None:
        pass


def test_service_runs_three_cycles_and_stops(tmp_path: Path) -> None:
    packet, database = _setup_material(tmp_path)
    config = ServiceConfig(
        native=FutuNativeConfig(
            login_packet_path=packet,
            seclist_paths=(database,),
        ),
        poll_interval_seconds=60.0,
    )
    reports: list[FutuNativeReport] = []
    sleep_calls: list[float] = []

    def on_report(report: FutuNativeReport, health: ServiceHealth) -> None:
        reports.append(report)

    def mock_sleep(seconds: float) -> None:
        sleep_calls.append(seconds)
        if len(sleep_calls) >= 3:
            service.stop()

    service = FutuNativeService(
        config,
        on_report=on_report,
        now=lambda: OBSERVED,
        sleep=mock_sleep,
        client_factory=SuccessClient,
    )
    service.run()

    assert len(reports) == 3
    assert all(r.decision is Decision.CONDITIONAL_GO for r in reports)
    assert all(s == 60.0 for s in sleep_calls)
    assert service.health.state is ServiceState.STOPPED
    assert service.health.total_cycles == 3
    assert service.health.total_successes == 3
    assert service.health.consecutive_failures == 0


def test_service_reuses_connection(tmp_path: Path) -> None:
    """Verify that the service creates the client only once across multiple cycles."""
    packet, database = _setup_material(tmp_path)
    config = ServiceConfig(
        native=FutuNativeConfig(
            login_packet_path=packet,
            seclist_paths=(database,),
        ),
    )
    factory_calls = 0

    def counting_factory(cfg: FutuNativeConfig) -> SuccessClient:
        nonlocal factory_calls
        factory_calls += 1
        return SuccessClient(cfg)

    cycle = 0

    def mock_sleep(seconds: float) -> None:
        nonlocal cycle
        cycle += 1
        if cycle >= 3:
            service.stop()

    service = FutuNativeService(
        config, now=lambda: OBSERVED, sleep=mock_sleep, client_factory=counting_factory,
    )
    service.run()

    assert factory_calls == 1
    assert service.health.total_successes == 3


def test_service_enters_waiting_on_login_rejected(tmp_path: Path) -> None:
    packet, database = _setup_material(tmp_path)
    config = ServiceConfig(
        native=FutuNativeConfig(
            login_packet_path=packet,
            seclist_paths=(database,),
        ),
        packet_retry_interval_seconds=30.0,
    )
    reports: list[FutuNativeReport] = []
    sleep_calls: list[float] = []

    def on_report(report: FutuNativeReport, health: ServiceHealth) -> None:
        reports.append(report)

    def mock_sleep(seconds: float) -> None:
        sleep_calls.append(seconds)
        service.stop()

    service = FutuNativeService(
        config,
        on_report=on_report,
        now=lambda: OBSERVED,
        sleep=mock_sleep,
        client_factory=RejectClient,
    )
    service.run()

    assert len(reports) == 1
    assert reports[0].decision is Decision.NO_GO
    assert reports[0].auth.session_status is SessionStatus.LOGIN_REJECTED
    assert service.health.state is ServiceState.STOPPED
    assert service.health.consecutive_failures == 1
    assert service.health.last_failure_reason == "login_rejected"
    assert sleep_calls == [30.0]


def test_service_uses_backoff_on_network_error(tmp_path: Path) -> None:
    packet, database = _setup_material(tmp_path)
    config = ServiceConfig(
        native=FutuNativeConfig(
            login_packet_path=packet,
            seclist_paths=(database,),
        ),
        backoff_base_seconds=5.0,
        backoff_max_seconds=300.0,
    )
    sleep_calls: list[float] = []
    cycle_count = 0

    def mock_sleep(seconds: float) -> None:
        nonlocal cycle_count
        sleep_calls.append(seconds)
        cycle_count += 1
        if cycle_count >= 3:
            service.stop()

    service = FutuNativeService(
        config,
        now=lambda: OBSERVED,
        sleep=mock_sleep,
        client_factory=NetworkErrorClient,
    )
    service.run()

    assert service.health.consecutive_failures == 3
    assert service.health.state is ServiceState.STOPPED
    assert sleep_calls[0] == 10.0  # 5 * 2^1
    assert sleep_calls[1] == 20.0  # 5 * 2^2
    assert sleep_calls[2] == 40.0  # 5 * 2^3


def test_service_recovers_on_packet_change(tmp_path: Path) -> None:
    packet, database = _setup_material(tmp_path)
    config = ServiceConfig(
        native=FutuNativeConfig(
            login_packet_path=packet,
            seclist_paths=(database,),
        ),
    )
    cycle_count = 0
    client_class_sequence = [RejectClient, SuccessClient]

    def rotating_factory(cfg: FutuNativeConfig):
        idx = min(cycle_count, len(client_class_sequence) - 1)
        return client_class_sequence[idx](cfg)

    def mock_sleep(seconds: float) -> None:
        nonlocal cycle_count
        cycle_count += 1
        if cycle_count == 1:
            packet.write_bytes(_login_packet())
            packet.chmod(0o600)
        elif cycle_count >= 2:
            service.stop()

    reports: list[FutuNativeReport] = []

    service = FutuNativeService(
        config,
        on_report=lambda r, h: reports.append(r),
        now=lambda: OBSERVED,
        sleep=mock_sleep,
        client_factory=rotating_factory,
    )
    service.run()

    assert reports[0].decision is Decision.NO_GO
    assert reports[1].decision is Decision.CONDITIONAL_GO
    assert service.health.packet_reloads >= 1
    assert service.health.consecutive_failures == 0
    assert service.health.total_successes == 1


def test_service_writes_results_file(tmp_path: Path) -> None:
    packet, database = _setup_material(tmp_path)
    results = tmp_path / "results" / "quotes.jsonl"
    config = ServiceConfig(
        native=FutuNativeConfig(
            login_packet_path=packet,
            seclist_paths=(database,),
        ),
        results_path=results,
    )

    def mock_sleep(seconds: float) -> None:
        service.stop()

    service = FutuNativeService(
        config,
        now=lambda: OBSERVED,
        sleep=mock_sleep,
        client_factory=SuccessClient,
    )
    service.run()

    assert results.exists()
    lines = results.read_text().strip().split("\n")
    assert len(lines) == 1
    report = json.loads(lines[0])
    assert report["decision"] == "CONDITIONAL_GO"
    assert report["source"] == "futu_native_app_session"


def test_service_absent_packet_enters_waiting(tmp_path: Path) -> None:
    missing_packet = tmp_path / "nonexistent" / "session.bin"
    config = ServiceConfig(
        native=FutuNativeConfig(
            login_packet_path=missing_packet,
            seclist_paths=(),
        ),
        packet_retry_interval_seconds=15.0,
    )
    sleep_calls: list[float] = []

    def mock_sleep(seconds: float) -> None:
        sleep_calls.append(seconds)
        service.stop()

    service = FutuNativeService(
        config,
        now=lambda: OBSERVED,
        sleep=mock_sleep,
    )
    service.run()

    assert service.health.state is ServiceState.STOPPED
    assert service.health.consecutive_failures == 1
    assert sleep_calls == [15.0]


def test_service_config_rejects_invalid_intervals() -> None:
    with pytest.raises(ValueError, match="poll_interval_seconds"):
        ServiceConfig(poll_interval_seconds=0)
    with pytest.raises(ValueError, match="packet_retry_interval_seconds"):
        ServiceConfig(packet_retry_interval_seconds=-1)
    with pytest.raises(ValueError, match="backoff"):
        ServiceConfig(backoff_base_seconds=0)


def test_service_backoff_caps_at_max(tmp_path: Path) -> None:
    packet, database = _setup_material(tmp_path)
    config = ServiceConfig(
        native=FutuNativeConfig(
            login_packet_path=packet,
            seclist_paths=(database,),
        ),
        backoff_base_seconds=100.0,
        backoff_max_seconds=200.0,
    )
    sleep_calls: list[float] = []

    def mock_sleep(seconds: float) -> None:
        sleep_calls.append(seconds)
        if len(sleep_calls) >= 4:
            service.stop()

    service = FutuNativeService(
        config,
        now=lambda: OBSERVED,
        sleep=mock_sleep,
        client_factory=NetworkErrorClient,
    )
    service.run()

    assert all(s <= 200.0 for s in sleep_calls)


def test_service_health_tracks_last_success(tmp_path: Path) -> None:
    packet, database = _setup_material(tmp_path)
    config = ServiceConfig(
        native=FutuNativeConfig(
            login_packet_path=packet,
            seclist_paths=(database,),
        ),
    )
    cycle_count = 0

    def mock_sleep(seconds: float) -> None:
        nonlocal cycle_count
        cycle_count += 1
        if cycle_count >= 2:
            service.stop()

    service = FutuNativeService(
        config,
        now=lambda: OBSERVED,
        sleep=mock_sleep,
        client_factory=SuccessClient,
    )
    service.run()

    assert service.health.last_success_at == OBSERVED
    assert service.health.last_failure_at is None
    assert service.health.total_successes == 2


def test_service_reconnects_after_query_failure(tmp_path: Path) -> None:
    """When a query fails mid-session, the service disconnects and reconnects."""
    packet, database = _setup_material(tmp_path)
    config = ServiceConfig(
        native=FutuNativeConfig(
            login_packet_path=packet,
            seclist_paths=(database,),
        ),
    )
    cycle_count = 0

    def rotating_factory(cfg: FutuNativeConfig):
        if cycle_count == 0:
            return QueryFailClient(cfg)
        return SuccessClient(cfg)

    def mock_sleep(seconds: float) -> None:
        nonlocal cycle_count
        cycle_count += 1
        if cycle_count >= 2:
            service.stop()

    reports: list[FutuNativeReport] = []

    service = FutuNativeService(
        config,
        on_report=lambda r, h: reports.append(r),
        now=lambda: OBSERVED,
        sleep=mock_sleep,
        client_factory=rotating_factory,
    )
    service.run()

    assert reports[0].decision is Decision.NO_GO
    assert reports[1].decision is Decision.CONDITIONAL_GO
    assert service.health.total_successes == 1
