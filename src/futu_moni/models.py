"""Fail-closed, redacted contracts for the native app-session POC."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

SOURCE = "futu_native_app_session"
UPSTREAM_COMMIT = "f2a73dfad47cc546cf79578512b3f9408776a620"
TargetSymbol = Literal["1306", "1321", "1489"]
PathPolicy = Literal["default", "environment", "cli"]
SizeBucket = Literal["absent", "0", "1-512", "513-2048", "2049-8192", ">8192"]
TARGET_SYMBOLS: tuple[TargetSymbol, ...] = ("1306", "1321", "1489")


class SessionStatus(StrEnum):
    ABSENT = "absent"
    NOT_REGULAR = "not_regular_file"
    SYMLINK = "symlink_rejected"
    PERMISSION_INSECURE = "permission_insecure"
    READ_ERROR = "read_error"
    INVALID_FORMAT = "invalid_format"
    SERVER_NOT_ALLOWLISTED = "server_not_allowlisted"
    NOT_ATTEMPTED = "not_attempted"
    LOGIN_OK = "login_ok"
    LOGIN_REJECTED = "login_rejected"
    LOGIN_BUSY = "login_busy"
    NETWORK_ERROR = "network_error"
    TIMEOUT = "timeout"
    FRAMING_ERROR = "framing_error"
    PARSE_ERROR = "parse_error"


class MappingStatus(StrEnum):
    RESOLVED = "resolved"
    MISSING = "missing"
    AMBIGUOUS = "ambiguous"
    DB_UNAVAILABLE = "db_unavailable"


class QuoteStatus(StrEnum):
    SUCCESS = "success"
    NOT_ATTEMPTED = "not_attempted"
    LOGIN_REQUIRED = "login_required"
    SECLIST_MISSING = "seclist_missing"
    SECLIST_AMBIGUOUS = "seclist_ambiguous"
    SECLIST_UNAVAILABLE = "seclist_unavailable"
    SERVER_NOT_ALLOWLISTED = "server_not_allowlisted"
    NETWORK_ERROR = "network_error"
    TIMEOUT = "timeout"
    FRAMING_ERROR = "framing_error"
    PARSE_ERROR = "parse_error"
    RATE_LIMITED = "rate_limited"


class QualityStatus(StrEnum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


class Decision(StrEnum):
    CONDITIONAL_GO = "CONDITIONAL_GO"
    NO_GO = "NO_GO"


class LoginPacketMetadata(BaseModel):
    model_config = ConfigDict(frozen=True)

    exists: bool
    is_regular_file: bool | None = None
    symlink: bool | None = None
    mode_octal: str | None = Field(default=None, pattern=r"^[0-7]{4}$")
    size_bucket: SizeBucket
    path_policy: PathPolicy
    format_valid: bool | None = None
    session_status: SessionStatus
    check_login_attempted: bool = False


class SecurityMapping(BaseModel):
    model_config = ConfigDict(frozen=True)

    symbol: TargetSymbol
    market: Literal["JP"] = "JP"
    market_code: Literal[830] = 830
    status: MappingStatus
    active: bool = False
    name_present: bool = False


class SecListMetadata(BaseModel):
    model_config = ConfigDict(frozen=True)

    database_status: Literal["available_readonly", "unavailable"]
    mappings: list[SecurityMapping]


class QuoteObservation(BaseModel):
    model_config = ConfigDict(frozen=True)

    source: Literal["futu_native_app_session"] = SOURCE
    upstream_commit: Literal["f2a73dfad47cc546cf79578512b3f9408776a620"] = UPSTREAM_COMMIT
    symbol: TargetSymbol
    market: Literal["JP"] = "JP"
    currency: Literal["JPY"] = "JPY"
    last: Decimal | None = Field(default=None, gt=0)
    prev_close: Decimal | None = Field(default=None, gt=0)
    observed_at: AwareDatetime
    market_as_of: None = None
    market_as_of_status: Literal["unknown"] = "unknown"
    status: QuoteStatus
    unit: Literal["nanounits_1e9", "unknown"] = "unknown"
    issues: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def enforce_fail_closed_quote(self) -> QuoteObservation:
        if self.observed_at.utcoffset() != UTC.utcoffset(self.observed_at):
            raise ValueError("observed_at must be UTC")
        if self.status is QuoteStatus.SUCCESS:
            if self.last is None or self.prev_close is None or self.unit != "nanounits_1e9":
                raise ValueError("successful quote requires verified positive prices and unit")
        elif self.last is not None or self.prev_close is not None:
            raise ValueError("failed quote must not expose partial prices")
        return self


class PriceData(BaseModel):
    model_config = ConfigDict(frozen=True)

    last: Decimal = Field(gt=0)
    prev_close: Decimal = Field(gt=0)
    timestamp_ms: int | None = None


class OrderBookLevel(BaseModel):
    model_config = ConfigDict(frozen=True)

    price: Decimal = Field(gt=0)
    volume: int = Field(ge=0)


class OrderBookData(BaseModel):
    model_config = ConfigDict(frozen=True)

    bids: list[OrderBookLevel]
    asks: list[OrderBookLevel]


class OhlcvData(BaseModel):
    model_config = ConfigDict(frozen=True)

    open: Decimal | None = Field(default=None, gt=0)
    high: Decimal | None = Field(default=None, gt=0)
    low: Decimal | None = Field(default=None, gt=0)
    volume: int | None = Field(default=None, ge=0)
    turnover: Decimal | None = Field(default=None, ge=0)


class FinancialData(BaseModel):
    model_config = ConfigDict(frozen=True)

    pe_raw: int | None = None
    market_cap_raw: int | None = None


class QuoteSnapshot(BaseModel):
    model_config = ConfigDict(frozen=True)

    security_id: int
    price: PriceData | None = None
    order_book: OrderBookData | None = None
    ohlcv: OhlcvData | None = None
    financial: FinancialData | None = None


class Quality(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: QualityStatus
    completeness: float = Field(ge=0, le=1)
    issues: list[str] = Field(default_factory=list)


class RedactionState(BaseModel):
    model_config = ConfigDict(frozen=True)

    packet_bytes_emitted: Literal[False] = False
    user_id_emitted: Literal[False] = False
    full_path_emitted: Literal[False] = False
    raw_payload_emitted: Literal[False] = False


class FutuNativeReport(BaseModel):
    """One redacted report. It cannot represent a production Go decision."""

    model_config = ConfigDict(frozen=True)

    schema_version: Literal["1.0.0"] = "1.0.0"
    source: Literal["futu_native_app_session"] = SOURCE
    upstream_commit: Literal["f2a73dfad47cc546cf79578512b3f9408776a620"] = UPSTREAM_COMMIT
    observed_at: AwareDatetime
    market_as_of: None = None
    market_as_of_status: Literal["unknown"] = "unknown"
    market: Literal["JP"] = "JP"
    currency: Literal["JPY"] = "JPY"
    symbols_requested: list[TargetSymbol]
    server_allowlisted: bool
    auth: LoginPacketMetadata
    seclist: SecListMetadata
    quotes: list[QuoteObservation]
    quality: Quality
    decision: Decision
    redaction: RedactionState = Field(default_factory=RedactionState)
    automatic_trading: Literal[False] = False
    default_provider: Literal[False] = False

    @model_validator(mode="after")
    def enforce_report_invariants(self) -> FutuNativeReport:
        if self.observed_at.utcoffset() != UTC.utcoffset(self.observed_at):
            raise ValueError("observed_at must be UTC")
        successful = sum(item.status is QuoteStatus.SUCCESS for item in self.quotes)
        mappings_ok = all(item.status is MappingStatus.RESOLVED for item in self.seclist.mappings)
        conditional = (
            self.auth.session_status is SessionStatus.LOGIN_OK
            and self.server_allowlisted
            and mappings_ok
            and successful == len(TARGET_SYMBOLS)
            and len(self.quotes) == len(TARGET_SYMBOLS)
            and self.quality.status in {QualityStatus.PASS, QualityStatus.WARN}
        )
        if (self.decision is Decision.CONDITIONAL_GO) != conditional:
            raise ValueError("decision does not match fail-closed evidence")
        return self


def utc_now() -> datetime:
    return datetime.now(UTC)
