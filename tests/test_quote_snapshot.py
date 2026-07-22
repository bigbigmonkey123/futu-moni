from __future__ import annotations

from decimal import Decimal

import pytest

from futu_moni.models import (
    FinancialData,
    OhlcvData,
    OrderBookData,
    OrderBookLevel,
    PriceData,
    QuoteSnapshot,
)
from futu_moni.protocol import (
    CMD_QUOTE,
    Frame,
    NativeSessionError,
    encode_varint,
    parse_quote_snapshot,
)


def _pb_varint(number: int, value: int) -> bytes:
    return encode_varint(number << 3) + encode_varint(value)


def _pb_bytes(number: int, value: bytes) -> bytes:
    return encode_varint((number << 3) | 2) + encode_varint(len(value)) + value


def _typed_payload(subtype: int, data: bytes) -> bytes:
    return _pb_bytes(2, _pb_varint(1, subtype) + _pb_bytes(2, data))


def _snapshot_frame(security_id: int, typed_items: list[tuple[int, bytes]]) -> Frame:
    item = _pb_varint(1, security_id)
    for subtype, data in typed_items:
        item += _typed_payload(subtype, data)
    return Frame(CMD_QUOTE, _pb_bytes(1, item), 0, sequence=9)


def test_parse_price_data() -> None:
    data = (
        _pb_varint(1, 421_600_000_000)
        + _pb_varint(2, 418_300_000_000)
        + _pb_varint(3, 1_721_000_000_000)
    )
    frame = _snapshot_frame(100, [(0, data)])
    snap = parse_quote_snapshot(frame, security_id=100)

    assert isinstance(snap, QuoteSnapshot)
    assert snap.price is not None
    assert snap.price.last == Decimal("421.6")
    assert snap.price.prev_close == Decimal("418.3")
    assert snap.price.timestamp_ms == 1_721_000_000_000


def test_parse_order_book_single_level() -> None:
    bid = _pb_varint(1, 421_500_000_000) + _pb_varint(2, 213_000)
    ask = _pb_varint(1, 421_600_000_000) + _pb_varint(2, 25_000)
    data = _pb_bytes(1, bid) + _pb_bytes(2, ask)
    frame = _snapshot_frame(100, [(3, data)])
    snap = parse_quote_snapshot(frame, security_id=100)

    assert snap.order_book is not None
    assert len(snap.order_book.bids) == 1
    assert len(snap.order_book.asks) == 1
    assert snap.order_book.bids[0].price == Decimal("421.5")
    assert snap.order_book.bids[0].volume == 213_000
    assert snap.order_book.asks[0].price == Decimal("421.6")
    assert snap.order_book.asks[0].volume == 25_000


def test_parse_order_book_multi_level() -> None:
    bids = b""
    for i in range(10):
        price = 114_000_000_000 - i * 100_000_000
        bids += _pb_bytes(1, _pb_varint(1, price) + _pb_varint(2, 1000 * (i + 1)))
    asks = b""
    for i in range(10):
        price = 114_100_000_000 + i * 100_000_000
        asks += _pb_bytes(2, _pb_varint(1, price) + _pb_varint(2, 2000 * (i + 1)))
    frame = _snapshot_frame(200, [(3, bids + asks)])
    snap = parse_quote_snapshot(frame, security_id=200)

    assert snap.order_book is not None
    assert len(snap.order_book.bids) == 10
    assert len(snap.order_book.asks) == 10
    assert snap.order_book.bids[0].price == Decimal("114")
    assert snap.order_book.bids[9].price == Decimal("113.1")
    assert snap.order_book.asks[0].price == Decimal("114.1")


def test_parse_ohlcv_data() -> None:
    data = (
        _pb_varint(1, 421_600_000_000)
        + _pb_varint(2, 424_100_000_000)
        + _pb_varint(3, 420_500_000_000)
        + _pb_varint(4, 24_200_000)
        + _pb_varint(7, 10_200_000_000)
    )
    frame = _snapshot_frame(100, [(5, data)])
    snap = parse_quote_snapshot(frame, security_id=100)

    assert snap.ohlcv is not None
    assert snap.ohlcv.open == Decimal("421.6")
    assert snap.ohlcv.high == Decimal("424.1")
    assert snap.ohlcv.low == Decimal("420.5")
    assert snap.ohlcv.volume == 24_200_000
    assert snap.ohlcv.turnover == Decimal("10200000")


def test_parse_financial_data() -> None:
    data = _pb_varint(1, 25_400) + _pb_varint(2, 3_500_000_000_000)
    frame = _snapshot_frame(100, [(8, data)])
    snap = parse_quote_snapshot(frame, security_id=100)

    assert snap.financial is not None
    assert snap.financial.pe_raw == 25_400
    assert snap.financial.market_cap_raw == 3_500_000_000_000


def test_parse_multi_selector_snapshot() -> None:
    price_data = _pb_varint(1, 421_600_000_000) + _pb_varint(2, 418_300_000_000)
    bid = _pb_varint(1, 421_500_000_000) + _pb_varint(2, 100)
    ask = _pb_varint(1, 421_600_000_000) + _pb_varint(2, 200)
    ob_data = _pb_bytes(1, bid) + _pb_bytes(2, ask)
    ohlcv_data = (
        _pb_varint(1, 420_000_000_000)
        + _pb_varint(2, 425_000_000_000)
        + _pb_varint(3, 419_000_000_000)
        + _pb_varint(4, 5_000_000)
    )
    frame = _snapshot_frame(300, [
        (0, price_data),
        (3, ob_data),
        (5, ohlcv_data),
    ])
    snap = parse_quote_snapshot(frame, security_id=300)

    assert snap.security_id == 300
    assert snap.price is not None
    assert snap.order_book is not None
    assert snap.ohlcv is not None
    assert snap.financial is None


def test_snapshot_missing_security_fails_closed() -> None:
    frame = _snapshot_frame(100, [(0, _pb_varint(1, 1) + _pb_varint(2, 1))])
    with pytest.raises(NativeSessionError, match="parse_error"):
        parse_quote_snapshot(frame, security_id=999)


def test_snapshot_wrong_command_fails() -> None:
    with pytest.raises(NativeSessionError, match="framing_error"):
        parse_quote_snapshot(Frame(0xFFFF, b"", 0), security_id=100)


def test_snapshot_missing_selectors_returns_none_fields() -> None:
    frame = _snapshot_frame(100, [(1, _pb_varint(1, 5))])
    snap = parse_quote_snapshot(frame, security_id=100)

    assert snap.price is None
    assert snap.order_book is None
    assert snap.ohlcv is None
    assert snap.financial is None


def test_snapshot_price_with_zero_value_returns_none() -> None:
    data = _pb_varint(1, 0) + _pb_varint(2, 418_300_000_000)
    frame = _snapshot_frame(100, [(0, data)])
    snap = parse_quote_snapshot(frame, security_id=100)
    assert snap.price is None


def test_snapshot_empty_order_book_returns_none() -> None:
    frame = _snapshot_frame(100, [(3, _pb_varint(5, 0))])
    snap = parse_quote_snapshot(frame, security_id=100)
    assert snap.order_book is None
