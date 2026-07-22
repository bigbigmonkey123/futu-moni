from __future__ import annotations

from decimal import Decimal

import pytest

from futu_moni.protocol import (
    CMD_QUOTE,
    Frame,
    NativeSessionError,
    build_quote_request,
    encode_varint,
    inspect_quote_response,
)


def _pb_varint(number: int, value: int) -> bytes:
    return encode_varint(number << 3) + encode_varint(value)


def _pb_bytes(number: int, value: bytes) -> bytes:
    return encode_varint((number << 3) | 2) + encode_varint(len(value)) + value


def _quote_frame(security_id: int, typed_items: list[tuple[int, bytes]]) -> Frame:
    item = _pb_varint(1, security_id)
    for subtype, data in typed_items:
        item += _pb_bytes(2, _pb_varint(1, subtype) + _pb_bytes(2, data))
    return Frame(CMD_QUOTE, _pb_bytes(1, item), 0, sequence=9)


def test_inspect_quote_response_reports_only_typed_varints() -> None:
    frame = _quote_frame(
        123,
        [
            (0, _pb_varint(1, 423_200_000_000) + _pb_varint(2, 418_300_000_000)
             + _pb_varint(3, 1_774_000_000_123) + _pb_varint(4, 1_774_000_000_000)),
            (4, _pb_varint(1, 100) + _pb_bytes(2, b"opaque")),
            (5, _pb_bytes(6, _pb_bytes(2, _pb_varint(9, 77)))),
        ],
    )

    result = inspect_quote_response(frame, security_id=123)

    assert [(item.subtype, item.varints) for item in result] == [
        (0, ((1, 423_200_000_000), (2, 418_300_000_000),
             (3, 1_774_000_000_123), (4, 1_774_000_000_000))),
        (4, ((1, 100),)),
        (5, ()),
    ]
    assert result[1].length_delimited_fields == (2,)
    assert result[2].nested_varints == (((6, 2, 9), 77),)
    assert "opaque" not in repr(result)


def test_inspect_quote_response_allows_uint64_boundary() -> None:
    frame = _quote_frame(123, [(7, _pb_varint(9, 0xFFFF_FFFF_FFFF_FFFF))])
    assert inspect_quote_response(frame, security_id=123)[0].varints == (
        (9, 0xFFFF_FFFF_FFFF_FFFF),
    )


def test_inspect_quote_response_missing_security_fails_closed() -> None:
    with pytest.raises(NativeSessionError, match="parse_error"):
        inspect_quote_response(_quote_frame(999, [(0, _pb_varint(1, 1))]), security_id=123)


def test_inspect_quote_response_missing_typed_data_fails_closed() -> None:
    item = _pb_varint(1, 123) + _pb_bytes(2, _pb_varint(1, 0))
    frame = Frame(CMD_QUOTE, _pb_bytes(1, item), 0)
    with pytest.raises(NativeSessionError, match="parse_error"):
        inspect_quote_response(frame, security_id=123)
    assert inspect_quote_response(
        frame, security_id=123, allow_missing_data=True
    )[0].data_present is False

    missing_subtype = Frame(CMD_QUOTE, _pb_bytes(1, _pb_varint(1, 123) + _pb_bytes(2, _pb_bytes(2, b""))), 0)
    with pytest.raises(NativeSessionError, match="parse_error"):
        inspect_quote_response(missing_subtype, security_id=123)
    assert inspect_quote_response(
        missing_subtype, security_id=123, allow_missing_data=True
    )[0].wrapper_valid is False


def test_inspect_quote_response_malformed_fails_closed() -> None:
    frame = Frame(CMD_QUOTE, b"\x0a\x05\x08", 0)
    with pytest.raises(NativeSessionError, match="parse_error"):
        inspect_quote_response(frame, security_id=123)


def test_inspect_quote_response_can_inventory_unsupported_nested_wire_shape() -> None:
    frame = _quote_frame(123, [(3, b"\x0b")])  # protobuf start-group wire type
    with pytest.raises(NativeSessionError, match="parse_error"):
        inspect_quote_response(frame, security_id=123)
    item = inspect_quote_response(
        frame, security_id=123, allow_missing_data=True
    )[0]
    assert item.data_present is True
    assert item.shape_valid is False


def test_inspect_quote_response_sanitizes_legacy_protobuf_group() -> None:
    grouped = b"\x0b" + _pb_varint(2, 77) + b"\x0c"
    item = inspect_quote_response(
        _quote_frame(123, [(3, grouped)]), security_id=123
    )[0]
    assert item.group_fields == (1,)
    assert item.nested_varints == (((1, 2), 77),)


def test_inspect_quote_response_rejects_wrong_command() -> None:
    with pytest.raises(NativeSessionError, match="framing_error"):
        inspect_quote_response(Frame(0xFFFF, b"", 0), security_id=123)


def test_build_quote_request_accepts_only_known_read_only_selectors() -> None:
    packet = build_quote_request(
        security_id=123,
        route=1001,
        sequence=7,
        user_id=9,
        extend_head=b"",
        selectors=(3, 4, 35),
    )
    # Each selector is encoded as repeated item field 2 containing field 1.
    assert b"\x12\x02\x08\x03\x12\x02\x08\x04\x12\x02\x08\x23" in packet

    for selectors in ((), (3, 3), (33,), (999,)):
        with pytest.raises(ValueError, match="selectors"):
            build_quote_request(
                security_id=123,
                route=1001,
                sequence=7,
                user_id=9,
                extend_head=b"",
                selectors=selectors,
            )
