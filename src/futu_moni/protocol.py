"""Minimal FT quote protocol derived from futu-moni (MIT, pinned commit).

Only login replay, session init, and read-only quote command 0x1AA8 are implemented.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from decimal import Decimal
from typing import Protocol

PROTOCOL_VERSION = 10095
CMD_LOGIN = 0x1771
CMD_INIT = 0x1B0E
CMD_QUOTE = 0x1AA8
HEADER_LENGTH = 32
MAX_BODY_LENGTH = 1024 * 1024
QUOTE_SELECTOR_NAMES = {
    0: "price",
    1: "stock_state",
    2: "stock_type_specific",
    3: "order_book",
    4: "order_book_simple",
    5: "deal_statistics",
    6: "history_highlow_price",
    7: "history_close_price",
    8: "financial_indicator",
    9: "hk_broker_queue",
    10: "auction",
    11: "hk_vcm",
    12: "extended_trading_time",
    13: "extended_trading_time_detail",
    14: "cn_order_book_detail",
    15: "margin_info",
    16: "depository_receipt",
    17: "us_lv2_order",
    18: "static_financial_indicator",
    19: "usopt_lv2_order",
    20: "time_sharing_plans",
    21: "kline_1minute",
    22: "kline_3minute",
    23: "kline_5minute",
    24: "kline_15minute",
    25: "kline_30minute",
    26: "kline_60minute",
    27: "kline_day",
    28: "kline_week",
    29: "kline_month",
    30: "kline_quarter",
    31: "kline_year",
    32: "extended_time_sharing_plans",
    35: "tick",
    36: "kline_120minute",
    37: "kline_240minute",
    38: "bond_analysis",
    39: "merge_lv2_order",
    40: "kline_10minute",
    41: "kline_180minute",
    42: "noii",
}


class SocketLike(Protocol):
    def settimeout(self, value: float) -> None: ...

    def recv(self, size: int) -> bytes: ...

    def sendall(self, data: bytes) -> None: ...

    def close(self) -> None: ...


class NativeSessionError(Exception):
    """Typed and safe-to-report error; never contains packet or response bytes."""

    def __init__(self, kind: str):
        self.kind = kind
        super().__init__(f"futu_native_app_session {kind}; session material and payload redacted")


@dataclass(frozen=True)
class Frame:
    command: int
    body: bytes
    extend_head_length: int
    sequence: int = 0

    @property
    def payload(self) -> bytes:
        return self.body[self.extend_head_length :]


@dataclass(frozen=True)
class QuoteSubtypeInspection:
    """Sanitized wire-shape evidence for one 0x1AA8 typed payload.

    Length-delimited and fixed-width values are deliberately not retained: the
    diagnostic exposes field numbers and varints, never opaque response bytes.
    """

    subtype: int
    varints: tuple[tuple[int, int], ...]
    data_present: bool = True
    shape_valid: bool = True
    wrapper_valid: bool = True
    nested_varints: tuple[tuple[tuple[int, ...], int], ...] = ()
    fixed64_fields: tuple[int, ...] = ()
    length_delimited_fields: tuple[int, ...] = ()
    group_fields: tuple[int, ...] = ()
    fixed32_fields: tuple[int, ...] = ()


def encode_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("varint cannot encode negative values")
    output = bytearray()
    while value > 0x7F:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def decode_varint(data: bytes, position: int = 0) -> tuple[int, int]:
    value = 0
    for offset in range(10):
        index = position + offset
        if index >= len(data):
            raise NativeSessionError("parse_error")
        byte = data[index]
        if offset == 9 and byte > 1:
            raise NativeSessionError("parse_error")
        value |= (byte & 0x7F) << (offset * 7)
        if not byte & 0x80:
            return value, index + 1
    raise NativeSessionError("parse_error")


def validate_login_packet(packet: bytes) -> int:
    """Validate a captured login frame and return its internal user id for protocol use only."""
    if len(packet) < HEADER_LENGTH or packet[:2] != b"FT":
        raise NativeSessionError("packet_invalid_format")
    command = struct.unpack(">H", packet[16:18])[0]
    body_length = struct.unpack(">I", packet[18:22])[0]
    extend_length = struct.unpack(">H", packet[30:32])[0]
    if (
        command != CMD_LOGIN
        or body_length > MAX_BODY_LENGTH
        or extend_length > body_length
        or len(packet) != HEADER_LENGTH + body_length
    ):
        raise NativeSessionError("packet_invalid_format")
    return struct.unpack(">I", packet[8:12])[0] >> 8


def _read_exact(sock: SocketLike, length: int) -> bytes:
    output = bytearray()
    while len(output) < length:
        try:
            chunk = sock.recv(length - len(output))
        except TimeoutError as exc:
            raise NativeSessionError("timeout") from exc
        except OSError as exc:
            raise NativeSessionError("network_error") from exc
        if not chunk:
            raise NativeSessionError("framing_error")
        output.extend(chunk)
    return bytes(output)


def read_frame(sock: SocketLike, *, timeout_seconds: float) -> Frame:
    sock.settimeout(timeout_seconds)
    header = _read_exact(sock, HEADER_LENGTH)
    if header[:2] != b"FT":
        raise NativeSessionError("framing_error")
    body_length = struct.unpack(">I", header[18:22])[0]
    extend_length = struct.unpack(">H", header[30:32])[0]
    if body_length > MAX_BODY_LENGTH or extend_length > body_length:
        raise NativeSessionError("framing_error")
    body = _read_exact(sock, body_length)
    return Frame(
        command=struct.unpack(">H", header[16:18])[0],
        body=body,
        extend_head_length=extend_length,
        sequence=struct.unpack(">I", header[12:16])[0],
    )


def read_frame_for_command(
    sock: SocketLike,
    *,
    timeout_seconds: float,
    command: int,
    sequence: int,
    max_skip: int = 50,
) -> Frame:
    """Read frames until one matches the expected command and sequence number.

    Skips server-initiated frames (heartbeats, pushes) that arrive on a shared
    connection obtained via the MITM proxy.
    """
    for _ in range(max_skip):
        frame = read_frame(sock, timeout_seconds=timeout_seconds)
        if frame.command == command and frame.sequence == sequence:
            return frame
    raise NativeSessionError("framing_error")


def parse_login_result(frame: Frame) -> None:
    payload = frame.payload
    if frame.command != CMD_LOGIN or len(payload) < 2:
        raise NativeSessionError("framing_error")
    _, position = decode_varint(payload, 0)
    result, _ = decode_varint(payload, position)
    if result == 0:
        return
    if result == 0xFFFF_FFFF_FFFF_FFFF:
        raise NativeSessionError("login_busy")
    raise NativeSessionError("login_rejected")


def build_header(command: int, body_length: int, sequence: int, user_id: int, extend: int) -> bytes:
    if not 0 <= body_length <= MAX_BODY_LENGTH or not 0 <= extend <= body_length:
        raise ValueError("invalid FT body length")
    header = bytearray(HEADER_LENGTH)
    header[0:2] = b"FT"
    header[2] = 0x27
    header[3] = 0x6F
    struct.pack_into(">H", header, 4, 0x41A8)
    struct.pack_into(">H", header, 6, 0x0200)
    struct.pack_into(">I", header, 8, user_id << 8)
    struct.pack_into(">I", header, 12, sequence)
    struct.pack_into(">H", header, 16, command)
    struct.pack_into(">I", header, 18, body_length)
    struct.pack_into(">H", header, 30, extend)
    return bytes(header)


def build_extend_head(random_bytes: bytes) -> bytes:
    if len(random_bytes) != 32:
        raise ValueError("extend-head entropy must be exactly 32 bytes")
    trace = b"\x0a\x10" + random_bytes[:16] + b"\x12\x08" + random_bytes[16:24]
    trace += b"\x1a\x08" + random_bytes[24:]
    return b"\x0a" + encode_varint(len(trace)) + trace + b"\x22\x02\x08\x00"


def build_init_request(*, sequence: int, user_id: int, extend_head: bytes) -> bytes:
    payload = bytes.fromhex("0807101118012000281e3a020800")
    body = extend_head + payload
    return build_header(CMD_INIT, len(body), sequence, user_id, len(extend_head)) + body


def build_quote_request(
    *,
    security_id: int,
    route: int,
    sequence: int,
    user_id: int,
    extend_head: bytes,
    selectors: tuple[int, ...] = (0, 1, 2),
) -> bytes:
    if (
        not selectors
        or len(set(selectors)) != len(selectors)
        or any(selector not in QUOTE_SELECTOR_NAMES for selector in selectors)
    ):
        raise ValueError("selectors must be unique known read-only quote selectors")
    inner = b"\x08" + encode_varint(security_id)
    for selector in selectors:
        selected = b"\x08" + encode_varint(selector)
        inner += b"\x12" + encode_varint(len(selected)) + selected
    inner += b"\x18" + encode_varint(route)
    payload = b"\x0a" + encode_varint(len(inner)) + inner
    body = extend_head + payload
    return build_header(CMD_QUOTE, len(body), sequence, user_id, len(extend_head)) + body


def _protobuf_fields(data: bytes) -> list[tuple[int, int, int | bytes]]:
    fields: list[tuple[int, int, int | bytes]] = []
    position = 0
    while position < len(data):
        tag, position = decode_varint(data, position)
        field_number, wire_type = tag >> 3, tag & 7
        if field_number == 0:
            raise NativeSessionError("parse_error")
        if wire_type == 0:
            value, position = decode_varint(data, position)
        elif wire_type == 1:
            if position + 8 > len(data):
                raise NativeSessionError("parse_error")
            value, position = data[position : position + 8], position + 8
        elif wire_type == 2:
            length, position = decode_varint(data, position)
            if position + length > len(data):
                raise NativeSessionError("parse_error")
            value, position = data[position : position + length], position + length
        elif wire_type == 3:
            value, position = _read_protobuf_group(data, position, field_number)
        elif wire_type == 4:
            raise NativeSessionError("parse_error")
        elif wire_type == 5:
            if position + 4 > len(data):
                raise NativeSessionError("parse_error")
            value, position = data[position : position + 4], position + 4
        else:
            raise NativeSessionError("parse_error")
        fields.append((field_number, wire_type, value))
    return fields


def _read_protobuf_group(
    data: bytes, position: int, field_number: int
) -> tuple[bytes, int]:
    """Read a legacy protobuf group and return its inner bytes and end."""

    start = position
    while position < len(data):
        tag_start = position
        tag, position = decode_varint(data, position)
        number, wire_type = tag >> 3, tag & 7
        if number == 0:
            raise NativeSessionError("parse_error")
        if wire_type == 4:
            if number != field_number:
                raise NativeSessionError("parse_error")
            return data[start:tag_start], position
        if wire_type == 0:
            _, position = decode_varint(data, position)
        elif wire_type == 1:
            position += 8
        elif wire_type == 2:
            length, position = decode_varint(data, position)
            position += length
        elif wire_type == 3:
            _, position = _read_protobuf_group(data, position, number)
        elif wire_type == 5:
            position += 4
        else:
            raise NativeSessionError("parse_error")
        if position > len(data):
            raise NativeSessionError("parse_error")
    raise NativeSessionError("parse_error")


def _type_zero_prices(item: bytes) -> tuple[Decimal, Decimal] | None:
    for field_number, wire_type, submessage in _protobuf_fields(item):
        if field_number != 2 or wire_type != 2 or not isinstance(submessage, bytes):
            continue
        subtype: int | None = None
        data: bytes | None = None
        for sub_number, sub_wire, value in _protobuf_fields(submessage):
            if sub_number == 1 and sub_wire == 0 and isinstance(value, int):
                subtype = value
            elif sub_number == 2 and sub_wire == 2 and isinstance(value, bytes):
                data = value
        if subtype != 0 or data is None:
            continue
        values = {
            number: value
            for number, wire, value in _protobuf_fields(data)
            if wire == 0 and isinstance(value, int)
        }
        current, previous = values.get(1), values.get(2)
        if current is None or previous is None or current <= 0 or previous <= 0:
            raise NativeSessionError("parse_error")
        scale = Decimal(1_000_000_000)
        return Decimal(current) / scale, Decimal(previous) / scale
    return None


def inspect_quote_response(
    frame: Frame, *, security_id: int, allow_missing_data: bool = False
) -> tuple[QuoteSubtypeInspection, ...]:
    """Return a strict, sanitized inventory of typed 0x1AA8 response fields.

    The outer protobuf structure is parsed rather than searched bytewise.  A
    malformed item, missing subtype/data pair, or missing requested security
    fails closed.  Opaque bytes are represented only by their field numbers.
    """

    if frame.command != CMD_QUOTE:
        raise NativeSessionError("framing_error")

    matching_item: bytes | None = None
    for field_number, wire_type, value in _protobuf_fields(frame.payload):
        if field_number != 1 or wire_type != 2 or not isinstance(value, bytes):
            continue
        fields = _protobuf_fields(value)
        item_security_id = next(
            (
                item_value
                for number, item_wire, item_value in fields
                if number == 1 and item_wire == 0 and isinstance(item_value, int)
            ),
            None,
        )
        if item_security_id == security_id:
            matching_item = value
            break
    if matching_item is None:
        raise NativeSessionError("parse_error")

    output: list[QuoteSubtypeInspection] = []
    for field_number, wire_type, typed in _protobuf_fields(matching_item):
        if field_number != 2 or wire_type != 2 or not isinstance(typed, bytes):
            continue
        subtype: int | None = None
        data: bytes | None = None
        for number, sub_wire, value in _protobuf_fields(typed):
            if number == 1 and sub_wire == 0 and isinstance(value, int):
                subtype = value
            elif number == 2 and sub_wire == 2 and isinstance(value, bytes):
                data = value
        if subtype is None:
            if not allow_missing_data:
                raise NativeSessionError("parse_error")
            output.append(
                QuoteSubtypeInspection(
                    subtype=-1,
                    varints=(),
                    data_present=data is not None,
                    shape_valid=False,
                    wrapper_valid=False,
                )
            )
            continue
        if data is None:
            if not allow_missing_data:
                raise NativeSessionError("parse_error")
            output.append(
                QuoteSubtypeInspection(
                    subtype=subtype,
                    varints=(),
                    data_present=False,
                )
            )
            continue

        try:
            data_fields = _protobuf_fields(data)
        except NativeSessionError:
            if not allow_missing_data:
                raise
            output.append(
                QuoteSubtypeInspection(
                    subtype=subtype,
                    varints=(),
                    shape_valid=False,
                )
            )
            continue

        varints: list[tuple[int, int]] = []
        nested_varints: list[tuple[tuple[int, ...], int]] = []
        fixed64: list[int] = []
        length_delimited: list[int] = []
        groups: list[int] = []
        fixed32: list[int] = []
        for number, data_wire, value in data_fields:
            if data_wire == 0 and isinstance(value, int):
                varints.append((number, value))
            elif data_wire == 1:
                fixed64.append(number)
            elif data_wire == 2:
                length_delimited.append(number)
                if isinstance(value, bytes):
                    nested_varints.extend(_inspect_nested_varints(value, (number,)))
            elif data_wire == 3:
                groups.append(number)
                if isinstance(value, bytes):
                    nested_varints.extend(_inspect_nested_varints(value, (number,)))
            elif data_wire == 5:
                fixed32.append(number)
        output.append(
            QuoteSubtypeInspection(
                subtype=subtype,
                varints=tuple(varints),
                nested_varints=tuple(nested_varints),
                fixed64_fields=tuple(fixed64),
                length_delimited_fields=tuple(length_delimited),
                group_fields=tuple(groups),
                fixed32_fields=tuple(fixed32),
            )
        )
    if not output:
        raise NativeSessionError("parse_error")
    return tuple(output)


def _inspect_nested_varints(
    data: bytes, prefix: tuple[int, ...], *, depth: int = 0
) -> list[tuple[tuple[int, ...], int]]:
    """Best-effort nested protobuf shape inspection without retaining bytes."""

    if depth >= 4 or not data:
        return []
    try:
        fields = _protobuf_fields(data)
    except NativeSessionError:
        return []
    output: list[tuple[tuple[int, ...], int]] = []
    for number, wire_type, value in fields:
        path = prefix + (number,)
        if wire_type == 0 and isinstance(value, int):
            output.append((path, value))
        elif wire_type == 2 and isinstance(value, bytes):
            output.extend(_inspect_nested_varints(value, path, depth=depth + 1))
    return output


def parse_quote_prices(frame: Frame, *, security_id: int) -> tuple[Decimal, Decimal]:
    if frame.command != CMD_QUOTE:
        raise NativeSessionError("framing_error")
    payload = frame.payload
    marker = b"\x08" + encode_varint(security_id)
    search_from = 0
    while (marker_index := payload.find(marker, search_from)) >= 0:
        lower_bound = max(0, marker_index - 10)
        for start in range(marker_index, lower_bound - 1, -1):
            if payload[start] != 0x0A:
                continue
            try:
                tag, position = decode_varint(payload, start)
                length, position = decode_varint(payload, position)
            except NativeSessionError:
                continue
            end = position + length
            if tag != 0x0A or end > len(payload) or not (position <= marker_index < end):
                continue
            prices = _type_zero_prices(payload[position:end])
            if prices is not None:
                return prices
        search_from = marker_index + len(marker)
    raise NativeSessionError("parse_error")
