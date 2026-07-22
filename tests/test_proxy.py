from __future__ import annotations

from futu_moni.protocol import encode_varint
from futu_moni.proxy import (
    CMD_CONNIP,
    ProxyConfig,
    _ProxyBridge,
    _is_public_ip,
    _parse_connip_item,
    extract_connip_ips,
)


def test_forward_connection_lifts_route_and_restores(monkeypatch) -> None:
    """Upstream connect temporarily removes route trap, then restores it."""
    commands_run: list[list[str]] = []

    def fake_run(args, **kwargs):
        commands_run.append(list(args))
        return __import__("subprocess").CompletedProcess(args, 0, "", "")

    monkeypatch.setattr("futu_moni.proxy.subprocess.run", fake_run)

    bridge = _ProxyBridge(ProxyConfig(), {"8.8.8.8"})
    bridge._routes.append("8.8.8.8")
    events: list[tuple[object, ...]] = []

    class FakeSocket:
        def settimeout(self, timeout):
            events.append(("settimeout", timeout))

        def connect(self, address):
            events.append(("connect", *address))

        def close(self):
            events.append(("close",))

    upstream = FakeSocket()
    monkeypatch.setattr("futu_moni.proxy.socket.socket", lambda *args: upstream)

    assert bridge._connect_forward("8.8.8.8") is upstream
    assert events == [("settimeout", 10), ("connect", "8.8.8.8", 443)]
    assert ["route", "delete", "-host", "8.8.8.8"] in commands_run
    assert ["route", "add", "-host", "8.8.8.8", "-interface", "lo0"] in commands_run


# ── ConnIpRsp protobuf helpers ──────────────────────────────


def _pb_varint(field_num: int, value: int) -> bytes:
    tag = encode_varint((field_num << 3) | 0)
    return tag + encode_varint(value)


def _pb_bytes(field_num: int, data: bytes) -> bytes:
    tag = encode_varint((field_num << 3) | 2)
    return tag + encode_varint(len(data)) + data


def _connip_item(ip: str, port: int = 443, conn_identity: int = 0x64) -> bytes:
    return (
        _pb_bytes(1, ip.encode("ascii"))
        + _pb_varint(2, port)
        + _pb_varint(5, conn_identity)
    )


def _connip_rsp(ips: list[str], result_code: int = 0) -> bytes:
    parts = _pb_varint(1, result_code)
    for ip in ips:
        parts += _pb_bytes(3, _connip_item(ip))
    return parts


# ── ConnIpRsp parsing tests ─────────────────────────────────


def test_extract_connip_ips_multiple() -> None:
    payload = _connip_rsp(["43.130.30.145", "119.28.37.77", "203.205.136.52"])
    assert extract_connip_ips(payload) == {"43.130.30.145", "119.28.37.77", "203.205.136.52"}


def test_extract_connip_ips_filters_private() -> None:
    payload = _connip_rsp(["43.130.30.145", "10.0.0.1", "192.168.1.1"])
    assert extract_connip_ips(payload) == {"43.130.30.145"}


def test_extract_connip_ips_empty_and_malformed() -> None:
    assert extract_connip_ips(b"") == set()
    assert extract_connip_ips(b"\xff\xff\xff") == set()


def test_parse_connip_item_extracts_ip() -> None:
    assert _parse_connip_item(_connip_item("119.28.37.77")) == {"119.28.37.77"}


def test_parse_connip_item_skips_non_ascii() -> None:
    bad = _pb_bytes(1, b"\x80\x81\x82") + _pb_varint(2, 443)
    assert _parse_connip_item(bad) == set()


def test_connip_realistic_multi_item_payload() -> None:
    real_ips = ["43.130.30.145", "119.28.37.77", "203.205.136.52",
                "150.109.74.63", "49.51.40.164"]
    payload = _pb_varint(1, 0)
    payload += _pb_bytes(2, b"extra_field")
    for ip in real_ips:
        item = (
            _pb_bytes(1, ip.encode("ascii"))
            + _pb_varint(2, 443)
            + _pb_bytes(3, b"some.domain.com")
            + _pb_varint(4, 1)
            + _pb_varint(5, 0x64)
        )
        payload += _pb_bytes(3, item)
    assert extract_connip_ips(payload) == set(real_ips)


def test_cmd_connip_contains_all_codes() -> None:
    assert CMD_CONNIP == frozenset({0xFFE1, 0x0529, 0x4EB3})
