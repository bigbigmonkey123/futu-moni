#!/usr/bin/env python3
"""Sanitized live inventory of statically recovered read-only 0x1AA8 selectors."""

from __future__ import annotations

import argparse
import json
import logging
import os
import time
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from futu_moni.adapter import DEFAULT_SECLIST_PATHS, JP_ROUTE, resolve_jp_securities
from futu_moni.protocol import (
    CMD_QUOTE,
    QUOTE_SELECTOR_NAMES,
    NativeSessionError,
    build_extend_head,
    build_quote_request,
    inspect_quote_response,
    read_frame_for_command,
)
from futu_moni.proxy import ProxyConfig, obtain_authenticated_session

GROUPS = (
    tuple(range(0, 9)),
    tuple(range(9, 20)),
    tuple(range(20, 33)),
    tuple(range(35, 43)),
)
KEY_GROUPS = ((0,), (3,), (4,), (5,), (6,), (7,), (8,))


def _iso_ms(value: int) -> str | None:
    try:
        parsed = datetime.fromtimestamp(value / 1000, tz=UTC)
    except (ValueError, OverflowError, OSError):
        return None
    if not 2020 <= parsed.year <= 2035:
        return None
    return parsed.isoformat().replace("+00:00", "Z")


def _inspection(item: Any) -> dict[str, object]:
    return {
        "selector": item.subtype,
        "name": QUOTE_SELECTOR_NAMES.get(item.subtype, "unknown"),
        "data_present": item.data_present,
        "shape_valid": item.shape_valid,
        "wrapper_valid": item.wrapper_valid,
        "varints": [
            {"field": number, "value": value, "epoch_millis_candidate": _iso_ms(value)}
            for number, value in item.varints
        ],
        "nested_varints": [
            {"path": list(path), "value": value, "epoch_millis_candidate": _iso_ms(value)}
            for path, value in item.nested_varints
        ],
        "fixed64_fields": list(item.fixed64_fields),
        "length_delimited_fields": list(item.length_delimited_fields),
        "group_fields": list(item.group_fields),
        "fixed32_fields": list(item.fixed32_fields),
    }


def _write_report(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--login-timeout", type=float, default=120)
    parser.add_argument("--singleton", action="store_true")
    parser.add_argument("--all-symbols-key", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("root required")

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    session = obtain_authenticated_session(
        ProxyConfig(login_timeout_seconds=args.login_timeout)
    )
    report: dict[str, object] = {
        "probe": "FTNN native 0x1AA8 selector inventory",
        "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "command": "0x1AA8",
        "route": 1001,
        "raw_payload_emitted": False,
        "user_id_emitted": False,
        "groups": [],
    }
    if session is None:
        report["status"] = "login_not_obtained"
        _write_report(args.output, report)
        return 2

    try:
        _, resolved = resolve_jp_securities(DEFAULT_SECLIST_PATHS)
        targets = [item for item in resolved if item.security_id is not None]
        if not args.all_symbols_key:
            targets = [item for item in targets if item.symbol == "1306"]
        if not targets:
            raise RuntimeError("target mapping unavailable")

        sequence = 9701
        if args.all_symbols_key:
            groups = KEY_GROUPS
        elif args.singleton:
            groups = tuple((selector,) for selector in QUOTE_SELECTOR_NAMES)
        else:
            groups = GROUPS

        results: list[dict[str, object]] = report["groups"]
        for target in targets:
            for selectors in groups:
                time.sleep(0.3)
                session.socket.sendall(
                    build_quote_request(
                        security_id=target.security_id,
                        route=JP_ROUTE,
                        sequence=sequence,
                        user_id=session.user_id,
                        extend_head=build_extend_head(os.urandom(32)),
                        selectors=selectors,
                    )
                )
                frame = read_frame_for_command(
                    session.socket,
                    timeout_seconds=10,
                    command=CMD_QUOTE,
                    sequence=sequence,
                )
                try:
                    items = inspect_quote_response(
                        frame,
                        security_id=target.security_id,
                        allow_missing_data=True,
                    )
                    result = {
                        "status": "response",
                        "returned": [_inspection(item) for item in items],
                    }
                except NativeSessionError as exc:
                    result = {"status": exc.kind, "returned": []}
                results.append(
                    {
                        "symbol": target.symbol,
                        "requested": [
                            {"selector": value, "name": QUOTE_SELECTOR_NAMES[value]}
                            for value in selectors
                        ],
                        **result,
                    }
                )
                sequence += 1
        report["status"] = "complete"
    except (NativeSessionError, OSError, RuntimeError) as exc:
        report["status"] = (
            exc.kind if isinstance(exc, NativeSessionError) else "probe_error"
        )
    finally:
        with suppress(OSError):
            session.socket.close()

    report["observed_at_end"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    _write_report(args.output, report)
    return 0 if report["status"] == "complete" else 3


if __name__ == "__main__":
    raise SystemExit(main())
