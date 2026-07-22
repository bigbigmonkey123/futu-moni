#!/usr/bin/env python3
"""Sanitized, read-only 0x1AA8 wire-shape probe for the three JP ETFs.

Uses the already verified quote request only. It never emits LOGIN bytes, user id,
or opaque response bytes and adds no trading command.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import time
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

from futu_moni.adapter import DEFAULT_SECLIST_PATHS, JP_ROUTE, resolve_jp_securities
from futu_moni.protocol import (
    CMD_QUOTE,
    NativeSessionError,
    build_extend_head,
    build_quote_request,
    inspect_quote_response,
    parse_quote_prices,
    read_frame_for_command,
)
from futu_moni.proxy import ProxyConfig, obtain_authenticated_session


def _iso_from_millis(value: int) -> str | None:
    try:
        parsed = datetime.fromtimestamp(value / 1000, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None
    if not 2020 <= parsed.year <= 2100:
        return None
    return parsed.isoformat().replace("+00:00", "Z")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--login-timeout", type=float, default=120.0)
    args = parser.parse_args()

    if os.geteuid() != 0:
        raise SystemExit("root required for the scoped PF/route interception")

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    session = obtain_authenticated_session(
        ProxyConfig(login_timeout_seconds=args.login_timeout)
    )
    if session is None:
        result = {
            "probe": "FTNN native 0x1AA8 sanitized field inventory",
            "status": "login_not_obtained",
            "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "raw_payload_emitted": False,
            "user_id_emitted": False,
            "symbols": [],
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n")
        return 2

    output: list[dict[str, object]] = []
    try:
        _, resolved = resolve_jp_securities(DEFAULT_SECLIST_PATHS)
        sequence = 9501
        for index, item in enumerate(resolved):
            if item.security_id is None:
                output.append({"symbol": item.symbol, "status": "mapping_failed"})
                continue
            if index:
                time.sleep(0.3)
            extend = build_extend_head(os.urandom(32))
            request = build_quote_request(
                security_id=item.security_id,
                route=JP_ROUTE,
                sequence=sequence,
                user_id=session.user_id,
                extend_head=extend,
            )
            session.socket.sendall(request)
            frame = read_frame_for_command(
                session.socket,
                timeout_seconds=8.0,
                command=CMD_QUOTE,
                sequence=sequence,
            )
            last, previous = parse_quote_prices(frame, security_id=item.security_id)
            inspections = inspect_quote_response(frame, security_id=item.security_id)
            output.append(
                {
                    "symbol": item.symbol,
                    "status": "success",
                    "last": str(last),
                    "prev_close": str(previous),
                    "typed_payloads": [
                        {
                            "subtype": inspection.subtype,
                            "varints": [
                                {
                                    "field": number,
                                    "value": value,
                                    "epoch_millis_candidate": _iso_from_millis(value),
                                }
                                for number, value in inspection.varints
                            ],
                            "nested_varints": [
                                {
                                    "path": list(path),
                                    "value": value,
                                    "epoch_millis_candidate": _iso_from_millis(value),
                                }
                                for path, value in inspection.nested_varints
                            ],
                            "fixed64_fields": list(inspection.fixed64_fields),
                            "length_delimited_fields": list(
                                inspection.length_delimited_fields
                            ),
                            "fixed32_fields": list(inspection.fixed32_fields),
                        }
                        for inspection in inspections
                    ],
                }
            )
            sequence += 1
    except (NativeSessionError, OSError) as exc:
        output.append(
            {
                "symbol": "probe",
                "status": exc.kind if isinstance(exc, NativeSessionError) else "network_error",
            }
        )
    finally:
        with suppress(OSError):
            session.socket.close()

    result = {
        "probe": "FTNN native 0x1AA8 sanitized field inventory",
        "status": "complete" if len(output) == 3 and all(i.get("status") == "success" for i in output) else "partial",
        "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "command": "0x1AA8",
        "request_selectors": [0, 1, 2],
        "route": 1001,
        "raw_payload_emitted": False,
        "user_id_emitted": False,
        "symbols": output,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    return 0 if result["status"] == "complete" else 3


if __name__ == "__main__":
    raise SystemExit(main())
