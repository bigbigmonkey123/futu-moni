"""One-command entry point: sudo python3 -m futu_moni [MARKET:CODE ...]

No args = default JP ETF (1306/1321/1489). With args = multi-market snapshot.
Examples:
  sudo python3 -m futu_moni
  sudo python3 -m futu_moni US:AAPL HK:9988 JP:1306
"""

from __future__ import annotations

import json
import logging
import os
import sys
from decimal import Decimal
from pathlib import Path

logger = logging.getLogger("futu_moni")

MARKET_ALIASES: dict[str, int] = {"HK": 1, "US": 11, "JP": 830}


def _preflight() -> list[str]:
    issues: list[str] = []

    if os.geteuid() != 0:
        issues.append("需要 root 权限: 请用 sudo python3 -m futu_moni 运行")

    seclist_paths = [
        Path.home() / ".com.futunn.FutuOpenD/F3CNN/SecListDB.v13.dat",
    ]
    if not any(p.exists() for p in seclist_paths):
        issues.append("SecListDB 不存在: 请确认已安装并登录过富途牛牛")

    app = Path("/Applications/富途牛牛.app")
    if not app.exists():
        issues.append("富途牛牛未安装: 请先安装 /Applications/富途牛牛.app")

    return issues


def _parse_symbols(args: list[str]) -> list[tuple[int, str]]:
    pairs: list[tuple[int, str]] = []
    for arg in args:
        if ":" not in arg:
            print(f"格式错误: {arg} (应为 MARKET:CODE, 如 US:AAPL)")
            sys.exit(1)
        market_str, code = arg.split(":", 1)
        market_str = market_str.upper()
        if market_str in MARKET_ALIASES:
            market_code = MARKET_ALIASES[market_str]
        elif market_str.isdigit():
            market_code = int(market_str)
        else:
            print(f"未知市场: {market_str} (支持: {', '.join(MARKET_ALIASES)})")
            sys.exit(1)
        pairs.append((market_code, code))
    return pairs


def _fmt_volume(v: int) -> str:
    if v >= 1_000_000_000:
        return f"{v / 1_000_000_000:.1f}B"
    if v >= 1_000_000:
        return f"{v / 1_000_000:.1f}M"
    if v >= 1_000:
        return f"{v / 1_000:.1f}K"
    return str(v)


def _fmt_price(p: Decimal) -> str:
    if p >= 10000:
        return f"{p:.0f}"
    if p >= 100:
        return f"{p:.1f}"
    return f"{p:.2f}"


def _run_default() -> None:
    from futu_moni.proxy import ProxyConfig, obtain_authenticated_session
    from futu_moni.adapter import (
        DEFAULT_SECLIST_PATHS,
        ProxyQuoteClient,
        resolve_jp_securities,
    )
    from futu_moni.protocol import NativeSessionError

    print("=" * 60)
    print("futu-moni: JP ETF 报价服务 (1306 / 1321 / 1489)")
    print("=" * 60)
    print()

    config = ProxyConfig()

    print("[启动] 预加载 IP 池, 设置路由拦截, 启动 FTNN...")
    print("  ➜ 如果弹出登录窗口, 请正常登录")
    print()

    session = obtain_authenticated_session(config)
    if session is None:
        print("\n❌ 登录超时或未发现服务器")
        sys.exit(1)

    print("[代理] 登录成功 ✓\n")

    _, resolved = resolve_jp_securities(DEFAULT_SECLIST_PATHS)
    client = ProxyQuoteClient(session.socket, session.user_id)

    print("[查询] 正在获取报价...\n")

    results = []
    for item in resolved:
        if item.security_id is None:
            print(f"  {item.symbol}: 映射失败 ({item.mapping.status.value})")
            results.append({"symbol": item.symbol, "status": "mapping_failed"})
            continue
        try:
            snap = client.query_snapshot(item.security_id)
            if snap.price:
                chg = (snap.price.last - snap.price.prev_close) / snap.price.prev_close * 100
                line = f"  {item.symbol}: last={_fmt_price(snap.price.last)} prev={_fmt_price(snap.price.prev_close)} chg={chg:+.2f}%"
                print(line)
                detail_parts = []
                if snap.ohlcv:
                    parts = []
                    if snap.ohlcv.open:
                        parts.append(f"O={_fmt_price(snap.ohlcv.open)}")
                    if snap.ohlcv.high:
                        parts.append(f"H={_fmt_price(snap.ohlcv.high)}")
                    if snap.ohlcv.low:
                        parts.append(f"L={_fmt_price(snap.ohlcv.low)}")
                    if snap.ohlcv.volume is not None:
                        parts.append(f"Vol={_fmt_volume(snap.ohlcv.volume)}")
                    if parts:
                        detail_parts.extend(parts)
                if snap.order_book and snap.order_book.bids and snap.order_book.asks:
                    b = snap.order_book.bids[0]
                    a = snap.order_book.asks[0]
                    detail_parts.append(f"Bid={_fmt_price(b.price)} Ask={_fmt_price(a.price)}")
                if detail_parts:
                    print(f"        {' '.join(detail_parts)}")
                results.append({
                    "symbol": item.symbol,
                    "last": str(snap.price.last),
                    "prev_close": str(snap.price.prev_close),
                    "status": "success",
                })
            else:
                print(f"  {item.symbol}: 无价格数据")
                results.append({"symbol": item.symbol, "status": "no_price"})
        except NativeSessionError as exc:
            print(f"  {item.symbol}: 查询失败 ({exc.kind})")
            results.append({"symbol": item.symbol, "status": exc.kind})

    client.close()

    success = [r for r in results if r["status"] == "success"]
    total = len(resolved)
    print()
    print("=" * 60)
    if len(success) == total:
        print(f"✓ 全部成功: {len(success)}/{total}")
        print("  decision = CONDITIONAL_GO")
    elif success:
        print(f"⚠ 部分成功: {len(success)}/{total}")
    else:
        print("✗ 全部失败")
    print("=" * 60)

    output_path = Path("futu_moni_result.json")
    output_path.write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n")
    print(f"\n结果已写入: {output_path.absolute()}")


def _run_multi_market(symbols: list[str]) -> None:
    from futu_moni.proxy import ProxyConfig, obtain_authenticated_session
    from futu_moni.adapter import ProxyQuoteClient, resolve_securities
    from futu_moni.protocol import NativeSessionError

    pairs = _parse_symbols(symbols)
    print(f"[解析] {len(pairs)} 个证券待查询")

    from futu_moni.adapter import DEFAULT_SECLIST_PATHS
    resolved = resolve_securities(pairs, DEFAULT_SECLIST_PATHS)
    for (mkt, code), sec in zip(pairs, resolved):
        if sec is None:
            print(f"  ✗ {code} (market={mkt}): 未找到")
        else:
            print(f"  ✓ {sec.code} → id={sec.security_id} route={sec.route} {sec.name or ''}")

    if not any(resolved):
        print("\n❌ 没有可查询的证券")
        sys.exit(1)

    config = ProxyConfig()
    print("\n[启动] 预加载 IP 池, 设置路由拦截, 启动 FTNN...")
    session = obtain_authenticated_session(config)
    if session is None:
        print("\n❌ 登录超时或未发现服务器")
        sys.exit(1)

    print("[代理] 登录成功 ✓\n")

    client = ProxyQuoteClient(
        session.socket, session.user_id,
        max_queries=len(pairs),
        total_deadline_seconds=60.0,
    )

    print("[查询] 正在获取报价...\n")

    results = []
    for (mkt, code), sec in zip(pairs, resolved):
        if sec is None:
            results.append({"code": code, "market_code": mkt, "status": "not_found"})
            continue
        try:
            snap = client.query_snapshot(sec.security_id, route=sec.route)
            entry: dict[str, object] = {
                "code": sec.code,
                "market_code": sec.market_code,
                "route": sec.route,
                "name": sec.name,
                "status": "success",
            }
            if snap.price:
                chg = (snap.price.last - snap.price.prev_close) / snap.price.prev_close * 100
                entry["last"] = str(snap.price.last)
                entry["prev_close"] = str(snap.price.prev_close)
                line = f"  {sec.code}: last={_fmt_price(snap.price.last)} prev={_fmt_price(snap.price.prev_close)} chg={chg:+.2f}%"
                print(line)
                detail_parts = []
                if snap.ohlcv:
                    parts = []
                    if snap.ohlcv.open:
                        parts.append(f"O={_fmt_price(snap.ohlcv.open)}")
                    if snap.ohlcv.high:
                        parts.append(f"H={_fmt_price(snap.ohlcv.high)}")
                    if snap.ohlcv.low:
                        parts.append(f"L={_fmt_price(snap.ohlcv.low)}")
                    if snap.ohlcv.volume is not None:
                        parts.append(f"Vol={_fmt_volume(snap.ohlcv.volume)}")
                    if parts:
                        detail_parts.extend(parts)
                if snap.order_book and snap.order_book.bids and snap.order_book.asks:
                    b = snap.order_book.bids[0]
                    a = snap.order_book.asks[0]
                    detail_parts.append(f"Bid={_fmt_price(b.price)} Ask={_fmt_price(a.price)}")
                if detail_parts:
                    print(f"        {' '.join(detail_parts)}")
            else:
                print(f"  {sec.code}: 无价格数据")
            results.append(entry)
        except NativeSessionError as exc:
            print(f"  {sec.code}: 查询失败 ({exc.kind})")
            results.append({"code": sec.code, "market_code": sec.market_code, "status": exc.kind})

    client.close()

    print()
    print(json.dumps(results, indent=2, ensure_ascii=False))


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(message)s",
        datefmt="%H:%M:%S",
    )

    print("[检查] 运行前置检查...")
    issues = _preflight()
    if issues:
        print("\n❌ 无法启动:")
        for i, issue in enumerate(issues, 1):
            print(f"   {i}. {issue}")
        sys.exit(1)
    print("[检查] 全部通过 ✓\n")

    args = sys.argv[1:]
    if args:
        _run_multi_market(args)
    else:
        _run_default()


if __name__ == "__main__":
    main()
