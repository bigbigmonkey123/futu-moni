"""One-command entry point: sudo python3 -m futu_moni

Runs all pre-flight checks, sets up the MITM proxy, launches FTNN,
queries JP ETF quotes, prints results, and cleans up.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import socket
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger("futu_moni")


def _preflight() -> list[str]:
    """Return list of blocking issues; empty = ready to go."""
    issues: list[str] = []

    if os.geteuid() != 0:
        issues.append("需要 root 权限: 请用 sudo python3 -m futu_moni 运行")

    try:
        result = socket.getaddrinfo("nnproxy.futunn.com", 443, socket.AF_INET, socket.SOCK_STREAM)
        if not result:
            issues.append("DNS 解析失败: nnproxy.futunn.com 无法解析")
    except socket.gaierror:
        issues.append("DNS 解析失败: nnproxy.futunn.com 无法解析")

    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", 443))
        probe.close()
    except OSError:
        probe.close()
        issues.append("端口 443 被占用: 请先释放 (lsof -nP -iTCP:443 -sTCP:LISTEN)")

    result = subprocess.run(["pgrep", "-x", "FTNN"], capture_output=True)
    if result.returncode == 0:
        pid = result.stdout.decode().strip()
        issues.append(f"富途牛牛已在运行 (PID {pid}): 请先退出 FTNN 再启动")

    seclist_paths = [
        Path.home() / ".com.futunn.FutuOpenD/F3CNN/SecListDB.v13.dat",
    ]
    if not any(p.exists() for p in seclist_paths):
        issues.append("SecListDB 不存在: 请确认已安装并登录过富途牛牛")

    app = Path("/Applications/富途牛牛.app")
    if not app.exists():
        issues.append("富途牛牛未安装: 请先安装 /Applications/富途牛牛.app")

    return issues


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(message)s",
        datefmt="%H:%M:%S",
    )

    print("=" * 60)
    print("futu-moni: JP ETF 报价服务 (1306 / 1321 / 1489)")
    print("=" * 60)
    print()

    print("[检查] 运行前置检查...")
    issues = _preflight()
    if issues:
        print()
        print("❌ 无法启动，以下问题需要解决：")
        for i, issue in enumerate(issues, 1):
            print(f"   {i}. {issue}")
        print()
        sys.exit(1)

    print("[检查] 全部通过 ✓")
    print()

    from futu_moni.proxy import ProxyConfig, obtain_authenticated_session
    from futu_moni.adapter import (
        DEFAULT_SECLIST_PATHS,
        ProxyQuoteClient,
        resolve_jp_securities,
    )
    from futu_moni.protocol import NativeSessionError

    config = ProxyConfig()

    print(f"[代理] 解析服务器域名 nnproxy.futunn.com ...")
    print(f"[代理] 修改 /etc/hosts → 127.0.0.1")
    print(f"[代理] 启动 FTNN 并等待登录 (最多 {int(config.login_timeout_seconds)} 秒)...")
    print()
    print("  ➜ 请在弹出的富途牛牛窗口中正常登录")
    print()

    session = obtain_authenticated_session(config)

    if session is None:
        print()
        print("❌ 登录超时或失败")
        print("   可能原因: FTNN 没有成功连接到代理")
        sys.exit(1)

    print(f"[代理] 登录成功 ✓")
    print()

    _, resolved = resolve_jp_securities(DEFAULT_SECLIST_PATHS)
    client = ProxyQuoteClient(session.socket, session.user_id)

    print("[查询] 正在获取报价...")
    print()

    results = []
    for item in resolved:
        if item.security_id is None:
            print(f"  {item.symbol}: 映射失败 ({item.mapping.status.value})")
            results.append({"symbol": item.symbol, "status": "mapping_failed"})
            continue
        try:
            last, prev_close = client.query(item.security_id)
            print(f"  {item.symbol}: last={last} JPY, prev_close={prev_close} JPY ✓")
            results.append({
                "symbol": item.symbol,
                "last": str(last),
                "prev_close": str(prev_close),
                "status": "success",
            })
        except NativeSessionError as exc:
            print(f"  {item.symbol}: 查询失败 ({exc.kind})")
            results.append({"symbol": item.symbol, "status": exc.kind})

    client.close()

    success = [r for r in results if r["status"] == "success"]
    print()
    print("=" * 60)
    if len(success) == 3:
        print(f"✓ 全部成功: {len(success)}/3 只 ETF 获取到报价")
        print(f"  decision = CONDITIONAL_GO")
    elif success:
        print(f"⚠ 部分成功: {len(success)}/3 只 ETF")
    else:
        print(f"✗ 全部失败")
    print("=" * 60)

    output_path = Path("futu_moni_result.json")
    output_path.write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n")
    print(f"\n结果已写入: {output_path.absolute()}")


if __name__ == "__main__":
    main()
