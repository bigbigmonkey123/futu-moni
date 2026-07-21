#!/bin/bash
# futu-moni 一键启动脚本
# 用法: ./run.sh         (单次查询)
#       ./run.sh serve    (持续服务模式，每5分钟查一次)
set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "需要 root 权限，正在请求 sudo..."
    exec sudo "$0" "$@"
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_PYTHON=""

# 查找可用的 Python (优先 venv)
if [ -f "$SCRIPT_DIR/.venv/bin/python" ]; then
    VENV_PYTHON="$SCRIPT_DIR/.venv/bin/python"
elif [ -f "$SCRIPT_DIR/../stock-moni/.venv/bin/python" ]; then
    VENV_PYTHON="$SCRIPT_DIR/../stock-moni/.venv/bin/python"
else
    for py in python3.11 python3.12 python3.13 python3; do
        if command -v "$py" >/dev/null 2>&1; then
            if "$py" -c "import pydantic" 2>/dev/null; then
                VENV_PYTHON="$py"
                break
            fi
        fi
    done
fi

if [ -z "$VENV_PYTHON" ]; then
    echo "❌ 找不到安装了 pydantic 的 Python"
    echo "   请运行: pip install pydantic"
    exit 1
fi

cd "$SCRIPT_DIR"

if [ "$1" = "serve" ]; then
    POLL="${2:-300}"
    echo "持续服务模式: 每 ${POLL} 秒查询一次 (Ctrl+C 退出)"
    exec "$VENV_PYTHON" -c "
from futu_moni import FutuNativeService, ServiceConfig, ProxyConfig
import logging, signal, sys, json

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s', datefmt='%H:%M:%S')

config = ServiceConfig(
    use_proxy=True,
    proxy=ProxyConfig(),
    poll_interval_seconds=${POLL},
)

def on_report(report, health):
    success = [q for q in report.quotes if q.status.value == 'success']
    for q in success:
        print(f'  {q.symbol}: last={q.last} prev_close={q.prev_close}')
    print(f'  decision={report.decision.value} ({len(success)}/3)')
    print()

service = FutuNativeService(config, on_report=on_report)
signal.signal(signal.SIGINT, lambda *_: service.stop())
signal.signal(signal.SIGTERM, lambda *_: service.stop())
service.run()
"
else
    exec "$VENV_PYTHON" -m futu_moni
fi
