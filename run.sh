#!/bin/bash
# ═══════════════════════════════════════════════════════════
#  futu-moni 一键启动
#
#  用法:
#    ./run.sh              单次查询 1306/1321/1489
#    ./run.sh serve        持续服务 (每5分钟查一次, Ctrl+C 退出)
#    ./run.sh serve 120    持续服务, 自定义间隔 (秒)
# ═══════════════════════════════════════════════════════════
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
VENV="$DIR/.venv"
PY=""

# ── 1. 找 Python 3.11+ ──────────────────────────────────
for candidate in python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
        ver=$("$candidate" -c "import sys; print(sys.version_info >= (3,11))" 2>/dev/null)
        if [ "$ver" = "True" ]; then
            PY="$candidate"
            break
        fi
    fi
done

if [ -z "$PY" ]; then
    echo "❌ 需要 Python 3.11+, 请先安装"
    echo "   brew install python@3.13"
    exit 1
fi

# ── 2. 自动创建 venv + 安装 ──────────────────────────────
if [ ! -f "$VENV/bin/python" ]; then
    echo "[setup] 首次运行, 创建虚拟环境..."
    "$PY" -m venv "$VENV"
    "$VENV/bin/pip" install --quiet --upgrade pip
    "$VENV/bin/pip" install --quiet -e "$DIR"
    echo "[setup] 安装完成 ✓"
    echo
fi

VPYTHON="$VENV/bin/python"

# ── 3. 检查是否需要 sudo ────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    echo "需要 root 权限 (修改 /etc/hosts + 绑定端口 443)"
    exec sudo "$VPYTHON" -m futu_moni "$@"
fi

# ── 4. 已是 root, 直接运行 ──────────────────────────────
if [ "$1" = "serve" ]; then
    POLL="${2:-300}"
    exec "$VPYTHON" -c "
import logging, signal
from futu_moni import FutuNativeService, ServiceConfig, ProxyConfig

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s', datefmt='%H:%M:%S')
print('持续服务模式: 每 ${POLL} 秒查询一次 (Ctrl+C 退出)')
print()

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
    exec "$VPYTHON" -m futu_moni
fi
