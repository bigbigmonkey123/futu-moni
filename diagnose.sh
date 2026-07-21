#!/bin/bash
# ═══════════════════════════════════════════════════════════
#  诊断 FTNN 实际连接目标
#
#  用法: sudo ./diagnose.sh
#
#  1. 退出已运行的 FTNN
#  2. 启动 FTNN
#  3. 每秒采集 FTNN 的 TCP 连接
#  4. 监控 DNS 查询
#  5. 60秒后输出报告
# ═══════════════════════════════════════════════════════════
set -e

if [ "$(id -u)" -ne 0 ]; then
    exec sudo "$0" "$@"
fi

REPORT="/tmp/futu-moni-diagnose-$(date +%s).txt"

echo "════════════════════════════════════════"
echo "  FTNN 网络连接诊断"
echo "════════════════════════════════════════"
echo

# 1. 确保 FTNN 没在运行
if pgrep -x FTNN >/dev/null 2>&1; then
    echo "[!] FTNN 正在运行, 先退出..."
    killall FTNN 2>/dev/null || true
    sleep 3
fi

# 2. 刷新 DNS 缓存
dscacheutil -flushcache
killall -HUP mDNSResponder 2>/dev/null || true
echo "[1] DNS 缓存已刷新"

# 3. 启动 DNS 监控 (后台)
DNS_LOG="/tmp/ftnn-dns-$$.log"
log stream --predicate 'process == "mDNSResponder" && messageType == info' --style compact 2>/dev/null > "$DNS_LOG" &
DNS_PID=$!
echo "[2] DNS 监控已启动 (PID $DNS_PID)"

# 4. 启动 FTNN
echo "[3] 启动富途牛牛..."
open -a "/Applications/富途牛牛.app"
sleep 2

# 等待 FTNN 进程出现
for i in $(seq 1 10); do
    FTNN_PID=$(pgrep -x FTNN 2>/dev/null | head -1)
    if [ -n "$FTNN_PID" ]; then
        break
    fi
    sleep 1
done

if [ -z "$FTNN_PID" ]; then
    echo "❌ FTNN 进程未启动"
    kill $DNS_PID 2>/dev/null
    exit 1
fi

echo "[4] FTNN PID: $FTNN_PID"
echo
echo "正在采集连接信息 (60秒)..."
echo "如果 FTNN 弹出登录窗口, 请正常登录"
echo

# 5. 采集连接 (每秒一次, 持续60秒)
CONN_LOG="/tmp/ftnn-conn-$$.log"
> "$CONN_LOG"
for i in $(seq 1 60); do
    # 采集所有 FTNN 相关进程的连接
    for pid in $(pgrep -f "FTNN|FutuOpenD|FTGateway" 2>/dev/null); do
        lsof -nP -a -p "$pid" -iTCP 2>/dev/null | grep -E 'ESTABLISHED|SYN_SENT' >> "$CONN_LOG"
    done
    printf "\r  采集中... %d/60s" "$i"
    sleep 1
done
echo
echo

# 6. 停止 DNS 监控
kill $DNS_PID 2>/dev/null || true
sleep 1

# 7. 分析结果
echo "════════════════════════════════════════" | tee "$REPORT"
echo "  诊断报告" | tee -a "$REPORT"
echo "════════════════════════════════════════" | tee -a "$REPORT"
echo | tee -a "$REPORT"

# DNS 查询 (futu/moomoo 相关)
echo "── DNS 查询 (futu/moomoo 关键词) ──" | tee -a "$REPORT"
grep -iE 'futu|moomoo|ftnn|nnproxy' "$DNS_LOG" 2>/dev/null | head -20 | tee -a "$REPORT"
if ! grep -qiE 'futu|moomoo|ftnn|nnproxy' "$DNS_LOG" 2>/dev/null; then
    echo "  (无相关 DNS 查询)" | tee -a "$REPORT"
fi
echo | tee -a "$REPORT"

# TCP 连接 (去重, 只看远端 IP:port)
echo "── FTNN TCP 连接 (去重) ──" | tee -a "$REPORT"
awk '{print $9}' "$CONN_LOG" 2>/dev/null | grep -- '->' | sed 's/.*->//' | sort -u | tee -a "$REPORT"
if [ ! -s "$CONN_LOG" ]; then
    echo "  (无 TCP 连接)" | tee -a "$REPORT"
fi
echo | tee -a "$REPORT"

# 443 端口连接 (最重要)
echo "── 端口 443 连接 (可能是 FT 协议) ──" | tee -a "$REPORT"
awk '{print $9}' "$CONN_LOG" 2>/dev/null | grep -- '->' | sed 's/.*->//' | grep ':443$' | sort -u | tee -a "$REPORT"
if ! awk '{print $9}' "$CONN_LOG" 2>/dev/null | grep -q ':443$'; then
    echo "  (无 443 端口连接)" | tee -a "$REPORT"
fi
echo | tee -a "$REPORT"

# 反查 443 端口 IP 的域名
echo "── 443 端口 IP 反查 ──" | tee -a "$REPORT"
for ip in $(awk '{print $9}' "$CONN_LOG" 2>/dev/null | grep -- '->' | sed 's/.*->//' | grep ':443$' | sed 's/:443$//' | sort -u); do
    rev=$(host "$ip" 2>/dev/null | head -1)
    # 正向查 nnproxy
    match=""
    for domain in nnproxy.futunn.com nnproxy2.futunn.com mmproxy.moomoo.com; do
        resolved=$(dig +short "$domain" 2>/dev/null)
        if echo "$resolved" | grep -q "^${ip}$"; then
            match="$domain"
            break
        fi
    done
    echo "  $ip -> reverse: $rev" | tee -a "$REPORT"
    if [ -n "$match" ]; then
        echo "         match: $match" | tee -a "$REPORT"
    fi
done
echo | tee -a "$REPORT"

# 与已知域名对比
echo "── 域名解析对比 ──" | tee -a "$REPORT"
for domain in nnproxy.futunn.com nnproxy2.futunn.com mmproxy.moomoo.com mmproxy2.moomoo.com; do
    resolved=$(dig +short "$domain" 2>/dev/null)
    echo "  $domain -> $resolved" | tee -a "$REPORT"
done
echo | tee -a "$REPORT"

echo "报告已保存: $REPORT" | tee -a "$REPORT"
echo
echo "请将以上输出发回, 用于确定正确的拦截域名。"

# 清理
rm -f "$DNS_LOG" "$CONN_LOG"
