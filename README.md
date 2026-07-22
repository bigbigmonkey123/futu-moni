# futu-moni

通过富途牛牛桌面端原生 FT 协议获取实时股票报价。

不需要 OpenD，不需要 API key，不需要任何配置。

支持 JP / HK / US 市场查询。

## 使用

**前提**: macOS + 已安装[富途牛牛](https://www.futunn.com/download) + Python 3.11+

```bash
git clone https://github.com/bigbigmonkey123/futu-moni.git
cd futu-moni
./run.sh
```

脚本会自动：创建虚拟环境 → 安装依赖 → 申请 sudo → 发现服务器 → 拦截登录 → 查询报价

**首次使用需在弹出的富途牛牛窗口中登录**，之后自动登录无需操作。

## 原理

```
阶段 1 — 发现:
  启动 FTNN → lsof 采集所有 port 443 连接 → 记录 IP → 关闭 FTNN

阶段 2 — 拦截:
  route add IP → lo0  ─┐
  pfctl rdr :443 → :19443 ─┤
  启动代理 (:19443)        │
  重启 FTNN (自动登录)  ────┘ → FTNN ──→ lo0 ──→ PF ──→ 代理 ──→ 真实服务器
  登录成功后: 清除 route/PF, 在连接上查询报价
```

FTNN 的 FT 协议服务器 IP 是动态分配的（通过 API 获取，不走 DNS），
所以必须先让 FTNN 连一次来发现 IP，再路由拦截。

## 输出示例

```
============================================================
futu-moni: JP ETF 报价服务 (1306 / 1321 / 1489)
============================================================

[阶段1] 启动 FTNN 发现服务器 IP...
  discovered: 43.153.233.15
  discovered: 43.153.233.166
  discovered: 47.242.25.150

[阶段2] 3 IPs routed, forward=43.153.233.15, proxy=:19443
  FTNN relaunched, waiting for auto-login...
  LOGIN success ✓

[查询] 正在获取报价...

  1306: last=417.1 JPY, prev_close=415.8 JPY ✓
  1321: last=41250.0 JPY, prev_close=41100.0 JPY ✓
  1489: last=2350.5 JPY, prev_close=2340.0 JPY ✓

============================================================
✓ 全部成功: 3/3 只 ETF 获取到报价
  decision = CONDITIONAL_GO
============================================================
```

## 常见问题

**FTNN 自动登录失败**
首次使用必须手动登录。登录时勾选"自动登录"，之后的查询不需要手动操作。

**Phase 1 没发现任何 IP**
- FTNN 可能被防火墙阻止
- 检查网络连接
- 增加发现时间: `ProxyConfig(discovery_seconds=60)`

**Phase 2 超时**
- FTNN 自动登录 token 可能已过期，需要手动重新登录
- 确认没有其他 PF 规则冲突: `sudo pfctl -sr`

**异常退出后路由残留**
```bash
# 查看残留路由
netstat -rn | grep lo0 | grep "43\.\|47\.\|49\."
# 手动清除
sudo route delete -host <IP>
sudo pfctl -d
```

## 支持市场

| 市场 | market_code | route | 示例 |
|------|-------------|-------|------|
| HK | 1 | 1 | 9988 (阿里巴巴), 00700 (腾讯) |
| US Stock | 11 | 11 | AAPL, MSFT, GOOGL |
| US ETF | 12 | 12 | SPY, QQQ |
| JP | 830 | 1001 | 1306, 1321, 1489 |

默认目标证券: 1306 / 1321 / 1489 (JP ETF)

## FT 协议能力

原生 FTNN 服务器 ≠ OpenD/OpenAPI。相同帧格式，不同命令集。

**可用数据 (CMD_QUOTE 0x1AA8 selector)**:

| Selector | 数据 | 说明 |
|----------|------|------|
| 0 | 实时价格 | last, prev_close, timestamp |
| 1 | 市场状态 | 交易状态 |
| 3 | 盘口 | HK 10档, US/JP 1档 |
| 5 | OHLCV | 开高低收量+成交额 |
| 8 | 基本面 | PE, 市值 |
| 12 | 盘前盘后 | US 市场 |

**不可用**: 逐笔成交、分时、历史K线、复权、ETF iNAV (OpenAPI 命令被拒绝)

## 诊断工具

```bash
# 探测所有 selector 的响应形状 (sanitized, 不泄露原始数据)
sudo python experiments/ft_selector_probe.py --all-symbols-key

# 探测不同市场的价格
sudo python experiments/ft_market_probe.py
```

## 已知限制

- macOS only
- 需要 root 权限 (route/pfctl + lsof)
- 需要 FTNN 开启自动登录才能全自动
- FTNN 崩溃后需重新运行
- Security_id 通过本地 SecListDB 解析 (FTNN 自动维护)

## License

MIT
