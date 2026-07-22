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
1. 预加载 IP 池 (~159 IPs): F3CLogin.framework + CommonConfig.db
2. route add IP → lo0  ─┐
   pfctl rdr :443 → :19443 ─┤
   启动代理 (:19443)        │
   启动 FTNN (自动登录)  ───┘ → FTNN ──→ lo0 ──→ PF ──→ 代理 ──→ 真实服务器
3. 代理在线解析 ConnIpRsp，热添加新 IP 路由
4. LOGIN 成功后: 清除 route/PF, 在保留连接上查询报价
```

FTNN 的 FT 协议服务器 IP 是动态分配的（通过 API 获取，不走 DNS），
通过预加载 + 在线解析双重覆盖。

## 输出示例

**默认 JP 模式** (`sudo python3 -m futu_moni`):

```
[检查] 全部通过 ✓
[启动] 预加载 IP 池, 设置路由拦截, 启动 FTNN...
[代理] 登录成功 ✓
[查询] 正在获取报价...

  1306: last=420.3 prev=418.3 chg=+0.48%
        O=421.6 H=424.1 L=419.5 Vol=33.9M Bid=420.1 Ask=420.3
  1321: last=68310 prev=68450 chg=-0.20%
        O=69650 H=69920 L=68210 Vol=331.2K Bid=68310 Ask=68320
```

**多市场模式** (`sudo python3 -m futu_moni US:AAPL HK:9988 JP:1306`):

```
[解析] 3 个证券待查询
  ✓ AAPL → id=205189 route=11 Apple
  ✓ 9988 → id=78224239372036 route=1 BABA-W
  ✓ 1306 → id=82669546513451 route=1001 NEXT FUNDS TOPIX ETF

[代理] 登录成功 ✓
[查询] 正在获取报价...

  AAPL: last=327.7 prev=326.6 chg=+0.35%
        O=323.1 H=329.6 L=322.2 Vol=41.3M Bid=327.4 Ask=327.8
  9988: last=113.6 prev=117.0 chg=-2.91%
  1306: last=420.3 prev=418.3 chg=+0.48%
        O=421.6 H=424.1 L=419.5 Vol=33.9M Bid=420.1 Ask=420.3
```

HK 仅显示价格（OHLCV/盘口因协议前缀截断暂不可用）。

## 常见问题

**FTNN 自动登录失败**
首次使用必须手动登录。登录时勾选"自动登录"，之后的查询不需要手动操作。

**登录超时**
- FTNN 自动登录 token 可能已过期，需要手动重新登录
- 确认没有其他 PF 规则冲突: `sudo pfctl -sr`
- 调整超时: `ProxyConfig(login_timeout_seconds=90)`

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
| US OTC | 13 | 13 | (via US: alias 自动搜索 11/12/13) |
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
