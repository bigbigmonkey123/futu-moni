# futu-moni

通过富途牛牛原生 FT 协议获取 JP 市场数据的独立服务。不使用 OpenD，不需要 API key。

> v0.2: 从单次命令行工具升级为**长期运行服务** + **MITM 代理自动认证**

## v0.2 升级要点

| 项目 | v0.1 (上游) | v0.2 (本版) |
|------|-------------|-------------|
| 认证方式 | tcpdump 抓包 → 手动 replay | MITM 代理自动拦截 FTNN 的 LOGIN |
| 运行模式 | 单次 CLI 查询 | 长期运行服务，可持续查询 10+次/天 |
| token 问题 | 一次性 token 消耗后需重新抓包 | 每次启动自动获取新 token |
| 架构 | 单文件脚本 | 模块化: protocol / adapter / proxy / service |
| 数据模型 | print 输出 | Pydantic 模型，JSON 输出，fail-closed |

## 原理

富途 FT 协议使用一次性登录 token，无法 replay。本项目通过 macOS PF rdr + route 规则搭建本地 MITM 代理，拦截 FTNN 桌面端的 LOGIN 认证，获取已认证的 TCP 连接，在上面注入 QUOTE 查询。

```
FTNN App  ──[LOGIN]──> lo0 ──[PF rdr]──> 本地代理 :19443 ──> 富途服务器 :443
                                              │
                                     拦截 LOGIN 成功后
                                     在远端 socket 上注入 QUOTE 查询
```

### 为什么不能用 packet replay？

v0.1 用 tcpdump 抓登录包再重放。但 FT 协议的 LOGIN token 是**服务端一次性消耗**的——FTNN 发出后服务端就标记已用，重放永远返回 rejected。MITM 代理解决了这个根本问题：让 FTNN 自己完成认证，我们只是"借用"认证后的连接。

### 为什么不用 lo0 IP alias？

最初尝试在 lo0 上添加 IP alias 拦截流量，但 macOS 内核有一个 bug：Python 的 `accept()` 在 lo0 alias IP 上永远不返回（尽管 TCP 三次握手已完成，`nc` 能正常工作）。改用 PF rdr 规则绕过了这个问题。

## 目标证券

| 代码 | 名称 | 市场 |
|------|------|------|
| 1306 | NEXT FUNDS TOPIX ETF | JP |
| 1321 | Nikkei 225 ETF | JP |
| 1489 | NF 日経高配当50 ETF | JP |

## 快速开始

需要 macOS + root 权限（pfctl/route 操作）+ 富途牛牛已安装。

```python
from futu_moni import FutuNativeService, ServiceConfig, ProxyConfig

config = ServiceConfig(
    use_proxy=True,
    proxy=ProxyConfig(forward_server="119.28.37.206"),
    poll_interval_seconds=300,  # 每 5 分钟查询一次
)

def on_report(report, health):
    for q in report.quotes:
        if q.last:
            print(f"{q.symbol}: {q.last} JPY")

service = FutuNativeService(config, on_report=on_report)
service.run()  # 阻塞运行，Ctrl+C 退出
```

服务启动后会自动：
1. 配置 PF rdr 规则 + host routes (22+ IP → lo0)
2. 启动富途牛牛
3. 拦截 FTNN 的 LOGIN 获取认证连接
4. 按间隔循环查询 1306/1321/1489 报价
5. 退出时清理 PF 规则和路由

## 项目结构

```
futu-moni/
├── src/futu_moni/          # 生产代码
│   ├── protocol.py         # FT wire protocol (32-byte header, protobuf payload)
│   ├── models.py           # Pydantic 数据模型 (fail-closed)
│   ├── adapter.py          # NativeQuoteClient + ProxyQuoteClient
│   ├── proxy.py            # PF rdr MITM 代理 (_ProxyBridge)
│   └── service.py          # 长期运行服务 (FutuNativeService)
├── tests/                  # 单元测试
├── experiments/            # 实验脚本迭代记录 (从 v0.1 到 v0.2 的探索过程)
├── upstream/               # v0.1 原始代码参考
└── docs/                   # JSON schema, 示例输出
```

## 协议细节

FT 协议运行在 TCP 443 端口（非 TLS），32 字节大端序 Header + Protobuf Body：

| 字段 | 偏移 | 说明 |
|------|------|------|
| Magic | 0-1 | `"FT"` (0x46 0x54) |
| Command | 16-17 | LOGIN=0x1771, INIT=0x1B0E, QUOTE=0x1AA8 |
| Body Length | 18-21 | 后续 body 长度 |
| Sequence | 12-15 | 请求序号，响应回传 |
| Extend Head | 30-31 | extend head 长度（body 前缀） |

价格单位：纳单位 (÷10⁹)，日股路由号 1001。

## 已知限制

- macOS only (依赖 pfctl, route, lo0)
- 需要 root 权限
- FTNN 崩溃后需手动重启服务（暂无自动重连）
- Futu 服务器池动态变化，`proxy.py` 中的已知 IP 列表可能需要更新

## License

MIT — 基于 [v0.1 原始项目](https://github.com/bigbigmonkey123/futu-moni) 的协议逆向工作。
