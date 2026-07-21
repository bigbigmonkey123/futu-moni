# futu-moni — Codex 快速上手

## 这个项目是什么

通过富途牛牛（FTNN）桌面端的原生 FT 二进制协议，持续获取日本市场 ETF 报价的服务。

**核心约束：不允许使用 OpenD。** 只走 FTNN 原生 app 的网络通道。

## 运行环境

- macOS（依赖 pfctl、route 命令）
- Python 3.11+
- pydantic >= 2.0
- 已安装富途牛牛（`/Applications/富途牛牛.app`）
- **需要 root 权限**（PF 规则和路由操作）

## 目标证券

固定查询 3 只 JP ETF，硬编码在 `models.py:TARGET_SYMBOLS`：

| 代码 | security_id (SecListDB) | 路由 |
|------|-------------------------|------|
| 1306 | 82669546513451 | 1001 |
| 1321 | 82669546513459 | 1001 |
| 1489 | 82669546513559 | 1001 |

security_id 从 FTNN 本地 SQLite (`~/.com.futunn.FutuOpenD/F3CNN/SecListDB.v13.dat`) 查询。

## 认证原理（最重要的部分）

FT 协议的 LOGIN token 是**服务端一次性消耗**的——FTNN 发出后立刻失效，packet replay 永远不行。

解决方案：**PF rdr + route MITM 代理**

```
                  route add -host <22个Futu IP> -interface lo0
                  pfctl rdr on lo0 port 443 → 127.0.0.1:19443

FTNN ─[LOGIN]→ lo0 ─[PF rdr]→ 本地代理:19443 ─→ 真实 Futu 服务器:443
                                    │
                           LOGIN 成功后：
                           1. 断开 FTNN↔代理 的连接
                           2. 保留 代理↔服务器 的 TCP socket
                           3. 在这个 socket 上注入 QUOTE 查询
```

关键细节：
- `proxy.py:KNOWN_FUTU_SERVERS` — 22 个已知 Futu 服务器 IP，全部 route 到 lo0
- `proxy.py:DEFAULT_FORWARD_SERVER` — 实际转发目标 `119.28.37.206`（**不能**在 route 列表中）
- 服务器池动态变化，如果 FTNN 连接了未知 IP 则拦截失败
- heartbeat (cmd 0x1844) 会和 QUOTE 响应混在一起，用 sequence number 过滤

## 核心数据流

```
FutuNativeService.run()                     # service.py — 主循环
  ├── _try_connect_proxy()                  # 启动 MITM 代理拦截 FTNN 登录
  │     ├── obtain_authenticated_session()  # proxy.py — 配置 PF + routes, 启动 FTNN, 等待 LOGIN
  │     └── ProxyQuoteClient(socket, uid)   # adapter.py — 封装已认证 socket
  └── _query_cycle() (循环)                 # 在已认证连接上查询 1306/1321/1489
        ├── client.reset_cycle()            # 重置计数器
        ├── client.query(security_id)       # 发 QUOTE, 用 read_frame_for_command 过滤心跳
        └── _process(report)               # 输出 FutuNativeReport JSON
```

## 文件说明

| 文件 | 职责 | 改动风险 |
|------|------|----------|
| `protocol.py` | FT 二进制协议：header 解析、varint、帧读写、protobuf 价格解码 | 高 — 一个字节偏移错就全挂 |
| `models.py` | Pydantic 模型，fail-closed 验证（decision 必须匹配证据） | 中 — 模型验证很严格 |
| `adapter.py` | `NativeQuoteClient`（packet replay）+ `ProxyQuoteClient`（MITM）| 中 |
| `proxy.py` | `_ProxyBridge`：PF 规则、路由、代理监听、LOGIN 拦截 | 高 — 涉及系统级操作 |
| `service.py` | `FutuNativeService`：主循环、重连、backoff、health 追踪 | 低 |

## 使用方法

### 方式一：Python API

```python
from futu_moni import FutuNativeService, ServiceConfig, ProxyConfig

config = ServiceConfig(
    use_proxy=True,
    proxy=ProxyConfig(forward_server="119.28.37.206"),
    poll_interval_seconds=300,
)

def on_report(report, health):
    for q in report.quotes:
        if q.last:
            print(f"{q.symbol}: {q.last} JPY")

service = FutuNativeService(config, on_report=on_report)
service.run()  # 阻塞，Ctrl+C 退出
```

### 方式二：通过 stock-moni CLI（如果已集成）

```bash
sudo stock-moni poc futu-native-serve --proxy --poll-interval 300 -v
```

## 运行前检查清单

1. **端口 443 没有被占用**：`lsof -nP -iTCP:443 | grep LISTEN` — 必须为空
2. **富途牛牛没有在运行**：代理启动后会自动 `open /Applications/富途牛牛.app`
3. **有 root 权限**：pfctl 和 route 命令需要
4. **SecListDB 存在**：`ls ~/.com.futunn.FutuOpenD/F3CNN/SecListDB.v13.dat`

## 输出格式

每个查询周期输出一个 `FutuNativeReport` JSON，关键字段：

```json
{
  "decision": "CONDITIONAL_GO",      // 或 "NO_GO"
  "quotes": [
    {
      "symbol": "1306",
      "last": "417.1",               // Decimal, 单位 JPY (已从 nanounits 转换)
      "prev_close": "415.8",
      "status": "success"
    }
  ],
  "quality": {
    "completeness": 1.0,             // 3/3 = 1.0
    "status": "warn"                 // 永远不会是 "pass"（market_as_of 未知）
  }
}
```

`decision == "CONDITIONAL_GO"` 当且仅当：3 只全部查到价格 + 登录成功 + 映射正确。

## 已知坑

1. **FTNN 崩溃后服务不会自动重连** — 进入 backoff 但不会重新启动 FTNN 和代理
2. **SIGKILL 泄漏 PF 规则** — 手动清理：`sudo pfctl -d && sudo route delete -host <ip>`
3. **服务器池变化** — 如果 FTNN 连接了不在 `KNOWN_FUTU_SERVERS` 里的 IP，LOGIN 拦截不到
4. **forward server 不稳定** — `49.51.78.83` 曾经拒绝登录，`119.28.37.206` 目前可用
5. **SSH tunnel 占端口** — colima SSH mux 曾经占用 `*:443`，导致代理无法绑定

## 测试

```bash
cd /Users/frank/Documents/futu-moni
pip install -e ".[test]"  # 或 pip install pydantic pytest
pytest tests/ -v
```

11 个单元测试，全部使用 mock client，不需要网络或 root。

## experiments/ 目录

5 个实验脚本记录了从 lo0 IP alias → PF rdr 的探索过程。**`ft_pf_proxy.py` 是最终成功的方案**，其逻辑已集成到 `proxy.py`。
