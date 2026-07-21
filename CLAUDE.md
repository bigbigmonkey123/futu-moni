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

解决方案：**/etc/hosts 域名劫持**

```
1. DNS 解析 nnproxy.futunn.com → 获取真实 IP（如 170.106.200.199）
2. 写入 /etc/hosts: 127.0.0.1 nnproxy.futunn.com nnproxy2.futunn.com
3. 监听 127.0.0.1:443

FTNN ─[LOGIN]→ nnproxy.futunn.com(→127.0.0.1) → 本地代理:443 ─→ 真实服务器
                                                      │
                                             LOGIN 成功后：
                                             1. 断开 FTNN↔代理 的连接
                                             2. 保留 代理↔服务器 的 TCP socket
                                             3. 恢复 /etc/hosts + 刷新 DNS
                                             4. 在 socket 上注入 QUOTE 查询
```

关键细节：
- `proxy.py:FUTU_PROXY_DOMAINS` — `nnproxy.futunn.com` + `nnproxy2.futunn.com`（从 F3CNet.framework 提取）
- DNS 自动解析真实服务器 IP，不需要手动维护 IP 列表
- `/etc/hosts` 修改通过 `HOSTS_MARKER` 标记，清理时只删自己的行
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
| `proxy.py` | `_ProxyBridge`：/etc/hosts 劫持、代理监听、LOGIN 拦截 | 中 — 只改 hosts 文件 |
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
3. **有 root 权限**：/etc/hosts 修改和端口 443 绑定需要
4. **SecListDB 存在**：`ls ~/.com.futunn.FutuOpenD/F3CNN/SecListDB.v13.dat`
5. **DNS 可解析**：`dig +short nnproxy.futunn.com` — 必须返回 IP

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
2. **SIGKILL 残留 hosts 条目** — 手动清理：编辑 `/etc/hosts` 删除含 `futu-moni-proxy` 的行
3. **DNS 解析变化** — 如果 `nnproxy.futunn.com` 解析到的 IP 拒绝登录，可用 `--forward-server` 手动指定
4. **SSH tunnel 占端口** — colima SSH mux 曾经占用 `*:443`，导致代理无法绑定

## 测试

```bash
cd /Users/frank/Documents/futu-moni
pip install -e ".[test]"  # 或 pip install pydantic pytest
pytest tests/ -v
```

11 个单元测试，全部使用 mock client，不需要网络或 root。

## experiments/ 目录

5 个实验脚本记录了从 lo0 IP alias → PF rdr → /etc/hosts 的探索过程。**`ft_pf_proxy.py` 是 PF 阶段的突破**，后来进化为更简单的 /etc/hosts 域名劫持方案，已集成到 `proxy.py`。
