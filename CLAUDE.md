# futu-moni — Codex 快速上手

## 这个项目是什么

通过富途牛牛（FTNN）桌面端的原生 FT 二进制协议，持续获取日本市场 ETF 报价的服务。

**核心约束：不允许使用 OpenD。** 只走 FTNN 原生 app 的网络通道。

## 运行环境

- macOS（依赖 pfctl、route、lsof 命令）
- Python 3.11+
- pydantic >= 2.0
- 已安装富途牛牛（`/Applications/富途牛牛.app`）
- **需要 root 权限**（route/PF/lsof）

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

FTNN 的 FT 协议服务器 IP 是**硬编码+API 动态分配**的（不走 DNS），域名劫持、/etc/hosts、SQLite 修改均无效。

### IP 解析链路（优先级从高到低）

1. **F3CLogin.framework 硬编码**: 155 个公网 IP，编译在二进制里
2. **ConnIpRsp**: FT 协议在线 IP 分配（protobuf）
3. **云配置 confnn.futuhn.com**: 覆盖 SQLite 中的 guaranteed_ip
4. **guaranteed_ip_for_conn**: SQLite 回退池（被云配置覆盖）
5. **forced_ip_for_conn**: 功能未启用

### 解决方案：单阶段预加载 IP 池 + route/PF anchor MITM (v0.5)

```
1. 预加载 IP 池:
   strings F3CLogin → 155 个公网 IP
   sqlite3 CommonConfig.db → guaranteed_ip_for_conn → 54 个 IP
   合并去重 → ~200 个候选 IP

2. 全 IP trap:
   route add -host <每个IP> -interface lo0
   pfctl -a stock-moni -f - <<< "rdr pass on lo0 proto tcp ... port 443 -> 127.0.0.1 port 19443"
   pfctl -e

3. 启动 FTNN (一次, 无需 kill/restart):
   FTNN → 某个 IP:443 → lo0 → PF anchor → 127.0.0.1:19443 (代理) → 原始IP:443

4. lsof 热补充:
   后台线程每 3 秒 lsof, 发现 ConnIpRsp 新 IP 立刻 hot-add route

5. LOGIN 成功后:
   保留 代理↔服务器 socket, 清除 route + PF anchor, 在 socket 上注入 QUOTE 查询
```

关键细节：
- PF **anchor** `stock-moni`（不污染全局 PF），清理用 `pfctl -a stock-moni -F all`
- 代理通过 `pfctl -s state` 恢复 original destination IP（fallback 到池中第一个 IP）
- heartbeat (cmd 0x1844) 和 QUOTE 响应混在一起，用 sequence number 过滤
- STATE_VERSION = 4，state file 记录 routes 列表 + pf_anchor 标志

## FT 二进制协议

### 传输层

- **TCP 端口 443**，但**不是 TLS**——裸 TCP 上跑自定义二进制帧
- 每个连接是全双工的，服务端会主动推 heartbeat / ConnIpPush

### 帧格式（32 字节 header + variable body）

```
偏移  大小  字段             说明
──────────────────────────────────────────
 0    2B   magic            固定 "FT" (0x46 0x54)
 2    1B   proto_version    固定 0x27
 3    1B   flags            固定 0x6F
 4    2B   reserved_1       0x41A8
 6    2B   reserved_2       0x0200
 8    4B   user_id_shifted  user_id << 8（高 24 位是 user_id）
12    4B   sequence         请求/响应配对用的序列号（big-endian）
16    2B   command          命令码（见下表）
18    4B   body_length      body 字节数（big-endian, max 1MB）
22    8B   reserved_3       0
30    2B   extend_length    body 中 extend_head 占的字节数
──────────────────────────────────────────
32+   var  body             = extend_head + payload (protobuf)
```

### 命令码

| 命令 | 代码 | 方向 | 说明 |
|------|------|------|------|
| LOGIN | 0x1771 | 双向 | 登录请求/响应，payload 含一次性 token |
| INIT | 0x1B0E | 双向 | 会话初始化（LOGIN 成功后必须发） |
| QUOTE | 0x1AA8 | 双向 | 报价查询，payload 含 security_id + selectors |
| Heartbeat | 0x1844 | 服务端→客户端 | 保活，代理/客户端需要跳过 |
| ConnIpReq | - | 客户端→服务端 | 请求服务器 IP 列表（protobuf） |
| ConnIpRsp | - | 服务端→客户端 | 返回 IP 池（ConnIpItem: ip, port, identity） |

### Payload 编码

- body = `extend_head` + `payload`
- `extend_head`：追踪信息，含 32 字节随机数（每次请求新生成），protobuf 编码
- `payload`：业务数据，protobuf 编码，字段用 varint tag
- LOGIN 响应 payload：`varint(unknown) + varint(result)`，result=0 表示成功，0xFFFFFFFFFFFFFFFF 表示 busy
- QUOTE 响应 payload：嵌套 protobuf，field 1 是 item 列表，每个 item 内 field 2 subtype=0 的子消息包含 `field1=current_price, field2=prev_close`，价格单位 nanounits（÷ 1e9 = JPY）

### 序列号规则

- `NativeQuoteClient`（packet replay 模式）：从 301 开始
- `ProxyQuoteClient`（MITM 模式）：从 9001 开始（避免和 FTNN 自身的序列号冲突）
- 每次请求 sequence++，响应匹配同一个 sequence
- `read_frame_for_command()` 按 command + sequence 匹配，最多跳过 50 个不匹配的帧（heartbeat 等）

## 连接生命周期

### Proxy 模式（v0.5，主要模式）

```
时间线：
──────────────────────────────────────────────────────────────────────────

1. proxy 启动
   load_ip_pool()                    → ~200 个候选 IP
   route add -host <IP> lo0          × N 个
   pfctl -a stock-moni               → rdr :443 → :19443
   listen 127.0.0.1:19443

2. FTNN 启动 + 自动登录
   FTNN → connect(某个 IP:443)
        → lo0 → PF anchor → 127.0.0.1:19443
   proxy accept()
   proxy → pfctl -s state           → 恢复原始目标 IP
   proxy → connect(原始 IP:443)     → 真实服务器

3. LOGIN 透传
   FTNN ──LOGIN req──→ proxy ──────→ 服务器
   FTNN ←─LOGIN rsp──← proxy ←─────← 服务器
                        ↓
              解析 user_id（header[8:12] >> 8）
              解析 result（payload varint）
              result == 0 → 成功

4. Socket 交接（LOGIN 成功后）
   ┌──────────┐         ┌──────────┐         ┌──────────┐
   │   FTNN   │─ close ─│  proxy   │─ keep ──│  服务器   │
   └──────────┘         └──────────┘    ↓     └──────────┘
                                   ProxySession {
                                     socket: 服务器连接 ← 保留
                                     user_id: 从 header 提取
                                   }
   清理: route delete + pfctl -a stock-moni -F all
   FTNN 进程不再被拦截, 可以正常重连其他 IP

5. 报价查询（在保留的 socket 上）
   ProxyQuoteClient(socket, user_id)
   ──INIT req──→ 服务器    (seq=9001, extend_head 含随机数)
   ←─INIT rsp──←
   ──QUOTE req─→ 服务器    (seq=9002, security_id=82669546513451)
   ←─QUOTE rsp←─           → parse_quote_prices → (417.1, 415.8) JPY
   ──QUOTE req─→           (seq=9003, ...)
   ...                     最多 3 次/cycle, 间隔 ≥ 250ms
```

### Packet Replay 模式（legacy）

```
NativeQuoteClient.login(captured_packet, user_id)
  → connect(server:443)             直连，不经代理
  → sendall(captured_packet)        发送完整的 LOGIN 帧（含一次性 token）
  ← read_frame() → parse_login_result()
  → sendall(INIT request)           (seq=302)
  ← read_frame()
  → query(security_id) × 3         (seq=303, 304, 305)
```

**限制**：token 一次性消耗，FTNN 登录后 token 即失效，replay 永远返回 LOGIN_REJECTED。所以这个模式只在 FTNN 完全不运行时才可能工作（需要手动抓包）。

### 连接共享的坑

MITM 模式下，proxy 只接管了**一条** TCP 连接。FTNN 会同时建立多条连接（行情通道、交易通道等），但我们只需要其中一条成功 LOGIN 的：

- 代理 accept 多个连接，每个连接独立 `_handle_connection` 线程
- 第一个 LOGIN 成功的连接被保留，其余自然断开
- 保留的 socket 是**共享连接**——服务端仍然会推 heartbeat (0x1844)
- `read_frame_for_command()` 通过 command + sequence 过滤，跳过不匹配的帧
- `max_skip=50`：如果连续 50 帧都不匹配目标，抛出 framing_error

## 核心数据流

```
obtain_authenticated_session(config)           # proxy.py — 入口
  ├── load_ip_pool()                           # F3CLogin binary + SQLite
  │     ├── _load_f3clogin_ips()               # strings | grep IP | filter public
  │     └── _load_guaranteed_ips()             # sqlite3 CommonConfig.db
  └── _ProxyBridge(config, ip_pool)
        ├── _setup_routes()                    # route add 每个 IP → lo0
        ├── _setup_pf_anchor()                 # pfctl -a stock-moni -f -
        ├── _lsof_monitor()                    # 后台线程, hot-add ConnIpRsp IP
        ├── accept_loop()                      # 监听 19443
        ├── killall FTNN + open FTNN           # 一次启动
        ├── _handle_connection()
        │     ├── _resolve_original_dst()      # pfctl -s state → 原始 IP
        │     └── 透传 + 解析 FT 帧 → LOGIN 成功
        └── _cleanup()                         # route delete + pfctl -a stock-moni -F all
```

## 文件说明

| 文件 | 职责 | 改动风险 |
|------|------|----------|
| `protocol.py` | FT 二进制协议：header 解析、varint、帧读写、protobuf 价格解码 | 高 — 一个字节偏移错就全挂 |
| `models.py` | Pydantic 模型，fail-closed 验证（decision 必须匹配证据） | 中 — 模型验证很严格 |
| `adapter.py` | `ProxyQuoteClient`（MITM 后查询）+ security_id 映射 | 中 |
| `proxy.py` | 单阶段代理：load_ip_pool + _ProxyBridge (route/PF-anchor/intercept/lsof) | 中 |
| `service.py` | `FutuNativeService`：主循环、重连、backoff、health 追踪 | 低 |

## 使用方法

### 一键运行

```bash
git clone https://github.com/bigbigmonkey123/futu-moni.git
cd futu-moni
./run.sh
```

### Python API

```python
from futu_moni.proxy import ProxyConfig, obtain_authenticated_session
from futu_moni.adapter import ProxyQuoteClient, resolve_jp_securities, DEFAULT_SECLIST_PATHS

session = obtain_authenticated_session(ProxyConfig())
_, resolved = resolve_jp_securities(DEFAULT_SECLIST_PATHS)
client = ProxyQuoteClient(session.socket, session.user_id)
for item in resolved:
    if item.security_id:
        last, prev_close = client.query(item.security_id)
        print(f"{item.symbol}: {last} JPY")
```

## 运行前检查清单

1. **富途牛牛已安装**: `/Applications/富途牛牛.app` 存在
2. **SecListDB 存在**: `ls ~/.com.futunn.FutuOpenD/F3CNN/SecListDB.v13.dat`
3. **有 root 权限**: route/pfctl/lsof 需要
4. **首次使用请手动登录并勾选"自动登录"**

## 输出格式

```json
{
  "decision": "CONDITIONAL_GO",
  "quotes": [
    {
      "symbol": "1306",
      "last": "417.1",
      "prev_close": "415.8",
      "status": "success"
    }
  ]
}
```

`decision == "CONDITIONAL_GO"` 当且仅当：3 只全部查到价格 + 登录成功 + 映射正确。

## 已知坑

1. **首次必须手动登录** — FTNN 需要至少登录一次才有自动登录 token
2. **SIGKILL 残留路由** — 手动清理: `sudo route delete -host <IP>; sudo pfctl -a stock-moni -F all`
3. **original_dst 恢复** — `pfctl -s state` 解析可能不精确，fallback 到池中第一个 IP
4. **代理超时** — 默认 120 秒等待登录，如果自动登录 token 过期需手动重新登录

## 测试

```bash
cd /path/to/futu-moni
pip install -e ".[test]"
pytest tests/ -v
```

## stock-moni 集成

生产代码在 `stock-moni/src/stock_moni/observations/futu_native_app_session/`。相比本仓库多了：
- `ProxyOutcome` / `ProxySetupError` 类型化错误处理
- State file v4（mode-0600, owner identity 校验, cleanup_stale_state 恢复）
- `run_command` 注入支持测试
- CLI 入口 `uv run stock-moni futu-native-serve`
