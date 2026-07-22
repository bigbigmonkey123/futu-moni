# futu-moni — Codex 快速上手

## 这个项目是什么

通过富途牛牛（FTNN）桌面端的原生 FT 二进制协议，持续获取日本市场 ETF 报价的服务。

**核心约束：不允许使用 OpenD。** 只走 FTNN 原生 app 的网络通道。

## 一键运行

```bash
# 1. 克隆
git clone https://github.com/bigbigmonkey123/futu-moni.git
cd futu-moni

# 2. 安装
uv sync

# 3. 前提：首次必须手动打开 FTNN 登录一次，勾选"自动登录"

# 4. 运行（需要 root）
sudo uv run python -m futu_moni.main
```

程序会自动：加载 IP 池 → 设置路由 → 启动 FTNN → 拦截登录 → 查询报价 → 清理。

## 运行前检查

```bash
# FTNN 已安装？
ls /Applications/富途牛牛.app

# SecListDB 存在？（报价查询需要 security_id 映射）
ls ~/.com.futunn.FutuOpenD/F3CNN/SecListDB.v13.dat

# 有 root 权限？（route/pfctl/lsof 需要）
sudo echo ok
```

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

## 认证原理

FT 协议的 LOGIN token 是**服务端一次性消耗**的——FTNN 发出后立刻失效，packet replay 永远不行。

FTNN 的 FT 协议服务器 IP 是**硬编码+API 动态分配**的（不走 DNS），域名劫持、/etc/hosts、SQLite 修改均无效。

### IP 解析链路（优先级从高到低）

1. **F3CLogin.framework 硬编码**: ~155 个公网 IP，编译在二进制里
2. **ConnIpRsp**: FT 协议在线 IP 分配（protobuf，cmd 0xFFE1/0x0529/0x4EB3）
3. **云配置 confnn.futuhn.com**: 覆盖 SQLite 中的 guaranteed_ip
4. **guaranteed_ip_for_conn**: SQLite 回退池
5. **forced_ip_for_conn**: 功能未启用

### 解决方案：v0.6 route-lift + ConnIpRsp 在代理内解析

```
1. 预加载 IP 池 (~159 个):
   strings F3CLogin.framework        → ~155 个公网 IP
   sqlite3 CommonConfig.db           → guaranteed_ip_for_conn → ~54 个 IP
   合并去重

2. 全 IP route trap:
   route add -host <每个IP> -interface lo0
   pfctl -a stock-moni -f -    →  rdr on lo0 port 443 → 127.0.0.1:19443
   pfctl -e

3. 启动 FTNN:
   killall FTNN → sleep 1 → open FTNN
   FTNN → connect(某个 IP:443) → lo0 → PF anchor → proxy:19443

4. proxy 上游连接（route-lift）:
   route delete -host <目标IP>        # 临时移除 trap
   connect(目标IP:443)                # 走默认路由直连真实服务器
   route add -host <目标IP> lo0       # 立刻恢复 trap
   竞态窗口 <100ms，FTNN 无法在此间隙逃逸

5. ConnIpRsp 在代理内解析:
   proxy 解析 server→client 帧流
   if command in {0xFFE1, 0x0529, 0x4EB3}:
       extract_connip_ips(payload) → 新 IP 集合
       hot-add route（在 FTNN 使用这些 IP 之前）

6. lsof 后备:
   后台线程每 3 秒 lsof，兜底发现漏网 IP

7. LOGIN 成功后:
   保留 proxy↔服务器 socket
   清除全部 route + PF anchor
   在 socket 上注入 INIT + QUOTE 查询
```

### 关键技术细节

- **route-lift 而非 IP_BOUND_IF**: 早期尝试用 `setsockopt(IP_BOUND_IF)` 绑定 socket 到物理网卡绕过 lo0 trap，但与 route trap 冲突（`EADDRNOTAVAIL`）。改为临时 route delete → connect → route add
- **ConnIpRsp 解析时机**: ConnIpRsp 在已代理的 TCP 连接上传输，proxy 在转发给 FTNN 之前就解析出新 IP 并 hot-add route，时序上保证在 FTNN 使用新 IP 之前完成
- PF **anchor** `stock-moni`（不污染全局 PF），清理用 `pfctl -a stock-moni -F all`
- `pfctl -s state` 恢复 original destination IP（fallback 到池中第一个 IP）

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
| ConnIpRsp | 0xFFE1 / 0x0529 / 0x4EB3 | 服务端→客户端 | 返回 IP 池，protobuf 编码 |

### ConnIpRsp protobuf 结构

```
ConnIpRsp {
  field 1: result_code (varint)          // tag 0x08
  field 2: string                        // tag 0x12
  field 3: repeated ConnIpItem           // tag 0x1a, len-delimited
}

ConnIpItem {
  field 1: server_ip (string)            // tag 0x0a — 我们要的
  field 2: port (varint)                 // tag 0x10
  field 3: domain (string)              // tag 0x1a
  field 4: region (varint)              // tag 0x20
  field 5: conn_identity (varint)       // tag 0x28 — 0x64=主通道
}
```

### Payload 编码

- body = `extend_head` + `payload`
- `extend_head`：追踪信息，含 32 字节随机数（每次请求新生成），protobuf 编码
- `payload`：业务数据，protobuf 编码，字段用 varint tag
- LOGIN 响应 payload：`varint(unknown) + varint(result)`，result=0 表示成功，0xFFFFFFFFFFFFFFFF 表示 busy
- QUOTE 响应 payload：嵌套 protobuf，field 1 是 item 列表，每个 item 内 field 2 subtype=0 的子消息包含 `field1=current_price, field2=prev_close`，价格单位 nanounits（÷ 1e9 = JPY）

### 序列号规则

- `ProxyQuoteClient`（MITM 模式）：从 9001 开始（避免和 FTNN 自身的序列号冲突）
- 每次请求 sequence++，响应匹配同一个 sequence
- `read_frame_for_command()` 按 command + sequence 匹配，最多跳过 50 个不匹配的帧

## 连接生命周期

```
时间线：
──────────────────────────────────────────────────────────────────────────

1. proxy 启动
   load_ip_pool()                    → ~159 个候选 IP
   route add -host <IP> lo0          × N 个
   pfctl -a stock-moni               → rdr :443 → :19443
   listen 127.0.0.1:19443

2. FTNN 启动 + 自动登录
   FTNN → connect(某个 IP:443)
        → lo0 → PF anchor → 127.0.0.1:19443
   proxy accept()
   proxy → pfctl -s state           → 恢复原始目标 IP
   proxy → route-lift connect       → 真实服务器（临时移除+恢复 route）

3. 帧流透传 + ConnIpRsp 解析
   FTNN ──各种 req──→ proxy ──────→ 服务器
   FTNN ←─各种 rsp──← proxy ←─────← 服务器
                       ↓
             if ConnIpRsp: extract IPs → hot-add route
             if LOGIN req: 记录 user_id
             if LOGIN rsp: 解析 result

4. LOGIN 成功 → Socket 交接
   proxy 关闭 client 侧连接
   保留 proxy↔服务器 socket → ProxySession
   清理: route delete + pfctl -a stock-moni -F all

5. 报价查询
   ProxyQuoteClient(socket, user_id)
   ──INIT req──→ 服务器    (seq=9001)
   ←─INIT rsp──←
   ──QUOTE req─→ 服务器    (seq=9002, security_id=...)
   ←─QUOTE rsp←─           → parse_quote_prices → JPY
```

## 核心数据流

```
obtain_authenticated_session(config)           # proxy.py — 入口
  ├── load_ip_pool()                           # F3CLogin binary + SQLite
  │     ├── _load_f3clogin_ips()               # strings | grep IP | filter public
  │     └── _load_guaranteed_ips()             # sqlite3 CommonConfig.db
  └── _ProxyBridge(config, ip_pool)
        ├── _setup_routes()                    # route add 每个 IP → lo0
        ├── _setup_pf_anchor()                 # pfctl -a stock-moni -f -
        ├── _lsof_monitor()                    # 后台线程, hot-add 漏网 IP
        ├── accept_loop()                      # 监听 19443
        ├── killall FTNN + open FTNN           # 一次启动
        ├── _handle_connection()
        │     ├── _resolve_original_dst()      # pfctl -s state → 原始 IP
        │     ├── _connect_forward()           # route-lift: delete → connect → add
        │     ├── ConnIpRsp 解析               # extract_connip_ips → hot-add route
        │     └── LOGIN 解析                   # 成功 → ProxySession
        └── _cleanup()                         # route delete + pfctl -a stock-moni -F all
```

## 文件说明

| 文件 | 职责 |
|------|------|
| `proxy.py` | 核心代理：IP 池加载、route/PF、route-lift 连接、ConnIpRsp 解析、LOGIN 拦截 |
| `protocol.py` | FT 二进制协议：header 解析、varint、帧读写、protobuf 价格解码 |
| `models.py` | Pydantic 模型，fail-closed 验证 |
| `adapter.py` | `ProxyQuoteClient`（MITM 后查询）+ security_id 映射 |
| `service.py` | `FutuNativeService`：主循环、重连、backoff、health 追踪 |

## 测试

```bash
uv sync --extra test
uv run pytest tests/ -v
```

## 手动清理（异常退出后）

```bash
# 清理 PF anchor
sudo pfctl -a stock-moni -F all

# 查看残留路由
netstat -rn | grep lo0 | grep -v "127\.\|::1\|ff"

# 逐个删除
sudo route delete -host <IP>
```

## 已知坑

1. **首次必须手动登录** — FTNN 需要至少登录一次才有自动登录 token
2. **反复 killall 会导致 token 失效** — 如果 LOGIN 被 reject，需要手动重新登录 FTNN
3. **SIGKILL 残留路由** — 用上面的手动清理命令
4. **代理超时** — 默认 120 秒等待登录

## 验证证据（2026-07-21 实机测试）

1. **IP 池加载**: 159 个候选 IP（155 F3CLogin + 54 guaranteed，去重后 159）
2. **route-lift 上游连接**: 4/4 连接全部成功（101.32.198.103, 49.51.78.82, 43.130.30.145, 124.156.124.214）
3. **PF anchor 拦截**: FTNN 的所有 TCP:443 连接均被重定向到 proxy
4. **LOGIN 检测**: proxy 在帧流中正确识别 LOGIN 请求并提取 user_id
5. **ConnIpRsp 解析**: 单元测试验证 protobuf 解析、私有 IP 过滤、帧重组、多命令码识别
6. **hot-add route**: 动态发现的 IP（43.130.30.145, 43.175.136.145, 42.193.128.62 等）在 FTNN 使用前被 trap

## stock-moni 集成

生产代码在 `stock-moni/src/stock_moni/observations/futu_native_app_session/`。相比本仓库多了：
- `ProxyOutcome` / `ProxySetupError` 类型化错误处理
- State file v4（mode-0600, owner identity 校验, cleanup_stale_state 恢复）
- `_FrameStream` 类替代内联 buffer 解析
- `run_command` 注入支持测试
- CLI 入口 `uv run stock-moni futu-native-serve`
