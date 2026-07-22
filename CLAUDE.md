# futu-moni — Codex 快速上手

## 这个项目是什么

通过富途牛牛（FTNN）桌面端的原生 FT 二进制协议，获取日本市场 ETF 报价（1306/1321/1489）。

**核心约束：不允许使用 OpenD。** 只走 FTNN 原生 app 的网络通道。

**注意：运行本工具会强制关闭正在运行的 FTNN 进程，请确保没有在 FTNN 中进行交易操作。**

## 一键运行

```bash
# 1. 克隆
git clone https://github.com/bigbigmonkey123/futu-moni.git
cd futu-moni

# 2. 运行（自动安装依赖 + 自动申请 sudo）
./run.sh
```

`run.sh` 会自动：找 Python 3.11+ → 创建 venv → 安装依赖 → 申请 sudo → 启动。

如果没有 `run.sh` 的执行权限：`chmod +x run.sh`

### 等价的手动运行方式

```bash
# 需要 uv (安装: curl -LsSf https://astral.sh/uv/install.sh | sh)
uv sync
sudo uv run python -m futu_moni
```

**注意**: 入口是 `python -m futu_moni`（不是 `futu_moni.main`）。

## 运行前必须做的一件事

**首次使用前，必须手动打开 FTNN 登录一次：**

1. 打开 `/Applications/富途牛牛.app`
2. 输入你的富途账号密码登录
3. **勾选「自动登录」复选框**（登录框底部）
4. 登录成功后可以关闭 FTNN

这一步是为了让 FTNN 保存自动登录 token。之后 `futu-moni` 每次运行时会自动启动 FTNN 并利用这个 token 完成登录。

**如果看到 `login_rejected` 错误**，说明自动登录 token 已失效（通常是因为反复强制关闭 FTNN）。解决方法：重复上面的手动登录步骤。

## 运行前检查

程序启动时会自动检查，但你也可以提前确认：

```bash
# 1. FTNN 已安装？
ls /Applications/富途牛牛.app

# 2. SecListDB 存在？（至少存在 v12 或 v13）
ls ~/.com.futunn.FutuOpenD/F3CNN/SecListDB.v1*.dat

# 3. 有 sudo 权限？（route/pfctl/lsof 需要 root）
sudo echo ok
```

## 运行环境

- macOS（依赖 pfctl、route、lsof 命令）
- Python 3.11+
- 已安装富途牛牛（`/Applications/富途牛牛.app`）
- **需要 root 权限**（route/PF/lsof）
- 如果 Terminal 没有「完全磁盘访问权限」，可能无法读取 FTNN 的 SQLite 数据库

## 输出示例

```
============================================================
futu-moni: JP ETF 报价服务 (1306 / 1321 / 1489)
============================================================

[检查] 全部通过 ✓
[启动] 预加载 IP 池, 设置路由拦截, 启动 FTNN...
[代理] 登录成功 ✓
[查询] 正在获取报价...

  1306: last=417.1 JPY, prev_close=415.8 JPY ✓
  1321: last=40385.0 JPY, prev_close=40210.0 JPY ✓
  1489: last=2543.0 JPY, prev_close=2535.0 JPY ✓

============================================================
✓ 全部成功: 3/3 只 ETF 获取到报价
  decision = CONDITIONAL_GO
============================================================

结果已写入: /path/to/futu_moni_result.json
```

## 常见错误及解决

| 错误信息 | 原因 | 解决方法 |
|----------|------|----------|
| `需要 root 权限` | 没有 sudo | 用 `sudo ./run.sh` 或 `sudo uv run python -m futu_moni` |
| `富途牛牛未安装` | FTNN 没装 | 安装 `/Applications/富途牛牛.app` |
| `SecListDB 不存在` | 没有登录过 FTNN | 手动打开 FTNN 登录一次 |
| `login_rejected` | 自动登录 token 失效 | 手动打开 FTNN 重新登录，勾选自动登录 |
| `fresh_login_timeout` | 120秒内没有成功登录 | 检查网络；手动登录 FTNN 刷新 token |
| `Address already in use` | 端口 19443 被占用 | `sudo lsof -i :19443` 找到并 kill 进程 |
| `no IPs in pool` | F3CLogin 二进制不存在 | 确认 FTNN 安装完整 |

## 异常退出后的手动清理

如果程序被 kill -9 或崩溃，可能残留系统级配置：

```bash
# 1. 清理 PF anchor（最重要）
sudo pfctl -a stock-moni -F all

# 2. 查看残留路由
netstat -rn | grep lo0 | grep -v "127\.\|::1\|ff"

# 3. 逐个删除残留路由
sudo route delete -host <IP>

# 4. 查看并 kill 残留的 proxy 监听
sudo lsof -i :19443
sudo kill <PID>

# 5. 如果需要，关闭 FTNN
killall FTNN
```

## 诊断工具

```bash
# 诊断 FTNN 实际连接了哪些 IP（不会修改系统配置）
sudo ./diagnose.sh
```

---

## 以下是技术细节（开发者/Codex 参考）

## 目标证券

| 代码 | security_id | 路由 |
|------|-------------|------|
| 1306 | 82669546513451 | 1001 |
| 1321 | 82669546513459 | 1001 |
| 1489 | 82669546513559 | 1001 |

security_id 来自 FTNN 本地 SQLite（SecListDB，支持 v12 和 v13）。

## 认证原理

FT 协议的 LOGIN token 是**服务端一次性消耗**的——FTNN 发出后立刻失效，packet replay 永远不行。

FTNN 的 FT 服务器 IP 是**硬编码+API 动态分配**的（不走 DNS），域名劫持、/etc/hosts、SQLite 修改均无效。

### IP 解析链路（优先级从高到低）

1. **F3CLogin.framework 硬编码**: ~155 个公网 IP，编译在二进制里
2. **ConnIpRsp**: FT 协议在线 IP 分配（protobuf，cmd 0xFFE1/0x0529/0x4EB3）
3. **云配置 confnn.futuhn.com**: 覆盖 SQLite 中的 guaranteed_ip
4. **guaranteed_ip_for_conn**: CommonConfig.db 回退池（路径: `~/Library/Containers/cn.futu.niuniu.nx/Data/Library/Application Support/Common/CommonConfig.db`）
5. **forced_ip_for_conn**: 功能未启用

### 代理方案：route-lift + ConnIpRsp 在代理内解析

```
1. 预加载 IP 池 (~159 个):
   strings F3CLogin.framework        → ~155 个公网 IP
   sqlite3 CommonConfig.db           → guaranteed_ip_for_conn → ~54 个 IP
   合并去重

2. 全 IP route trap:
   route add -host <每个IP> -interface lo0
   pfctl -a stock-moni -f -    →  rdr on lo0 port 443 → 127.0.0.1:19443
   pfctl -e

3. killall FTNN → sleep 1 → open FTNN
   FTNN → connect(某个 IP:443) → lo0 → PF anchor → proxy:19443

4. proxy 上游连接（route-lift）:
   route delete -host <目标IP>        # 临时移除 trap (<100ms)
   connect(目标IP:443)                # 走默认路由直连真实服务器
   route add -host <目标IP> lo0       # 立刻恢复 trap

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

## FT 二进制协议

### 传输层

- **TCP 端口 443**，但**不是 TLS**——裸 TCP 上跑自定义二进制帧

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
| QUOTE | 0x1AA8 | 双向 | 报价查询 |
| Heartbeat | 0x1844 | 服务端→客户端 | 保活 |
| ConnIpRsp | 0xFFE1 / 0x0529 / 0x4EB3 | 服务端→客户端 | 返回 IP 池 |

### ConnIpRsp protobuf 结构

```
ConnIpRsp {
  field 1: result_code (varint)          // tag 0x08
  field 2: string                        // tag 0x12
  field 3: repeated ConnIpItem           // tag 0x1a, len-delimited
}

ConnIpItem {
  field 1: server_ip (string)            // tag 0x0a
  field 2: port (varint)                 // tag 0x10
  field 5: conn_identity (varint)        // tag 0x28, 0x64=主通道
}
```

### Payload 编码

- body = `extend_head`（追踪信息）+ `payload`（业务数据），都是 protobuf
- LOGIN 响应：`varint(unknown) + varint(result)`，result=0 成功，0xFFFFFFFFFFFFFFFF busy
- QUOTE 响应：嵌套 protobuf，价格单位 nanounits（÷ 1e9 = JPY）

## 文件说明

| 文件 | 职责 |
|------|------|
| `__main__.py` | CLI 入口（`python -m futu_moni`），preflight 检查 + 单次查询 |
| `proxy.py` | 核心代理：IP 池加载、route/PF、route-lift 连接、ConnIpRsp 解析、LOGIN 拦截 |
| `protocol.py` | FT 二进制协议：header、varint、帧读写、protobuf 价格解码 |
| `models.py` | Pydantic 模型，fail-closed 验证 |
| `adapter.py` | `ProxyQuoteClient`（MITM 后查询）+ security_id 映射 |
| `service.py` | `FutuNativeService`：持续轮询主循环 |
| `run.sh` | 一键启动脚本（自动找 Python、创建 venv、申请 sudo） |
| `diagnose.sh` | 诊断 FTNN 实际连接目标（不修改系统配置） |

## 测试

```bash
# 安装 pytest（项目未声明 test extra，需手动安装）
uv sync
uv pip install pytest

# 运行测试
uv run pytest tests/ -v
```

## stock-moni 集成

生产代码在 `stock-moni/src/stock_moni/observations/futu_native_app_session/`。相比本仓库多了：
- `ProxyOutcome` / `ProxySetupError` 类型化错误处理
- State file v4（mode-0600, owner identity 校验, cleanup_stale_state 恢复）
- `_FrameStream` 类替代内联 buffer 解析
- `run_command` 注入支持测试
- CLI 入口 `uv run stock-moni futu-native-serve`
