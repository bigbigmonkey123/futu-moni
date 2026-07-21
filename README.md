# futu-moni

通过富途牛牛桌面端获取 JP 市场 ETF 报价 (1306 / 1321 / 1489)。

不需要 OpenD，不需要 API key，不需要任何配置。

## 使用

**前提**: macOS + 已安装[富途牛牛](https://www.futunn.com/download) + Python 3.11+

```bash
git clone https://github.com/bigbigmonkey123/futu-moni.git
cd futu-moni
./run.sh
```

脚本会自动：创建虚拟环境 → 安装依赖 → 申请 sudo → 启动代理 → 打开富途牛牛

**你只需要在弹出的富途牛牛窗口中登录**，登录后自动查询报价并输出结果。

### 持续服务模式

```bash
./run.sh serve        # 每 5 分钟查一次
./run.sh serve 120    # 每 2 分钟查一次
```

### 通过 pip 安装

```bash
pip install git+https://github.com/bigbigmonkey123/futu-moni.git
sudo futu-moni
```

## 输出示例

```
[代理] 解析服务器域名 nnproxy.futunn.com ...
[代理] 修改 /etc/hosts → 127.0.0.1
[代理] 启动 FTNN 并等待登录 (最多 120 秒)...

  ➜ 请在弹出的富途牛牛窗口中正常登录

[代理] 登录成功 ✓

[查询] 正在获取报价...

  1306: last=417.1 JPY, prev_close=415.8 JPY ✓
  1321: last=41250.0 JPY, prev_close=41100.0 JPY ✓
  1489: last=2350.5 JPY, prev_close=2340.0 JPY ✓

============================================================
✓ 全部成功: 3/3 只 ETF 获取到报价
  decision = CONDITIONAL_GO
============================================================
```

## 原理

```
1. 解析 nnproxy.futunn.com 得到真实服务器 IP
2. 临时修改 /etc/hosts → 127.0.0.1
3. 启动代理 (127.0.0.1:443) + 打开富途牛牛
4. 富途牛牛登录流量 → 本地代理 → 真实服务器
5. 登录成功后: 恢复 /etc/hosts, 在连接上查询报价
```

FT 协议使用一次性登录 token，无法抓包重放。本项目让 FTNN 自己完成认证，然后"借用"认证后的连接查询报价。

## 常见问题

**端口 443 被占用**
```bash
sudo lsof -nP -iTCP:443 -sTCP:LISTEN
# 关掉占用 443 的程序, 再运行 ./run.sh
```

**异常退出后 /etc/hosts 残留**
```bash
sudo sed -i '' '/futu-moni-proxy/d' /etc/hosts
```

**DNS 解析的服务器拒绝登录**
```bash
# 手动指定已知可用的服务器 IP
sudo .venv/bin/python -c "
from futu_moni import FutuNativeService, ServiceConfig, ProxyConfig
config = ServiceConfig(use_proxy=True, proxy=ProxyConfig(forward_server='119.28.37.206'))
FutuNativeService(config, on_report=lambda r,h: print(r.model_dump_json())).run()
"
```

## 目标证券

| 代码 | 名称 | 市场 |
|------|------|------|
| 1306 | NEXT FUNDS TOPIX ETF | JP |
| 1321 | Nikkei 225 ETF | JP |
| 1489 | NF 日経高配当50 ETF | JP |

## 已知限制

- macOS only
- 需要 root 权限 (/etc/hosts + 端口 443)
- FTNN 崩溃后需手动重启
- 需要在 FTNN 窗口中手动登录 (有自动登录则无需操作)

## License

MIT
