# 实验脚本

FT 协议 MITM 代理的迭代过程，从失败到成功。

## 演进路线

| 脚本 | 方法 | 结果 |
|------|------|------|
| `ft_tcp_proxy.py` | 透明 TCP 代理分析流量 | 能看到协议帧，但无法拦截认证 |
| `ft_proxy.py` | 透明代理尝试直接转发 | LOGIN 被服务器拒绝 (token 已消耗) |
| `ft_mitm_proxy.py` | lo0 IP 别名 + 多监听器 | Python accept() bug 导致无法接受连接 |
| `ft_full_proxy.py` | lo0 IP 别名 (扩展 22 IP) | 同样的 accept() bug |
| **`ft_pf_proxy.py`** | **PF rdr + route (最终方案)** | **成功: 9/9 报价, 3 轮全通过** |

## 关键发现

- FT LOGIN token 是一次性的，packet replay 永远不行
- macOS lo0 IP alias 有 Python accept() bug (nc 正常但 Python 不行)
- PF rdr 绕过了这个 bug，是可行的替代方案
- Futu 服务器池是动态的 (~22+ IP)，每次会话都变
- Forward server 选择很重要: 49.51.78.83 拒绝登录, 119.28.37.206 成功
