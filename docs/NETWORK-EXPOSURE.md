# 公网入口与连接受阻

加密、抗探测、网络可达性、服务商账号政策是不同问题。项目不能保证 IP 不会被封锁，也不能从一次超时确定封锁原因。出现 SSH 与所有节点同时直连失败时，先核对服务商控制台和主机状态，再比较不同网络路径；更换协议、SNI、域名或端口不能恢复整个 IP 的可达性。

## 参考的官方实现

| 项目 | 可借鉴的机制 | 本项目的选择与边界 |
| --- | --- | --- |
| [Hysteria 2 协议](https://v2.hysteria.network/docs/developers/Protocol/) | QUIC/HTTP3、认证失败响应普通 HTTP3 内容 | 可选 HY2 入口；未认证请求返回本地 HTML，不连接 SOCKS5 上游。不宣称内容或流量无法被识别。 |
| [sing-box HY2](https://sing-box.sagernet.org/configuration/inbound/hysteria2/) | masquerade、证书验证、服务端忽略客户端强制带宽 | 复用已固定版本的核心；保留 HTTP3，不启用随机数据混淆；不设置带宽并启用 ignore_client_bandwidth 使用 BBR。 |
| [XTLS REALITY](https://github.com/XTLS/REALITY/blob/main/README.en.md) | 在 TLS 握手中验证代理客户端、处理未认证连接 | 已研究，但这次没有实现 REALITY，也不会把现有 TUIC 简单改个 SNI 就称为 REALITY。 |
| [TUIC / sing-box](https://sing-box.sagernet.org/configuration/inbound/tuic/) | 认证、QUIC/TLS、关闭有重放风险的 0-RTT | 保留 TUIC，新增仅 TUIC 模式以停止不需要的 SS TCP 监听。 |
| [Hysteria 2 端口跳跃](https://v2.hysteria.network/docs/advanced/Port-Hopping/) | 可应对部分针对单一 UDP 端口的限制 | 本次不自动添加端口跳跃或大范围防火墙规则。整个 IP/UDP 被限制时无法靠端口跳跃解决。 |

HY2 初始页面是简单的固定欢迎内容，仅用于提供正常 HTTP3 响应，不等同于经过长期验证的真实网站伪装。没有证据支持“换成此配置就不会被识别”的承诺。它也不会启用 TCP 80/443 网站或接管现有站点。

## 菜单 25：按节点选择入口

1. **仅 TUIC**：保留原 TUIC 凭据、端口、证书；停止该节点 SS 的 TCP 监听。
2. **仅 Hysteria 2**：先在菜单 22 配置公共 CA 域名证书，再选此模式。程序生成独立随机 HY2 密码，在原公网端口监听 UDP，关闭原 SS 和 TUIC。导出普通 `hysteria2://`、Mihomo YAML 和 sing-box JSON，始终开启证书验证。
3. **SS + TUIC**：恢复原来的兼容模式及原 SS/TUIC 凭据；移除 HY2 凭据。下次启用 HY2 会生成新密码。

切换只影响选中节点，失败通过原事务回滚。其他节点、SSH、防火墙、DNS、已安装的其他代理服务不修改。仅 UDP 模式仍通过认证的 3proxy 固定上游转发 TCP 请求，拒绝应用 UDP；不存在直连回退。

切换后必须重新导入客户端配置、更新自己的订阅。仅 UDP 模式的文件中不再包含 SS，失效的 JSON 会删除；旧的手机 TUIC 二维码在切到 HY2 时删除。原二维码菜单用于 TUIC；HY2 使用菜单 16 中的普通链接，不能把 HY2 当成 TUIC 导入。

已有节点和新增节点默认继续使用 SS + TUIC，避免升级时使已分发的链接突然失效。需要关闭 SS 时由管理员主动选择；安装升级本身不代表已切换模式。

## 在电脑上比较直连与代理路径

下载源码后执行（Windows 可将 `python3` 换为自己的 Python 命令）：

```bash
python3 tools/check_reachability.py VPS公网IPv4 --ssh-port 22 --socks-port 10808
```

`10808` 必须是电脑已经运行的本地 SOCKS5 代理。没有代理可省略该参数；工具不读取密码或代理环境变量，不修改系统设置。至多对 4 个明确指定端口各做一次连接；没有端口扫描、持续测速或第三方检测网站请求。

经代理收到真实 SSH 握手而直连超时，说明路径或来源存在差异，仍应检查区域阻断、路由、服务商 ACL 和安全组。部分本地代理提前响应 SOCKS CONNECT，因此普通端口“TCP 建连成功”不能证明远端应用可用；工具对 SSH 必须收到握手才确认这条路径有效。

服务器的菜单 24 只验证服务器内部链路。TCP 测试不能代替 TUIC/HY2 的 UDP 客户端测试，也不等于实际下载速度。不要通过关闭证书验证、关闭整个防火墙或运行来源不明的“解封”脚本来掩盖连接问题。

上游 IP 能 Ping 通不代表它的 SOCKS5 端口和认证可用。添加节点时的检查现在分别报告 TCP 建连、SOCKS5 协议协商、账号密码认证响应的超时；认证超时只表示未收到结果，不等于供应商明确拒绝了密码。明确拒绝认证仍单独报错。
