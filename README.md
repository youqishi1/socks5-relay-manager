# SOCKS5 中转管理系统

Ubuntu/Debian VPS 中文管理工具，并提供 CentOS 7 x86_64 / systemd 219 兼容模式。粘贴完整 SOCKS5，自动部署 **加密 TCP + TUIC** 两种入口、随机凭据、证书和客户端配置。每个出口独立运行 3proxy，固定一个上游，无其他上游或 VPS 直连回退。

```text
电脑 → 加密 TCP 或 TUIC → VPS:30001 → 本机 3proxy:20001 → SOCKS5 A → 网站
电脑 → 加密 TCP 或 TUIC → VPS:30002 → 本机 3proxy:20002 → SOCKS5 B → 网站
```

TCP 使用 Shadowsocks 2022，TUIC 使用 QUIC/TLS。两种入口共用公网端口号，分别监听 TCP/UDP。不需要预装 TUIC 或购买域名；自动证书通过客户端指纹或内嵌信任验证，默认不关闭验证和不启用 0-RTT。

## 一键安装

以 root 登录，普通用户先 `sudo -i`，再复制一整行：

```bash
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/youqishi1/socks5-relay-manager/v1.3.1/start.sh -o /root/socks-relay-setup.sh && bash /root/socks-relay-setup.sh
```

固定版本安装包先校验 SHA-256，再执行安装。交互终端安装后自动打开菜单，以后 root 输入 `sb1`，普通用户输入 `sudo sb1`。原命令 `socks-menu` 继续可用。若 `/usr/local/bin/sb1` 已被其他程序占用，安装器拒绝覆盖。没有 curl 时先安装 `curl ca-certificates`。下载源码后在源码目录执行 `bash install.sh --local`。

支持完整 systemd 的 Ubuntu 22.04/24.04、Debian 12/13；安装时需要访问发行版源、GitHub。项目专用核心是 3proxy 0.9.9.0、sing-box 1.14.2，官方源固定校验，不改动已有 TUIC/VLESS/sing-box 服务。不使用面板、Xray 或 Docker。架构支持 x86_64、aarch64、armv7l、i686、riscv64，实际验证范围见 [测试说明](docs/TESTING.md)。

CentOS 7 x86_64 使用相同命令：自动使用官方 7.9.2009 归档（HTTPS、RPM 签名校验），项目软件源文件只保存在 `/opt/socks5-relay-manager/yum-repos`，不改系统 yum 配置。原生 Python 过旧时，自动编译独立 Python 3.12.15 / OpenSSL 3.5.9 到项目目录，不覆盖 `/usr/bin/python` 或系统 OpenSSL。首次编译可能需要较长时间及额外磁盘/内存；再次安装复用独立运行环境。服务配置适配 systemd 219，保留凭据私有权限、只读程序/配置目录和服务隔离。证书生成兼容系统 OpenSSL 1.0.2。

兼容安装不等于修复老系统的漏洞：CentOS 7 已于 2024-06-30 停止官方安全更新，长期使用建议迁移到受维护系统。[CentOS 官方说明](https://www.centos.org/centos-linux/)。

## 只填写一整条 SOCKS5

菜单 **1** 粘贴以下任一格式，输入隐藏，粘贴后回车即可：

```text
IP:端口:账号:密码
socks5://账号:密码@IP:端口
[IPv6地址]:端口:账号:密码
```

冒号格式按前 3 个冒号拆分，密码中的冒号保留；账号含冒号/@ 时用 URL 格式和 URL 编码。支持可打印特殊字符及 UTF-8 密码，拒绝换行、控制字符及 3proxy 保留用户名 `*`。

程序检测上游，自动分配端口、生成凭据/证书、启动两种入口并生成私有客户端文件。菜单 **16** 一次查看全部中转的连接信息、SS 密钥、TUIC UUID/密码及本机账密，无需逐个输入端口；**18** 重新导出；**19** 给旧中转启用双模式，此时旧原生端口改为本机入口，电脑使用新加密公网端口。

旧版默认仅允许本机来源，电脑直接连接原生 SOCKS5 可能因此被拒绝。新版状态显示来源和绑定地址。公网地址优先从网卡发现，NAT 时通过不含凭据的 HTTPS 查询获取并保存；失败时菜单 **20** 设置公网 IP/域名。NAT 的端口映射仍需主机商提供。

## 电脑使用

通过现有 SSH/SFTP 下载 `/etc/socks5-relay-manager/exports/dual` 的文件。文件含客户端凭据和公开证书，不含代理商账号密码及 TLS 私钥，不要公开分享。

- **Clash Verge**：导入 `clash-dual.yaml` 并启用。每个出口的模式组可选 TUIC/TCP，固定同一个上游。
- **v2rayN TCP**：复制 `连接信息.txt` 的 `ss://` 链接导入并启用，本地端口沿用 v2rayN 设置。
- **v2rayN TUIC**：支持 ConfigVersion 4 的版本可以复制 `v2rayN-一键导入.txt` 全部内容，从剪贴板一次导入 TCP/TUIC。TUIC 使用内嵌证书的 `v2rayn://` 官方内部分享格式。[官方解析源码](https://github.com/2dust/v2rayN/blob/master/v2rayN/ServiceLib/Handler/Fmt/InnerFmt.cs)。旧版不支持时添加自定义配置，选择 `v2rayn-tuic.json`，核心选 sing-box 1.14.2 或兼容更新版，Socks 端口留空，再启用。[官方说明](https://github.com/2dust/v2rayN/wiki/Description-of-some-ui)。

**常见 TUIC 短链接**：`TUIC-普通链接.txt` 使用 `tuic://UUID:密码@地址:端口?...` 写法。导入短链接后，需要在 TUIC 节点证书/Cert 字段粘贴对应 `TUIC-20001-证书.pem` 的完整公开 PEM（包括首尾标记），保持证书验证开启。普通短链接无法携带 v2rayN 自动信任的 PEM 信息，单独复制并不能保证连接成功。没有该证书编辑功能的旧客户端，请用上述安全一键导入或自定义 JSON；Clash 使用完整 YAML。不要为了使用短链接关闭验证。公开证书可以交给自己的客户端，私钥始终留在 VPS。

**MiSub / 小火箭 / v2rayN 普通订阅分发**：每台 VPS 可独立运行 `sb1` → **22**，输入自己的 TUIC 子域名，自动申请公开 CA 证书并启用每日续期检查。先把域名 A 记录解析到该 VPS；Cloudflare 使用“仅 DNS”。HTTP-01 申请和续期需要放行 **80/TCP**。80 端口空闲时网站根目录留空；已有网站时填写该域名的网站根目录，程序使用 webroot 验证，不停止网站。邮箱可留空。

配置成功后，端口及 SS/TUIC 账密保留，所有现有双模式入口改用域名 SNI，新添加的入口也自动使用该证书。菜单 **16/18** 获取更新后的 `TUIC-普通链接.txt`，把普通 `tuic://` 链接加入 MiSub；客户端使用系统 CA 验证，无需单独安装自签证书。节点仍可使用 VPS IP 连接，SNI 使用配置的域名；支持 TUIC v5 的客户端必须保留 SNI/ALPN。不要在 MiSub 开启跳过证书验证。已有订阅需更新一次。

证书工具使用固定官方 lego 5.5.2，下载验证 SHA-256，保存在本项目 `/opt/socks5-relay-manager/acme`，不安装全局软件、不覆盖其他网站证书。证书先验证完整链、私钥、域名和有效期，再通过配置事务应用；申请失败保留现有节点。`socks-relay-cert.timer` 每天检查，证书实际变化时才重启对应实例并重新导出；证书/账号文件为 root 私有。更换域名重新运行菜单 22。若未配置域名，继续保留原来的自签证书模式。小火箭的原生 iOS 界面需要用户最终导入验证，CI 验证普通链接及实际 TUIC 核心链路。

多端口文件的本机 SOCKS5 是 `127.0.0.1:20001` 等，账号密码见连接信息；一次只运行一个客户端的多端口文件，避免本机争用。新增、删除、改密码后需重新导出并导入。每个模式组仅包含相同出口的两种入口，没有跨出口自动切换或 DIRECT 回退。Clash 系统代理通过“中转出口”组选择出口。

云安全组/防火墙需允许生成的公网端口，例如 **30001/TCP 和 30001/UDP**，不要开放内部 20001。程序不关闭防火墙或修改共享规则，云安全组没有授权 API 无法由安装器代改。TCP 通而 TUIC 不通，先核对 UDP 放行。

菜单 14/15 保留复用已有 TUIC 的高级功能，21 保留原生 SOCKS5 手动配置。原生 SOCKS5 不加密。

## 常用菜单

| 选项 | 用途 |
| --- | --- |
| 1 | 完整 SOCKS5 自动部署 TCP + TUIC |
| 2 / 8 | 查看中转 / 状态 |
| 3 / 4 | 删除 / 修改指定中转 |
| 5 / 6 | 全部 / 指定出口连通性 |
| 7 / 9 | 重启指定中转及入口 / 查看日志 |
| 10 / 11 | 备份 / 恢复 |
| 12 / 13 | 更新 / 卸载 |
| 16 | 一次查看全部连接信息和账密 |
| 18 | 重新导出客户端文件 |
| 19 | 旧中转启用双模式 |
| 20 | 设置公网地址 |
| 22 | 每台 VPS 独立配置域名证书及自动续期，供 MiSub 普通 TUIC 分发 |

指定中转编号是内部 20001 等端口。修改上游保留入口凭据，密码留空保留旧值。增删改仅重启对应实例，其他出口继续运行。

## 连通性与速度

出口查询经固定上游访问 `https://api.ipify.org`。完整耗时包括认证、连接、远端 DNS/TLS 和 HTTP 响应，**不是青岛到 VPS 的 ping 或下载速度**。1000 ms 不能直接解释为墨西哥线路 RTT。真实速度应在青岛客户端，固定同一上游、同一下载目标和同一时段，分别测试 TCP/TUIC；后半段上游瓶颈不会由入口协议自动解决。

检测凭据通过 stdin 输入 curl，参数不含密码，禁用环境代理及 NO_PROXY 干扰，没有直连重试。检测网站不可用也会失败，不必然代表所有目标不可用。新建/修改的出口检测失败自动回滚。

## 保存、安全和恢复

- 3proxy 仅支持认证后的 TCP CONNECT，拒绝匿名、SOCKS4、BIND、UDP ASSOCIATE。TUIC 用 UDP 传输 TCP 请求，应用 UDP 转发未启用。
- 每端口只有一个必选 `parent 1000 socks5+`，目标域名经上游解析。入口仅连接本机对应中转，没有直接出站或备用供应商。
- 配置、明文凭据、证书私钥、备份和日志位于 root 私有目录，目录 700、文件 600。下载的客户端文件也需保护。
- systemd 清空 capabilities，启用只读文件系统保护、私有临时目录、NoNewPrivileges。它不能消除核心漏洞，应保持系统更新。
- 3proxy 日志记录端口、错误码、字节数和时长，入口只记录错误，不记录明文配置。菜单对凭据额外做替换；日志每天轮转，保留 7 份。
- 不修改 SSH、防火墙、云安全组、系统 DNS/代理或已有服务；仅管理本项目三个目录、两个服务模板、logrotate 和入口命令。
- IP 换成域名不会给原生 SOCKS5 加密。加密保护传输，不能保证具体用途合法或不会被调查，应遵守所在地法规。

SS2022 使用认证加密和随机预共享密钥，保护数据机密性与完整性，但协议不提供前向保密；TUIC 的 QUIC/TLS 1.3 在正常证书验证和临时密钥交换下可以提供前向保密。二者都有安全配置要求，这个差别不意味着 TUIC 在国内不会被识别、封锁或调查，也不代表自动合法。[SS2022 规范](https://shadowsocks.org/doc/sip022.html)、[QUIC/TLS 标准](https://www.rfc-editor.org/rfc/rfc9001.html)、[现行国际联网规定](https://xzfg.moj.gov.cn/front/law/detail?LawID=1713)。

项目目录：`/opt/socks5-relay-manager`、`/etc/socks5-relay-manager`、`/var/log/socks5-relay-manager`。服务为 `socks-relay@20001.service` 和 `socks-access@20001.service`，异常退出 3 秒后重启。容量取决于 VPS 和上游。

所有写操作先备份，3proxy 配置用真实临时认证监听检查，入口配置经 sing-box 检查，再原子切换活动指针。失败回滚，崩溃事务在下次管理操作恢复；持续回滚失败保留事务并退出。

备份在 `/etc/socks5-relay-manager/backups`，包含凭据，不要上传。历史版本和备份由管理员按需清理。重复安装保留数据和密码；更新短暂重启服务，失败回退旧程序、两个核心和模板。菜单 12 输入受信任的版本标签，公开仓库无需登录。

菜单 13 或 `sudo socks-relay-uninstall`，输入 `UNINSTALL`。仅删除本项目程序及服务，默认保留配置、备份和日志，不删除系统依赖。

## 故障排查

| 现象 | 检查 |
| --- | --- |
| 旧版本机通，电脑不通 | 来源 ACL / 回环监听，菜单 19 启用双模式 |
| 公网两种模式都不通 | 公网地址、TCP/UDP 放行、云安全组、NAT 映射 |
| TCP 通，TUIC 不通 | UDP 入口、客户端证书及 UDP 路由 |
| 上游认证失败 | 完整用户名密码、代理商对 VPS 来源 IP 的白名单 |
| DNS 失败 | 上游地址在 VPS 解析，目标域名在上游解析 |
| 端口未监听 | 菜单 8/9，端口占用与 systemd 状态 |
| 连续崩溃后停止 | 修复原因，reset-failed 对应服务，再菜单 7 |

以下状态不输出密码，可以提供用于诊断：

```bash
sudo python3 /opt/socks5-relay-manager/current/scripts/manager.py status
sudo ss -lntup | grep -E '3proxy|sing-box|:2000|:3000'
```

## 官方依据

[3proxy 配置](https://3proxy.org/doc/man3/3proxy.cfg.3.html)、[TUIC TCP 协议](https://github.com/tuic-protocol/tuic/blob/master/SPEC.md)、[sing-box TUIC](https://sing-box.sagernet.org/configuration/inbound/tuic/)、[Shadowsocks](https://sing-box.sagernet.org/configuration/inbound/shadowsocks/)、[Mihomo TLS 指纹](https://wiki.metacubex.one/config/proxies/tls/)。

真实核心、固定出口、证书拒绝、无直连回退、安装回滚和独立服务测试见 [测试说明](docs/TESTING.md)。没有真实 VPS/商业账号就不宣称已完成青岛公网提速或目标 VPS 重启验证。
