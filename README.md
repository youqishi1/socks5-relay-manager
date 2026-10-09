# SOCKS5 中转管理系统

Ubuntu/Debian VPS 上的中文 SSH 管理工具。每个 VPS 监听端口对应一个独立的 3proxy 进程和一个固定上游 SOCKS5。添加、修改、删除、检测、备份和恢复均通过 `socks-menu` 操作，无需编辑配置文件。

```text
客户端 --账号密码--> VPS:20001 --上游账号密码--> SOCKS5 A --> 目标网站
客户端 --账号密码--> VPS:20002 --上游账号密码--> SOCKS5 B --> 目标网站
```

使用 3proxy 官方 LTS `0.9.9.0`，不使用 Xray、3X-UI 或 Docker。仅支持 **SOCKS5 TCP CONNECT**；主动拒绝 SOCKS4、匿名认证、BIND 和 UDP ASSOCIATE。DNS 请求通过上游 SOCKS5 转发。上游断线后该端口请求失败，不切换其他上游或 VPS 直连。

## 系统要求

- root，或 `sudo` 后的 root shell。
- Ubuntu 22.04/24.04、Debian 12/13，完整 systemd 系统。
- 安装时可以访问发行版软件源、GitHub 和官方源码站点。
- 支持 x86_64、aarch64、armv7l、i686、riscv64 源码构建路径；实际测试范围见 [测试说明](docs/TESTING.md)。
- 需要上游 SOCKS5 的 IP/域名、端口、用户名、密码。

## 简单安装与 TUIC 加速

推荐路径：**电脑 → 原有 TUIC → 同一 VPS 的本机 3proxy → 固定上游 SOCKS5 → 网站**。TUIC 可以用 QUIC 流承载 TCP 应用连接，3proxy 继续负责每端口独立出口。此功能复用已安装的 TUIC v5，不安装、不改动 TUIC/VLESS 服务。无法仅凭 VLESS 慢、TUIC 快就断言物理线路瓶颈；生产提速仍需在同一出口、目标和时段测量。

依据：[TUIC 官方 TCP 转发协议](https://github.com/tuic-protocol/tuic/blob/master/SPEC.md)、[Mihomo 链式拨号](https://wiki.metacubex.one/config/proxies/dialer-proxy/)、[sing-box detour](https://sing-box.sagernet.org/configuration/shared/dial/)。

### 第一步：在 VPS 安装

公开安装入口需要仓库为公开且 `v1.1.0` Release 已发布。以 root 登录 VPS；普通用户先执行 `sudo -i`。复制一整行：

```bash
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/youqishi1/socks5-relay-manager/v1.1.0/start.sh -o /root/socks-relay-setup.sh && bash /root/socks-relay-setup.sh
```

这行命令先完整下载入口，下载失败不执行。入口使用固定版本的 Release 安装包，校验写在脚本里的 SHA-256，校验失败不会执行安装。3proxy 官方源码另做固定 SHA-256 校验。信任来源为此 GitHub 仓库的固定版本、官方 3proxy 和发行版签名软件源；不是独立代码签名。交互终端安装后自动打开中文菜单；以后执行 `socks-menu`。

若系统没有 curl，先执行 `apt-get update && apt-get install -y curl ca-certificates`。

### 第二步：添加固定出口

1. 选择菜单 **15：添加 TUIC 加速用的本机中转**。
2. 输入上游 SOCKS5 的地址、端口、用户名、密码；客户端账号密码选择自动生成。
3. 回车确认保存。默认自动使用 `127.0.0.1` 监听和来源限制，不需要开放 20001 等 SOCKS5 公网端口。
4. 有几个上游出口就重复几次，每个端口独立绑定固定上游。

原有使用菜单 1 建立的端口可通过菜单 4 将监听地址改成 `127.0.0.1`、来源改成 `127.0.0.1`，再导出。不会自动改变旧端口的监听设置。

### 第三步：导入电脑客户端

1. 选择菜单 **14：导出 TUIC 加速客户端配置**。
2. 从 v2rayN 复制现有 TUIC v5 分享链接，在 VPS 菜单中粘贴。输入不显示字符，这是隐藏密码的正常行为。
3. 用现有 SSH/SFTP 下载提示目录中的文件，不能把文件上传 GitHub 或作为公开订阅。
4. **Clash Verge**：在配置页导入本地 `clash-verge.yaml` 并启用。文件使用 JSON 序列化，但它也是有效 YAML，支持 Mihomo。
5. **v2rayN**：在“添加自定义配置服务器”中选择 `v2rayn-sing-box.json`，核心选择 sing-box（1.12 或更新稳定版），自定义配置的“Socks 端口”留空，启用该配置。多端口入口由文件负责，按下一步手动设置应用代理。此模式下托盘系统代理不能自动对应这些入口。[v2rayN 官方自定义配置说明](https://github.com/2dust/v2rayN/wiki/Description-of-some-ui)。
6. 给浏览器或其他程序填写 SOCKS5 `127.0.0.1:20001` 等本地端口，使用导出目录中 `使用说明.txt` 的对应客户端账号密码。需要通过 SOCKS5 发送目标域名（curl 使用 `socks5h`）。

例如：电脑的 `127.0.0.1:20001` 固定到 VPS 的本机 `20001`，再到上游 A；`20002` 固定到 B。固定入口不经过自动切换组，也没有 DIRECT 回退。不要同时在两个客户端启用这份多端口配置，否则会争用本地端口。Clash Verge 的普通系统代理出口可在“中转出口”组手动选择；该组只含上游中转节点。

现有 TUIC 服务必须允许访问本机 `127.0.0.1:20001–29999` 中已启用的端口；原服务如有拒绝私网规则，应仅允许这些需要的本机端口。TUIC 服务自身的直连出站负责连接本机 3proxy；不要将 TUIC 的所有出站再设为这个 TUIC 节点，避免循环。

导出只含 TUIC 和中转客户端凭据，**不含上游供应商账号密码**。文件在 `/etc/socks5-relay-manager/exports` 的独立私有目录内，目录 700、文件 600。该目录中的文件仍是敏感信息，下载到 Windows 后也要自行保护。新建/删除/改客户端密码后需重新导出并导入，停用某个出口后原配置访问它会失败。

默认保留 TLS 证书验证并关闭 0-RTT。链接原本设置 `allow_insecure=1` 时，必须明确确认才会按原设置关闭证书验证，推荐改用受信任证书。只接受标准 TUIC v5 参数；未知参数或重复冲突参数会拒绝导出，避免悄悄改变原配置。

### 其他安装方式

仍保留私有仓库的认证安装：root 安装 `gh` 后执行 `gh auth login`，然后：

```bash
SOCKS_REPO_REF=v1.1.0 bash <(gh api -H 'Accept: application/vnd.github.raw+json' 'repos/youqishi1/socks5-relay-manager/contents/install.sh?ref=v1.1.0')
```

或取得源码后在源码目录执行 `bash install.sh --local`。安装依赖和核心仍需网络。VPS 不需要提供 GitHub 令牌给任何第三方。客户端导出功能不向外部配置转换网站发送链接。

首次安装启动管理系统，但不创建虚假的上游或开放端口。选择添加时生成 `client01` 等账号和 32 字符随机密码。重复安装会保留全部代理、密码和活动配置，并备份当前配置。更新会重启已有启用服务，因此有短暂中断；普通增删改只操作对应端口。

安装优先检查来自 Ubuntu/Debian 官方签名软件源的合适 0.9 版本包，只提取二进制、不执行包中的默认服务脚本。如果没有满足要求的版本，下载官方固定提交 `da99424eac4092e3722f1a5b1844cfe80478f580` 的源码，核验已固定 SHA-256 后构建。不会执行上游 `make install`，不会生成额外的 1080/3128 默认代理。

## 中文菜单

```bash
socks-menu
# 普通 SSH 账号：
sudo socks-menu
```

```text
1. 添加 SOCKS5 中转       2. 查看全部中转
3. 删除 SOCKS5 中转       4. 修改 SOCKS5 中转
5. 检测所有代理出口 IP    6. 检测指定代理
7. 重启代理服务          8. 查看运行状态
9. 查看日志             10. 备份配置
11. 恢复配置            12. 更新程序
13. 卸载程序            14. 导出 TUIC 加速客户端配置
15. 添加 TUIC 本机中转    0. 退出
```

### 添加

1. 选择 `1`，输入上游地址、端口、用户名、密码，密码隐藏回显。
2. 选择自动生成或手动指定客户端账号密码。
3. 输入允许的客户端来源 IPv4/CIDR，可输入多个，以逗号分隔。默认仅本机；公网访问通常填你自己的公网 IP，比如 `203.0.113.8/32`（示例地址，需要替换）。
4. 监听地址默认 `0.0.0.0`，也可指定 VPS 上实际存在的 WireGuard IPv4 地址。
5. 工具先通过上游真实访问出口 IP 检测网站，再分配 20001–29999 中未使用且没有系统监听冲突的端口。
6. 确认保存。工具验证配置、启动对应服务，并**再次从本地对应中转端口**检测出口 IP。出口检测失败会回滚。
7. 工具自动从本机网卡读取公网 IPv4；使用 NAT 且无法自动发现时才提示输入公网 IP/域名。复制终端中的 `IP:PORT:USERNAME:PASSWORD`。检测监听隧道地址时直接显示该地址，不通过直连外部网站猜测 VPS 地址。

如果上游检测失败，可以取消，或确认保存为未启用状态。以后通过 `4` 修改或 `7` 重启指定端口时重新解析上游、验证并启用。

来源填 `*` 时必须再次确认公网风险。无论来源范围如何，客户端始终需要正确账号密码。健康检测会在来源 ACL 中保留 `127.0.0.1`，也使用相同的强认证和固定父代理。IPv6 上游地址可以使用，客户端监听和来源限制目前仅支持 IPv4。

密码允许空格、`$`、引号、冒号、反斜杠和中文等 UTF-8 字符，1–128 字节；不允许控制字符/换行。客户端账号限字母、数字、`_ . @ -`，避免 ACL 和用户表语法歧义。上游账号支持可打印特殊字符，但拒绝 3proxy 保留用户名 `*`。如果密码含冒号，`IP:PORT:USERNAME:PASSWORD` 应按前 3 个冒号拆分，或在客户端分别填写 4 个字段。

### 修改、删除和恢复

按监听端口选择中转。修改时空白密码保留旧密码；自动选项保留已有客户端密码。所有写操作先备份，候选配置通过真实 3proxy 的临时认证监听验证后才切换。每次修改仅重启对应的 systemd 实例。删除保留受保护的历史版本，释放端口，不重启其他实例。

备份含敏感凭据，保存在 `/etc/socks5-relay-manager/backups`，权限 600。恢复菜单只允许选择这个目录中已有的备份，恢复失败会回滚整个受影响端口集合。不要把备份上传到 GitHub。

崩溃时保留事务日志，下次打开菜单会先恢复旧指针和对应服务。回滚重启失败时明确提示并保留事务日志；修复环境后再次打开菜单。

### 出口检测

默认查询 `https://api.ipify.org`，不直接查询 VPS 公网 IP。上游入口 IP 和出口 IP 可以不同，工具不把二者不同当作错误。每项结果包含监听端口、实际出口 IP、成功/失败和耗时。

探测先检查 SOCKS5 认证，再通过 curl 的 `socks5h` 访问检测站。凭据经 stdin 输入 curl 配置，进程参数无密码；禁用环境代理和 `NO_PROXY` 对检测路径的影响，且没有直连重试。检测站不可用、TLS 错误、DNS 错误等也会使检测失败，并不必然代表所有目标网站都不可用。此时新建/修改会回滚，避免把未验证的服务当成成功。

## 安全与网络

- **SOCKS5 不加密**。优先复用同台 VPS 已有的 TUIC 加密通道，让 3proxy 仅监听本机；也可使用 WireGuard 并绑定隧道地址、限定来源。
- 不修改 SSH、UFW、iptables、nftables 或云安全组。需要公网访问时由管理员自行仅放行需要的 TCP 端口和客户端 IP。
- 所有配置、明文凭据、备份、日志均在 root 私有目录（700），文件权限 600。root 明文存储是必要功能选择；不要把 root 共享给不可信人员。
- 代理进程以 root 读取私有配置，systemd 清空 capabilities，启用文件系统只读保护、私有临时目录和 `NoNewPrivileges`。这不能消除代理核心漏洞风险，应保持系统更新。
- 日志仅记录端口、错误码、字节数和时长，不包含账号、密码、URL 或目标正文。日志每日轮转、7 份，超过 10 MB 在下一次 logrotate 执行时轮转。
- 管理权限由 `sudo` 的 root 授权提供。授予用户 `sudo socks-menu` 等同授予本项目完整管理权限，建议仅授权可信管理员。
- 每条 ACL 只有一个必选 `parent 1000 socks5+`，后面是 `deny *`，没有任何直连 `allow`、备选父代理、认证缓存或 `auth none`。
- 本项目只管理自己的 `/opt/socks5-relay-manager`、`/etc/socks5-relay-manager`、`/var/log/socks5-relay-manager`、systemd 模板、logrotate 文件和两个入口命令。

## 更新和卸载

菜单 `12` 输入已存在且受信任的版本标签。私有仓库更新需要 root 的 `gh` 登录仍有效。更新切换程序版本前备份，检查旧端口配置并重启，启动失败回退旧程序、核心和 unit。

```bash
socks-relay-uninstall
```

或菜单 `13`，输入 `UNINSTALL`。停止并禁用本项目服务，删除程序和入口，默认保留 root 配置、备份和日志，便于重装恢复；不会删除系统依赖包。如果确认不再需要凭据，可在卸载成功后自行删除保留目录（请先核对路径）：

```bash
rm -rf -- /etc/socks5-relay-manager /var/log/socks5-relay-manager
```

## 故障排查

| 现象 | 检查方法 |
| --- | --- |
| 本地正常，公网连接失败 | 核对来源 ACL、WireGuard/监听地址、防火墙、云安全组及公网 IP |
| 上游认证失败 | 核对代理商的用户名密码和 IP 白名单，可能是代理商限制 VPS 来源 |
| DNS 失败 | 上游地址在 VPS 解析；目标域名在上游解析，分别检查两者 |
| 出口检测站失败 | 查看显示的 curl 类别，确认检测网站在该出口可访问 |
| 端口未监听 | 菜单 `8/9`；检查本机端口占用和 systemd 限速状态 |
| 反复崩溃后停止重启 | 修复原因后 `systemctl reset-failed socks-relay@20001`，再菜单 `7` |
| GitHub 返回 404 | 私有仓库需要认证，检查 root 的 `gh auth status` 和版本标签是否存在 |
| 管理操作等待 | 另一菜单/安装持有全局配置锁，关闭或完成该操作 |

仅在 root 私有终端查看：

```bash
systemctl status socks-relay@20001 --no-pager
ss -lntp 'sport = :20001'
tail -n 50 /var/log/socks5-relay-manager/service-20001.log
```

## 实现及依据

- [3proxy 官方配置手册](https://3proxy.org/doc/man3/3proxy.cfg.3.html)：`auth strong`、`-u2`、`parent` 权重、`socks5+`、`fakeresolve`、双引号及 `$` 转义。
- [固定 LTS 源码及官方构建说明](https://github.com/3proxy/3proxy/tree/0.9.9.0)：`make -f Makefile.Linux`；SHA-256 固定在安装脚本。
- 每个端口独立 systemd 服务 `socks-relay@20001.service`，异常退出 3 秒后重启，60 秒最多 5 次，文件描述符上限 65536。实际并发能力取决于 VPS CPU/内存和上游能力。
- 没有假造 `3proxy --check`。验证器在私有临时目录生成配置，实际运行 3proxy、监听随机回环端口并完成认证，然后终止并回收进程。
- 每个版本目录保存 JSON 和生成配置，活动版本通过单个 `active.json` 原子替换；事务日志支持进程崩溃后的回滚。历史版本和备份目前由管理员按需清理，避免自动删除重要凭据。

源码目录：`install.sh`、`socks-menu.sh`、`uninstall.sh`、`scripts/manager.py`、`systemd/`、`tests/`。测试使用真实 3proxy 与本地认证 SOCKS5 上游，详见 [测试说明](docs/TESTING.md)。
