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

## 安装（当前仓库为私有）

**私有仓库不能匿名执行 `curl raw.githubusercontent.com/...`。** 先在 VPS 上以 root 安装 GitHub CLI 并登录有仓库读取权限的账号：

```bash
sudo -i
apt-get update && apt-get install -y gh ca-certificates
gh auth login
```

登录后，一条命令安装正式版本：

```bash
SOCKS_REPO_REF=v1.0.0 bash <(gh api -H 'Accept: application/vnd.github.raw+json' 'repos/youqishi1/socks5-relay-manager/contents/install.sh?ref=v1.0.0')
```

`gh` 的认证信息由 GitHub CLI 管理；本项目不把令牌写入日志或 3proxy 配置，也不把令牌放在 curl 参数中。安装脚本会通过已认证的 `gh api` 下载整个指定版本的源码。务必以同一个 root 账号执行登录和安装。无需安装过程中输入任何代理凭据。

也可以先取得源码，再离线执行管理程序安装步骤（安装依赖和核心仍需网络）：

```bash
gh repo clone youqishi1/socks5-relay-manager
cd socks5-relay-manager
git checkout v1.0.0
bash install.sh --local
```

如果所有者以后主动把仓库公开，才可以使用匿名 raw 安装命令：

```bash
SOCKS_REPO_REF=v1.0.0 bash <(curl -fsSL https://raw.githubusercontent.com/youqishi1/socks5-relay-manager/v1.0.0/install.sh)
```

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
13. 卸载程序             0. 退出
```

### 添加

1. 选择 `1`，输入上游地址、端口、用户名、密码，密码隐藏回显。
2. 选择自动生成或手动指定客户端账号密码。
3. 输入允许的客户端来源 IPv4/CIDR，可输入多个，以逗号分隔。默认仅本机；公网访问通常填你自己的公网 IP，比如 `203.0.113.8/32`（示例地址，需要替换）。
4. 监听地址默认 `0.0.0.0`，也可指定 VPS 上实际存在的 WireGuard IPv4 地址。
5. 工具先通过上游真实访问出口 IP 检测网站，再分配 20001–29999 中未使用且没有系统监听冲突的端口。
6. 确认保存。工具验证配置、启动对应服务，并**再次从本地对应中转端口**检测出口 IP。出口检测失败会回滚。
7. 输入 VPS 公网 IP/域名用于显示，复制终端中的 `IP:PORT:USERNAME:PASSWORD`。

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

- **SOCKS5 不加密**。推荐先建立 WireGuard 等加密隧道，并绑定隧道地址、限定客户端来源。
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
