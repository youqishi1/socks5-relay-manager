# 测试与验证范围

此文档记录真实执行结果；最终报告补充 CI 运行链接和结果。没有提供真实 VPS 或商业 SOCKS5 凭据，因此不会宣称完成商业出口或真实 VPS 重启测试。

## 集成测试原理

`tests/test_relay.py` 运行真实 3proxy。测试上游实现 SOCKS5 用户名密码认证及真实 TCP 转发，分别以 `127.0.0.2`、`127.0.0.3` 等源地址连接本地 HTTP 目标。目标返回实际连接来源 IP。因此验证的是真实经过指定上游的转发路径，不是从配置读取入口 IP，也不伪造外部公网出口。

目标域名 `exit.invalid` 只由模拟上游识别，验证远程 DNS 路径。断线测试改为本机可直连的 IP 目标，同时统计目标收到的请求，失败后目标收到零次请求才通过“无直连回退”测试。

### 测试覆盖

1. 真实转发、客户端/上游特殊字符与 UTF-8 密码、远程 DNS。
2. 添加 1/3/10 个端口，每个出口独立；修改/删除不重启其他端口；删除后的端口复用。
3. 上游账号密码错误及事务回滚。
4. 上游断线、无直连和无其他上游回退；正常端口继续可用。
5. 上游域名解析失败、目标域名解析失败。
6. 拒绝匿名、错误客户端密码、BIND 和 UDP ASSOCIATE。
7. VPS 端口占用及注入的服务启动故障回滚。
8. 无效生成配置被真实 3proxy 拒绝，原进程不变。
9. 进程重启后的配置持久化、备份和恢复。
10. 模拟崩溃事务日志恢复。
11. 不可用上游保存为停用状态，不监听。
12. 命令/配置注入输入拒绝；Linux 上检查目录 700、文件 600 和日志无密码。
13. `NO_PROXY`/环境代理不能绕过检测路径。
14. 多端口恢复失败后的全体回滚。
15. 来源 ACL 拒绝非授权客户端。
16. 错误上游用户名不能创建启用端口。
17. 中文菜单完整添加、查看、检测、退出流程及连接信息展示。
18. 错误客户端用户名的完整 CONNECT 请求被拒绝，目标收到零请求。
19. systemd 启动器只读加载配置，不修改被沙箱保护的目录。
20. 回滚遇到持续故障时保留事务，菜单退出，避免不受控的重试循环。
21. Linux 上已关闭连接的 TIME_WAIT 不妨碍端口复用；正在监听的服务仍被排除。
22. 从本机网卡检测 VPS 公网地址；没有直接访问外部 IP 检测站，NAT 地址提示手动输入。

`tests/test-install.sh` 在可丢弃 Ubuntu 主机上安装程序；`tests/test_systemd.py` 使用真正的 systemd 服务验证：

- 全新安装、重复安装、已存在配置/凭据保留。
- 开机启用、独立实例启动、真实出口检测。
- 删除单个代理后另一代理 MainPID 不变。
- 错误上游修改后的服务自动回滚。
- SIGKILL 后 systemd 自动恢复。
- 新管理进程读取已保存状态、服务重启后恢复。
- 配置/备份/日志权限，日志不包含凭据。
- 损坏新版 unit 的安装失败回退旧版本、核心和服务。
- `systemd-analyze verify` 和 `logrotate --debug`。
- 通过 GitHub 临时只读令牌认证的私有仓库一条命令安装路径。

安装测试只能在可丢弃主机执行，必须设定 `RELAY_DISPOSABLE_HOST=YES`，因为会操作真正的项目系统路径。

## 执行

```bash
bash -n start.sh install.sh socks-menu.sh uninstall.sh tests/test-install.sh
shellcheck start.sh install.sh socks-menu.sh uninstall.sh tests/test-install.sh
THREEPROXY_BINARY=/path/to/3proxy python3 tests/test_relay.py
# 仅可丢弃的 Ubuntu/Debian 完整系统：
sudo env RELAY_DISPOSABLE_HOST=YES bash tests/test-install.sh
```

CI 使用 Ubuntu 22.04 和 24.04 原生 GitHub runner，不使用 Docker 运行代理。Windows 本地执行同一真实核心集成套件；Windows 不提供 Linux 权限或 systemd 证据。

## v1.1.0 TUIC 加速验证

`tests/test_clients.py` 包含分享链接解析、控制字符/未知参数/重复冲突参数拒绝、证书验证显式确认、客户端文件不含供应商凭据、私有导出权限，以及菜单 15 不询问开放公网来源的检查。

真实链路测试使用本机隔离测试目录、测试证书、官方 sing-box TUIC 服务、Mihomo/sing-box 客户端、真实 3proxy 和两个带认证的 SOCKS5 上游。两个本地入口分别返回上游实际连接来源 `127.0.0.2`、`127.0.0.3`；关闭 TUIC 后请求失败且目标请求数量不增加。未信任的测试证书被两个客户端拒绝。测试证书仅在测试配置中信任/固定指纹，不写入操作系统证书库。

Windows 本地测试使用 Mihomo 1.19.32、sing-box 1.14.2、3proxy 0.9.9.0。CI 下载相同客户端的官方 Linux 文件并校验 GitHub Release 元数据中的固定 SHA-256。可以这样运行：

```bash
SINGBOX_BINARY=/path/to/sing-box MIHOMO_BINARY=/path/to/mihomo \
THREEPROXY_BINARY=/path/to/3proxy python3 tests/test_clients.py
```

测试需要 OpenSSL；没有真实客户端二进制时会跳过链路部分，不将跳过当成通过。v2rayN 导出的是自定义 sing-box 文件，实测对象是 sing-box 内核，没有宣称在每个版本的 v2rayN/Clash Verge 图形界面完成导入操作。

公开仓库发布后，还要用匿名方式验证 raw 入口、Release 安装包和 SHA-256 一致，并在 Ubuntu CI 上执行 `start.sh`。真实青岛到 VPS 的线路、公网吞吐、现有 TUIC 的本机访问规则仍需目标部署验证；本地成功不代表已经测到公网提速。

## v1.2.0 自动双模式验证

`tests/test_access.py` 使用真正的项目双模式服务配置：Shadowsocks 2022 TCP 和 TUIC UDP → 独立 3proxy → 两个认证 SOCKS5 上游。Mihomo 和 sing-box 两种客户端分别测试 TCP/TUIC，返回实际连接来源，删除单出口不改变另一入口 PID，故障请求不会直连目标。

还检查整条 SOCKS5 URL/IPv6/冒号密码、控制字符拒绝、一个输入自动生成凭据、中文菜单默认添加与凭据查看、私有文件、不包含供应商凭据和私钥、错误证书指纹/信任、错误传输密码、上游失败后双服务回滚。

v2rayN 的内部链接按官方 InnerFmt ConfigVersion 4 编码，保存证书信任；测试解码字段，并按官方 TUIC/TLS 核心字段生成真实 sing-box 连接。未声称自动操作过 v2rayN 图形界面。旧版客户端提供自定义 JSON 文件作为兼容导入方式。

systemd 套件新增双服务开机启用、TCP/UDP 两种监听所有权、内部核心崩溃时入口保留、入口自身崩溃后恢复，以及包含双模式数据的重复安装和安装回滚验证。公开安装 CI 从固定 Release 下载，已设置可丢弃主机守卫变量。

```bash
SINGBOX_BINARY=/path/to/sing-box MIHOMO_BINARY=/path/to/mihomo \
THREEPROXY_BINARY=/path/to/3proxy python3 tests/test_access.py
```

## 域名证书与自动网站目录

`tests/test_certificates.py` 检查完整证书链、私钥匹配、域名、有效期、系统 CA 验证、MiSub 普通 TUIC 解析/转换、凭据保留及申请失败隔离。Linux 可丢弃 CI 主机还验证真实 lego 安装、私有文件权限和 systemd 219 兼容续期定时器。

`tests/test_acme.py` 使用固定校验的官方 lego 5.5.2 / Pebble 2.10.1，在本机高端口执行真实 HTTP-01 文件验证，测试空邮箱、签发、无需续期时不变、强制续期和自动识别现有目录后签发。使用测试专用 DNS 和 CA，不关闭验证，也不添加系统根证书。

v1.3.2 的 `tests/test_webroot.py` 使用真实 curl/HTTP 请求验证选中域名的 Host、实际目录、多站点、include、引号/注释路径、错误响应和重定向拒绝、已有文件和权限保留、取消不修改配置。Linux 同时验证私有 umask 下新验证文件可读以及目录符号链接拒绝。Ubuntu CI 的 `tests/test_webroot_nginx.py` 运行独立高端口 Nginx，验证多虚拟主机、include 内 location 覆盖 root 和 HTTP 403 时安全失败；不使用其结果冒充所有面板/容器配置均可识别。

## 尚需真实部署验证

v1.2.1 增加常见 TUIC URI 配套证书的真实连接测试，含特殊字符密码、证书验证开启、公开证书无私钥。菜单测试验证一次显示多条中转的全部客户端账密及 SS/TUIC 凭据，不要求选择端口；原有安全内部链接及客户端文件继续保留。

- Debian 12/13 的全新完整系统安装及 systemd 启动。
- 真实 VPS 重启/断电后的恢复，不能用进程重启冒充 VPS 重启。
- 商业 SOCKS5 的实际公网出口和代理商策略，公网客户端经过安全组/防火墙连接。
- ARM/其他 CPU 架构，IPv6 上游，WireGuard 实际隧道。
- 长期运行、几十个端口和生产并发容量/资源消耗。

这些限制不等于已知失败，但不能声称通过。建议首次在目标 VPS 添加一个中转，分别做本地出口检测、公网客户端连接和 VPS 重启验证，再扩大规模。
