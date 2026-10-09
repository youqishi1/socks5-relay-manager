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
bash -n install.sh socks-menu.sh uninstall.sh tests/test-install.sh
shellcheck install.sh socks-menu.sh uninstall.sh tests/test-install.sh
THREEPROXY_BINARY=/path/to/3proxy python3 tests/test_relay.py
# 仅可丢弃的 Ubuntu/Debian 完整系统：
sudo env RELAY_DISPOSABLE_HOST=YES bash tests/test-install.sh
```

CI 使用 Ubuntu 22.04 和 24.04 原生 GitHub runner，不使用 Docker 运行代理。Windows 本地执行同一真实核心集成套件；Windows 不提供 Linux 权限或 systemd 证据。

## 尚需真实部署验证

- Debian 12/13 的全新完整系统安装及 systemd 启动。
- 真实 VPS 重启/断电后的恢复，不能用进程重启冒充 VPS 重启。
- 商业 SOCKS5 的实际公网出口和代理商策略，公网客户端经过安全组/防火墙连接。
- ARM/其他 CPU 架构，IPv6 上游，WireGuard 实际隧道。
- 长期运行、几十个端口和生产并发容量/资源消耗。

这些限制不等于已知失败，但不能声称通过。建议首次在目标 VPS 添加一个中转，分别做本地出口检测、公网客户端连接和 VPS 重启验证，再扩大规模。
