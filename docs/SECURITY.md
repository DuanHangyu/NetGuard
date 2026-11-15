# NetGuard 安全模型与恢复

## 默认拒绝原则

PF anchor 的顺序是：回环 → 指定 TUN → 指定代理 IP/端口 → Clash 引导 DNS（proxy-server-nameserver 的字面 IP:端口）→ DNS/DoT 阻断 → 可选局域网 → 非 TUN IPv6 阻断 → 默认阻断全部出站。

监控程序没有“网络恢复后关闭 PF”的代码路径。即使监控崩溃，已加载的 PF 规则仍保留。TUN 消失时监控切换到 lock-only；如果连端点解析也失败，规则退化为仅允许回环并阻断其他出站。

`service/com.netguard.boot.plist` 是开机服务模板，不会随项目测试自动安装。只有启用状态已保存时，`boot-lock` 才会加载规则。

## 代理端点与 fake-ip

Clash TUN 的 fake-ip 模式会把节点域名在系统解析里变成 198.18.x，放行这些地址没有意义；mihomo 实际连接的是节点真实 IP。因此 NetGuard：

- 绝不接受 198.18.0.0/15 作为代理端点；
- 绑定物理网卡（IP_BOUND_IF），用 YAML 中 `dns.proxy-server-nameserver`（没有时用 `nameserver`）的同一组服务器查询节点真实 IP，DoT 会校验证书；
- 放行这些引导 DNS 的固定 IP:端口，否则启用后 Clash 无法解析节点域名；这意味着任何进程都可以直接向这几个解析器发 DNS 请求，属于必要的已知放行；
- 把真实 IP 缓存在 `~/.netguard/endpoint-cache.yml`（0600），DNS 暂不可用时监控使用缓存；
- 节点为域名但 YAML 中没有字面 IPv4 的引导 DNS 时，拒绝生成规则。

监控每个周期重新解析并比较规则，节点 IP 变化或 TUN 变化时才重新加载 PF。

## 启用前必须确认

1. 已阅读 `bin/netguard plan` 的输出，TUN 名称与代理端点正确。
2. 已在本机终端定位 `bin/netguard-recovery`，恢复不依赖互联网。
3. 知道 sudo 密码，能够在本机执行恢复。
4. 接受整台 Mac 的非代理公网流量都会被阻断，不只是 Claude。
5. 已保存工作，理解 Wi-Fi、VPN、其他防火墙或企业安全软件可能与 PF/TUN 相互影响。
6. 当前没有重要上传、下载、远程会议或远程桌面任务。

## 图形应用与管理员授权

- 应用启动和定时刷新只运行只读 `status`，不会自动启用或关闭 PF。
- 只有用户点击“一键启动保护”后，应用才执行配置导入、`plan` 和代理预检；随后必须通过 macOS 系统管理员授权，应用自身不收集或保存密码。
- `Privileged.applescript` 只接受固定的 `enable` 和 `disable` 动作。辅助程序要求 root、固定的应用内 Ruby CLI，以及用户目录下的 `.netguard` 配置目录，不接收任意 shell 命令。
- 图形界面的启动按钮与 macOS 管理员授权构成用户确认；辅助程序仍通过标准输入满足 CLI 原有的 `ENABLE NETGUARD` 二次检查，没有删除该核心校验。
- 启用成功后才安装 `com.netguard.monitor`。监控服务安装或启动失败时只报告错误，**不会为了恢复可用性而自动关闭 PF**。
- 停止或紧急恢复会先移除监控服务，再只清理 NetGuard 自己的 PF anchor 和托管配置，不修改 Clash 节点、系统代理或浏览器。
- 图形应用不自动安装 `com.netguard.boot.plist`，因此不能声称已经验证开机早期锁网。

## 故障处理

先运行：

```sh
sudo /Users/qing/Projects/NetGuard/bin/netguard-recovery
```

恢复只移除 NetGuard 托管的 anchor 和 `/etc/pf.conf` 中的标记行。它不会删除 Clash 配置，也不会自动重置 macOS 系统代理。

如果系统存在其他 PF 使用方，不要盲目反复执行 `pfctl -F all`；NetGuard 只清理自己的 `com.netguard` anchor。

## 检查证据的限制

- `curl --interface en0` 失败是直连受阻的一项证据，但不是形式化安全证明。
- 公共 DNS 请求被 TUN 接管时也可能成功，因此还要结合路由和 PF 规则判断。
- 浏览器页面只报告 JS 语言和时区，不尝试收集 WebRTC IP，也不读取浏览器 Cookie。
- 第三方出口检查服务只能提供采样结果；NetGuard 不保证平台认可该出口。

## 数据边界

配置导入仅保存代理 `server`、`port` 和传输协议，不保存 UUID、密码、订阅全文。浏览器报告仅存于内存并用于本次检查，不写浏览历史或账号信息。健康状态只包含 TUN、时间、检查结果和锁网策略。
