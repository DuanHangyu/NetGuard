# NetGuard 安全模型与恢复

## 默认拒绝原则

PF anchor 的顺序是：回环 → 指定 TUN → 指定代理 IP/端口 → Clash 引导 DNS（proxy-server-nameserver 的字面 IP:端口）→ DNS/DoT 阻断 → 可选局域网 → 非 TUN IPv6 阻断 → 默认阻断全部出站。

监控程序没有“网络恢复后关闭 PF”的代码路径。即使监控崩溃，已加载的 PF 规则仍保留。TUN 消失时监控切换到 lock-only；如果连端点解析也失败，规则退化为仅允许回环并阻断其他出站。

监控以 root LaunchDaemon 运行并随系统启动。每个周期先检查 PF 是否启用、anchor 是否仍被引用且有规则、`/etc/pf.conf` 托管行是否还在，缺任何一项就用上次安装的规则（没有则 lock-only）重新加载并启用 PF。这同时就是开机锁网，不需要 DNS。

紧急恢复（`netguard recovery`）会先停止监控服务，再移除规则，避免监控把刚移除的规则自愈回来。监控发现 state 中已未启用时自行退出，launchd 不会重启正常退出的监控。

启用时锁定当时的出口 IP（`state.yml` 的 `locked_exit_ip`，`expected_ip` 配置优先）。出口变化只告警，不额外断网，避免检查服务本身被阻断后无法恢复。

## 代理端点与 fake-ip

Clash TUN 的 fake-ip 模式会把节点域名在系统解析里变成 198.18.x，放行这些地址没有意义；mihomo 实际连接的是节点真实 IP。因此 NetGuard：

- 绝不接受 198.18.0.0/15 作为代理端点；
- 绑定物理网卡（IP_BOUND_IF），用 YAML 中 `dns.proxy-server-nameserver`（没有时用 `nameserver`）的同一组服务器查询节点真实 IP，DoT 会校验证书；
- 放行这些引导 DNS 的固定 IP:端口，否则启用后 Clash 无法解析节点域名；这意味着任何进程都可以直接向这几个解析器发 DNS 请求，属于必要的已知放行；
- 把真实 IP 缓存在 `~/.netguard/endpoint-cache.yml`（0600），DNS 暂不可用时监控使用缓存；
- 节点为域名但 YAML 中没有字面 IPv4 的引导 DNS 时，拒绝生成规则。

监控每个周期重新解析并比较规则，节点 IP 变化或 TUN 变化时才重新加载 PF。

## 国内直连（可选，默认关闭）

开启后 anchor 增加 `table <netguard_cn> persist file "/etc/pf.anchors/com.netguard.cn"` 和一条无状态放行规则：

- 列表来自 Clash Verge 的 `geoip.dat`（与 Clash 的 `GEOIP,CN` 判定同源）。只取 IPv4，丢弃前缀短于 /8 的条目，并要求至少 1000 段，以防文件异常导致大范围放行。
- 放行规则位于 DNS 拦截之后、`block out all` 之前；IPv6 仍全部拦截（除经 TUN）。
- 仅在 TUN 存在时生成；lock-only 规则不含国内直连。
- 写入表文件失败或列表不可用时，安装前会删除这两行，保证 `pfctl -f` 一定能加载，不因缺文件而让 PF 整体失效。开机自愈时如果 geoip.dat 读不到，沿用上次写入的表文件。
- 关闭开关后，自愈不会再使用旧表。
- 风险：任何本机进程都可以直接访问中国大陆 IP，访问时暴露真实 IP。不允许任何非大陆目的地直连。`config.yml` 由用户可写，root 监控会应用其中的开关；这与代理端点配置的信任模型相同。

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
- 监控每 2 秒核对一次 PF；防火墙被外部关闭后，最长约 2 秒的未保护窗口。
- 开机保护由监控服务承担；在 launchd 拉起监控之前的极短窗口内不受保护。

## 故障处理

先运行：

```sh
sudo /Applications/NetGuard.app/Contents/Resources/netguard/bin/netguard-recovery
```

恢复只移除 NetGuard 托管的 anchor 和 `/etc/pf.conf` 中的标记行。它不会删除 Clash 配置，也不会自动重置 macOS 系统代理。

如果系统存在其他 PF 使用方，不要盲目反复执行 `pfctl -F all`；NetGuard 只清理自己的 `com.netguard` anchor。

## 检查证据的限制

- `curl --interface en0` 失败是直连受阻的一项证据，但不是形式化安全证明。
- 公共 DNS 请求被 TUN 接管时也可能成功，因此还要结合路由和 PF 规则判断。
- 浏览器页面报告 JS 语言、时区、浏览器 IPv4/IPv6 出口（访问 api.ipify.org / api6.ipify.org）和 WebRTC ICE 候选地址（向 Google、Cloudflare 公共 STUN 发起绑定请求）。结果只发给 127.0.0.1，不读取 Cookie 或历史。
- WebRTC 判定：任何不等于代理出口的公网地址，或与本机宽带 IPv6 同一 /64 的地址，都算泄露。Chrome 的 mDNS 主机名（*.local）和内网地址不算。
- 浏览器 DNS 泄露没有做成网页检测，因为那需要第三方泄露测试域名。改为在主机侧确认两点：系统 DNS 返回 Clash fake-ip（说明由 Clash 接管）；PF 拦截所有非引导 DNS。
- 第三方出口检查服务只能提供采样结果；NetGuard 不保证平台认可该出口。

## 数据边界

配置导入仅保存代理 `server`、`port` 和传输协议，不保存 UUID、密码、订阅全文。浏览器报告仅存于内存并用于本次检查，不写浏览历史或账号信息。健康状态只包含 TUN、时间、检查结果和锁网策略。
