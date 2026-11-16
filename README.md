# NetGuard 0.4.0

NetGuard 是 macOS 主机上的 fail-closed 网络锁：复用 Clash/Mihomo TUN，以 PF 防火墙兜底。代理或 TUN 失效时，保持断网而不是自动恢复家庭宽带直连。

> **代码和离线测试完成不等于保护已开启。** 图形应用启动时只读取状态；只有点击“一键启动保护”并完成 macOS 管理员授权后，才会修改 PF。

## 最简单：使用 NetGuard.app

### 日常使用

1. 在 Clash Verge 中连接可用节点，并保持 **TUN 模式开启**。
2. 打开 `/Applications/NetGuard.app`。
3. 窗口默认读取 **Clash Verge 当前运行配置**（自动跟随订阅更新和配置切换），一般无需选择；只有使用其他客户端时才点“选择 YAML…”。
4. 点击 **“一键启动保护”**，在 macOS 系统窗口中输入管理员密码。
5. 看到“保护运行中”即可。需要浏览器证据时，再点“检查环境”，会打开 Chrome 本地诊断页。

首次启动会显示一次整机断网风险说明；之后正常启动只需主按钮和系统管理员授权。NetGuard 不收集或保存管理员密码。

### 一键启动会自动完成

- 从所选 Clash YAML 仅导入代理 `server`、`port` 和传输协议；不保存 UUID、密码或订阅全文。
- 检查 TUN 和代理端点，生成并审查 PF 规则。
- 检查当前代理出口，失败时不启用；成功时**锁定这个出口 IP**，之后出口一旦变化就告警。
- 备份 `/etc/pf.conf`，加载 NetGuard 的 PF anchor。
- 安装并启动 `com.netguard.monitor` 后台监控：自愈防火墙、跟随 Clash 配置、适配 TUN 和节点 IP 变化、核对出口 IP；异常只保持锁网，绝不自动关闭 PF。
- 检查终端出口、物理网卡直连、公共 DNS 和 IPv6。

浏览器语言和时区检查由“检查环境”按钮单独触发，避免每次启动都等待浏览器页面。

### 停止与紧急恢复

正常情况下点击 **“停止并恢复网络”**，完成管理员授权即可。该操作会：

- 停止并移除 NetGuard 的后台监控服务；
- 移除 NetGuard 自己的 `com.netguard` PF anchor 和托管配置；
- 保留 Clash 节点、系统代理、浏览器和其他应用设置。

无法操作窗口时，打开终端执行（不需要互联网或 DNS）：

```sh
sudo /Applications/NetGuard.app/Contents/Resources/netguard/bin/netguard recovery
```

开发目录中的恢复入口仍可使用：

```sh
sudo /Users/qing/Projects/NetGuard/bin/netguard-recovery
```

不要为了恢复而盲目执行 `pfctl -F all`，那可能影响其他防火墙使用方。

### 后台监控（含自愈与开机保护）

启用时安装 `/Library/LaunchDaemons/com.netguard.monitor.plist`（root、开机自动运行），停止时移除。每个周期（默认 20 秒）依次：

1. **自愈**：确认 PF 已启用、主规则集引用了 NetGuard anchor、anchor 内有规则、`/etc/pf.conf` 仍有托管行。任何一项被其他软件、系统更新或 `pfctl -d` 改掉，都会立即用上次的规则重新锁网，并在窗口和系统通知中提示。
2. **跟随 Clash 配置**：Clash Verge 运行配置变化（订阅更新、切换配置）时，重新导入节点和引导 DNS；配置读取失败时保留上一份。
3. **更新规则**：TUN 或节点 IP 变化时重新加载 PF。
4. **核对出口**：出口 IP 与启用时锁定的地址不同就告警（只告警，不额外断网）。想换出口时，停止后重新启动保护即可重新锁定；也可用 `configure --expected-ip` 指定。

**开机保护**：监控随系统启动运行，第一步就是自愈，用上次的规则锁网，不依赖 DNS 或网络。因此重启后无需打开应用，保护会自动恢复。启动早期在 launchd 拉起监控之前仍有极短窗口，这是用户态程序的限制。
### 国内直连（微信等国内应用）

默认情况下，开启保护后只有经代理的流量能出网。Clash 规则里判定为 `DIRECT`（直连）的连接，由 mihomo 从物理网卡直接发出，也会被拦截，所以微信、QQ、支付宝和国内网站都会打不开。

勾选窗口里的「允许国内应用直连」（或运行 `bin/netguard configure --cn-direct`）后：

- 只放行 Clash Verge 自己的 `geoip.dat` 中标记为中国大陆的 IPv4 网段（约 6000 段），也就是 Clash `GEOIP,CN,DIRECT` 规则会直连的那些地址。
- 国外地址仍只能经代理访问。代理断开时国外流量继续锁网。
- 只在检测到 Clash TUN 时生效；TUN 不在（lock-only）时国内直连也一并锁住。
- 普通 DNS（53/853）仍然拦截，国内直连规则排在 DNS 拦截之后。
- 无需管理员授权：后台监控每个周期读取配置，约 20 秒内应用或撤销。geoip.dat 更新后会自动刷新列表。
- 读不到 geoip.dat 时不放行任何国内地址（保持严格），并在状态中提示。

代价：这些国内服务会看到本地宽带的真实 IP，与不用 NetGuard 时相同。PF 只能看到 mihomo 发出的连接，无法区分是哪个应用发起的，所以这是按目的地（中国大陆 IP）放行，而不是按应用放行。按应用分流需要在 Clash 的规则里做（如 `PROCESS-NAME`），NetGuard 不会修改 Clash。另外，Clash 规则中走 DIRECT 的邮件端口（25/465/587/993 等）和解析到非大陆 IP 的 `GEOSITE,cn` 域名仍然会被拦截。

## 能做什么

- 仅允许 TUN、指定代理端点、回环及可选局域网流量；其他出站流量默认阻断。
- DNS/DoT 阻断规则先于局域网放行，IPv6 仅能通过已批准的 TUN。
- 分别检查终端出口、物理接口直连、公共 DNS、IPv6、系统时区和 Chrome 语言。
- 本地浏览器页面回传 JS 实际读取到的语言和时区，不收集 Cookie 或历史。
- 监控自愈防火墙、开机即锁网、锁定并核对出口 IP、跟随 Clash 配置变化，绝不因代理故障自动关闭防火墙。
- 提供不依赖 DNS 或外网的本地恢复入口。

## 重要边界

- 这是网络保护，不是账号“免封”工具，不能改变代理 IP 信誉或平台规则。
- 主机版不提供 Cage 那样的独立文件系统、独立系统账户、独立系统时区或完整应用隔离。
- PF 配置错误可能导致整台 Mac 断网。启用前保存工作，并确认知道恢复入口。
- 代理端点可以是 IP 或域名。域名经 Clash 的 `proxy-server-nameserver`（绑定物理网卡）解析为真实 IP，绝不使用 fake-ip；这些引导 DNS 的 IP:端口会被放行。YAML 中缺少字面 IPv4 引导 DNS 时拒绝启用。节点 IP 变化由 root 监控刷新，失败时使用缓存并保持锁网。
- 启用 TUN 属于 Clash Verge 的操作，NetGuard 不会静默替你打开 TUN。
- 系统代理或 `HTTP_PROXY` 环境变量本身不足以防止所有应用直连。

## 构建和安装应用

在本机使用 Apple Swift、AppKit、Ruby 和 macOS 自带工具构建，无第三方 Ruby 依赖：

```sh
cd /Users/qing/Projects/NetGuard
app/build_app.sh
ditto dist/NetGuard.app /Applications/NetGuard.app
open -a NetGuard
```

应用采用本机 ad-hoc 签名，用于当前这台 Mac；不代表 Apple 公证或对外分发签名。

应用资源内包含一份独立后端，位置为：

```text
/Applications/NetGuard.app/Contents/Resources/netguard/
```

## 命令行使用（高级用户）

```sh
cd /Users/qing/Projects/NetGuard

# 只读诊断
bin/netguard doctor

# 仅导入端点，不修改 PF
bin/netguard configure --from /path/to/config.yaml \
  --tun auto --timezone America/Chicago --language en-US

# 检查规则与启用前代理环境
bin/netguard plan
bin/netguard check --preflight --browser

# 明确决定后才实际启用，需要二次输入 ENABLE NETGUARD
sudo bin/netguard enable --apply

# 启用后完整检查和监控
bin/netguard check --browser
sudo bin/netguard watch

# 查看状态或恢复
bin/netguard status
sudo bin/netguard-recovery
```

### 命令

- `doctor`：只读环境诊断。
- `configure`：保存 NetGuard 自有配置，不改 PF；`--cn-direct` / `--no-cn-direct` 开关国内直连。
- `plan`：解析端点并显示 PF 规则，不写系统文件。
- `enable --apply`：备份 `/etc/pf.conf`，安装 anchor，并要求二次确认。
- `check --preflight [--browser]`：启用前检查代理和环境，不要求直连已经阻断。
- `check [--browser]`：启用后运行完整主机及可选浏览器检查。
- `watch`：故障监控与自愈（通常由后台服务运行）；Ctrl-C 只停止监控，不关闭防火墙。
- `status`：查看锁网与健康状态。
- `recovery`：移除 NetGuard anchor 和托管配置，不重置 Clash 节点或浏览器。

## 文件

- `app/NetGuardApp.swift`：原生 AppKit 图形界面。
- `app/Privileged.applescript`：只接受 `enable`/`disable`，调用 macOS 管理员授权。
- `app/netguard-gui-helper`：固定后端路径的授权辅助程序，管理 PF 启用流程和监控服务。
- `app/build_app.sh`：构建、图标生成、语法检查和 ad-hoc 签名。
- `bin/`、`lib/`：命令行与 fail-closed 核心。
- `web/diagnostics.html`：只连接 127.0.0.1 的浏览器检查页。
- `test/`：不修改网络的离线测试。

## 测试

```sh
ruby test/test_netguard.rb
for f in lib/netguard.rb lib/netguard/*.rb bin/netguard; do ruby -c "$f"; done
swiftc -typecheck -target arm64-apple-macosx12.0 app/NetGuardApp.swift
zsh -n app/netguard-gui-helper
```

详细安全说明见 [`docs/SECURITY.md`](docs/SECURITY.md)。
