# NetGuard 0.2.1

NetGuard 是 macOS 主机上的 fail-closed 网络锁：复用 Clash/Mihomo TUN，以 PF 防火墙兜底。代理或 TUN 失效时，保持断网而不是自动恢复家庭宽带直连。

> **代码和离线测试完成不等于保护已开启。** 图形应用启动时只读取状态；只有点击“一键启动保护”并完成 macOS 管理员授权后，才会修改 PF。

## 最简单：使用 NetGuard.app

### 日常使用

1. 在 Clash Verge 中连接可用节点，并保持 **TUN 模式开启**。
2. 打开 `/Applications/NetGuard.app`。
3. 确认窗口中的 YAML 与 Clash 当前配置一致；第一次可点“选择 YAML…”更换。
4. 点击 **“一键启动保护”**，在 macOS 系统窗口中输入管理员密码。
5. 看到“保护运行中”即可。需要浏览器证据时，再点“检查环境”，会打开 Chrome 本地诊断页。

首次启动会显示一次整机断网风险说明；之后正常启动只需主按钮和系统管理员授权。NetGuard 不收集或保存管理员密码。

### 一键启动会自动完成

- 从所选 Clash YAML 仅导入代理 `server`、`port` 和传输协议；不保存 UUID、密码或订阅全文。
- 检查 TUN 和代理端点，生成并审查 PF 规则。
- 检查当前代理出口，失败时不启用。
- 备份 `/etc/pf.conf`，加载 NetGuard 的 PF anchor。
- 安装并启动 `com.netguard.monitor` 后台监控，适配 TUN 变化；异常只保持锁网，绝不自动关闭 PF。
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

### 后台监控与开机保护的区别

启用时安装的是 `/Library/LaunchDaemons/com.netguard.monitor.plist`，停止时移除。它用于后台健康检查和 TUN 适配，**不等同于已经完成开机早期锁网验证**。

`service/com.netguard.boot.plist` 仍只是 boot-lock 模板，图形应用不会自动安装它。重启后应打开应用检查状态，不要默认重启全过程都已受到保护。

## 能做什么

- 仅允许 TUN、指定代理端点、回环及可选局域网流量；其他出站流量默认阻断。
- DNS/DoT 阻断规则先于局域网放行，IPv6 仅能通过已批准的 TUN。
- 分别检查终端出口、物理接口直连、公共 DNS、IPv6、系统时区和 Chrome 语言。
- 本地浏览器页面回传 JS 实际读取到的语言和时区，不收集 Cookie 或历史。
- 监控只保持锁网和适配 TUN 变化，绝不因代理故障自动关闭防火墙。
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
- `configure`：保存 NetGuard 自有配置，不改 PF。
- `plan`：解析端点并显示 PF 规则，不写系统文件。
- `enable --apply`：备份 `/etc/pf.conf`，安装 anchor，并要求二次确认。
- `check --preflight [--browser]`：启用前检查代理和环境，不要求直连已经阻断。
- `check [--browser]`：启用后运行完整主机及可选浏览器检查。
- `watch`：故障监控；Ctrl-C 只停止监控，不关闭防火墙。
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
