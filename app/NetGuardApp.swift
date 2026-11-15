import AppKit
import Foundation
import UniformTypeIdentifiers

struct CommandResult {
    let status: Int32
    let output: String
    var succeeded: Bool { status == 0 }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    private let workQueue = DispatchQueue(label: "com.netguard.app.work")
    private let resourceRoot = Bundle.main.resourceURL!
    private let configHome = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".netguard")
    private let anchorPath = "/etc/pf.anchors/com.netguard"
    private let monitorPlistPath = "/Library/LaunchDaemons/com.netguard.monitor.plist"
    private let defaults = UserDefaults.standard

    private var window: NSWindow!
    private var statusDot: NSTextField!
    private var statusLabel: NSTextField!
    private var statusDetail: NSTextField!
    private var configLabel: NSTextField!
    private var startButton: NSButton!
    private var checkButton: NSButton!
    private var stopButton: NSButton!
    private var clashButton: NSButton!
    private var chooseButton: NSButton!
    private var logView: NSTextView!
    private var busy = false
    private var refreshing = false
    private var isProtected = false
    private var monitorRunning = false
    private var sourceYAML: String?

    private var cliPath: String {
        resourceRoot.appendingPathComponent("netguard/bin/netguard").path
    }

    private var helperPath: String {
        resourceRoot.appendingPathComponent("netguard-gui-helper").path
    }

    private var privilegeScriptPath: String {
        resourceRoot.appendingPathComponent("Privileged.applescript").path
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        buildMainMenu()
        buildWindow()
        if defaults.string(forKey: "sourceYAML") == nil {
            let known = "/Users/qing/Downloads/RESIP纯净住宅IP.yaml"
            if FileManager.default.fileExists(atPath: known) {
                defaults.set(known, forKey: "sourceYAML")
            }
        }
        sourceYAML = defaults.string(forKey: "sourceYAML")
        updateConfigLabel()
        appendLog("NetGuard 图形界面已就绪。启动保护前不会修改防火墙。")
        refreshStatus()
        Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in
            self?.refreshStatus()
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    private func makeLabel(_ text: String, _ frame: NSRect, size: CGFloat = 13,
                           weight: NSFont.Weight = .regular, color: NSColor = .labelColor) -> NSTextField {
        let label = NSTextField(labelWithString: text)
        label.frame = frame
        label.font = .systemFont(ofSize: size, weight: weight)
        label.textColor = color
        label.lineBreakMode = .byTruncatingTail
        return label
    }

    private func makeButton(_ title: String, _ frame: NSRect, action: Selector) -> NSButton {
        let button = NSButton(title: title, target: self, action: action)
        button.frame = frame
        button.bezelStyle = .rounded
        button.controlSize = .large
        button.font = .systemFont(ofSize: 13, weight: .medium)
        return button
    }

    private func buildWindow() {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 680, height: 720),
                          styleMask: [.titled, .closable, .miniaturizable],
                          backing: .buffered, defer: false)
        window.title = "NetGuard"
        window.center()
        window.isReleasedWhenClosed = false

        guard let content = window.contentView else { return }
        let shield = makeLabel("🛡", NSRect(x: 28, y: 650, width: 50, height: 46), size: 38)
        content.addSubview(shield)
        content.addSubview(makeLabel("NetGuard", NSRect(x: 86, y: 664, width: 500, height: 30),
                                     size: 26, weight: .bold))
        content.addSubview(makeLabel("代理失效时保持断网，不自动恢复家庭宽带直连 · macOS 主机版",
                                     NSRect(x: 86, y: 638, width: 566, height: 24),
                                     size: 12, color: .secondaryLabelColor))

        let statusBox = NSView(frame: NSRect(x: 28, y: 520, width: 624, height: 102))
        statusBox.wantsLayer = true
        statusBox.layer?.backgroundColor = NSColor.quaternaryLabelColor.cgColor
        statusBox.layer?.cornerRadius = 12
        content.addSubview(statusBox)

        statusDot = makeLabel("●", NSRect(x: 18, y: 56, width: 28, height: 30), size: 23,
                              color: .systemOrange)
        statusBox.addSubview(statusDot)
        statusLabel = makeLabel("正在读取状态…", NSRect(x: 50, y: 58, width: 548, height: 28),
                                size: 18, weight: .semibold)
        statusBox.addSubview(statusLabel)
        statusDetail = makeLabel("", NSRect(x: 50, y: 12, width: 548, height: 42),
                                 size: 12, color: .secondaryLabelColor)
        statusDetail.lineBreakMode = .byWordWrapping
        statusDetail.cell?.wraps = true
        statusDetail.cell?.isScrollable = false
        statusBox.addSubview(statusDetail)

        content.addSubview(makeLabel("代理配置", NSRect(x: 28, y: 486, width: 96, height: 20),
                                     size: 12, weight: .medium))
        configLabel = makeLabel("尚未选择", NSRect(x: 126, y: 486, width: 388, height: 20),
                                size: 12, color: .secondaryLabelColor)
        content.addSubview(configLabel)
        chooseButton = makeButton("选择 YAML…", NSRect(x: 520, y: 480, width: 132, height: 30),
                                  action: #selector(chooseYAML))
        chooseButton.controlSize = .regular
        content.addSubview(chooseButton)

        content.addSubview(makeLabel("使用前提：Clash Verge 已连接节点并开启 TUN；配置需与 Clash 当前使用的一致。",
                                     NSRect(x: 28, y: 450, width: 624, height: 24),
                                     size: 12, color: .secondaryLabelColor))

        startButton = makeButton("一键启动保护", NSRect(x: 28, y: 382, width: 624, height: 48),
                                 action: #selector(startProtection))
        startButton.font = .systemFont(ofSize: 17, weight: .semibold)
        startButton.bezelColor = .systemBlue
        startButton.keyEquivalent = "\r"
        startButton.setAccessibilityIdentifier("StartProtection")
        content.addSubview(startButton)

        checkButton = makeButton("检查环境", NSRect(x: 28, y: 330, width: 196, height: 36),
                                 action: #selector(runEnvironmentCheck))
        clashButton = makeButton("打开 Clash Verge", NSRect(x: 242, y: 330, width: 196, height: 36),
                                 action: #selector(openClash))
        stopButton = makeButton("停止并恢复网络", NSRect(x: 456, y: 330, width: 196, height: 36),
                                action: #selector(stopProtection))
        stopButton.bezelColor = .systemRed
        stopButton.setAccessibilityIdentifier("StopProtection")
        content.addSubview(checkButton)
        content.addSubview(clashButton)
        content.addSubview(stopButton)

        content.addSubview(makeLabel("运行记录", NSRect(x: 28, y: 296, width: 300, height: 20),
                                     size: 12, weight: .medium))
        let clearButton = makeButton("清空", NSRect(x: 580, y: 290, width: 72, height: 26),
                                     action: #selector(clearLog))
        clearButton.controlSize = .small
        clearButton.font = .systemFont(ofSize: 11)
        content.addSubview(clearButton)

        let scroll = NSScrollView(frame: NSRect(x: 28, y: 44, width: 624, height: 238))
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        logView = NSTextView(frame: scroll.bounds)
        logView.isEditable = false
        logView.isSelectable = true
        logView.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        logView.textContainerInset = NSSize(width: 8, height: 8)
        logView.autoresizingMask = [.width, .height]
        scroll.documentView = logView
        content.addSubview(scroll)

        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    private func buildMainMenu() {
        let main = NSMenu()
        let appItem = NSMenuItem()
        let appMenu = NSMenu(title: "NetGuard")
        let about = NSMenuItem(title: "关于 NetGuard", action: #selector(showAbout), keyEquivalent: "")
        about.target = self
        appMenu.addItem(about)
        appMenu.addItem(.separator())
        let recovery = NSMenuItem(title: "紧急恢复网络…", action: #selector(emergencyRecovery), keyEquivalent: "r")
        recovery.keyEquivalentModifierMask = [.command, .shift]
        recovery.target = self
        appMenu.addItem(recovery)
        appMenu.addItem(.separator())
        appMenu.addItem(NSMenuItem(title: "退出 NetGuard", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))
        appItem.submenu = appMenu
        main.addItem(appItem)

        let editItem = NSMenuItem()
        let editMenu = NSMenu(title: "编辑")
        editMenu.addItem(NSMenuItem(title: "拷贝", action: #selector(NSText.copy(_:)), keyEquivalent: "c"))
        editMenu.addItem(NSMenuItem(title: "全选", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a"))
        editItem.submenu = editMenu
        main.addItem(editItem)
        NSApp.mainMenu = main
    }

    private func updateConfigLabel() {
        guard let path = sourceYAML, !path.isEmpty else {
            configLabel.stringValue = "尚未选择（首次启动时选择 Clash YAML）"
            configLabel.toolTip = nil
            return
        }
        configLabel.stringValue = URL(fileURLWithPath: path).lastPathComponent
        configLabel.toolTip = path
    }

    @objc private func chooseYAML() {
        guard !busy else { return }
        let panel = NSOpenPanel()
        panel.title = "选择与 Clash 当前配置一致的 YAML"
        panel.message = "NetGuard 只读取 server、port 和传输协议，不保存 UUID、密码或订阅全文。"
        panel.allowedContentTypes = [UTType(filenameExtension: "yaml"), UTType(filenameExtension: "yml")].compactMap { $0 }
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        if let sourceYAML {
            panel.directoryURL = URL(fileURLWithPath: sourceYAML).deletingLastPathComponent()
        }
        guard panel.runModal() == .OK, let url = panel.url else { return }
        sourceYAML = url.path
        defaults.set(url.path, forKey: "sourceYAML")
        updateConfigLabel()
        appendLog("已选择配置：\(url.path)。尚未写入或启用任何保护。")
    }

    private func ensureSource() -> Bool {
        if let sourceYAML, FileManager.default.fileExists(atPath: sourceYAML) {
            return true
        }
        chooseYAML()
        if let sourceYAML, FileManager.default.fileExists(atPath: sourceYAML) {
            return true
        }
        showAlert("需要代理配置", "请选择与 Clash Verge 当前使用配置一致的 YAML 文件。")
        return false
    }

    @objc private func startProtection() {
        guard !busy, ensureSource() else { return }
        if !defaults.bool(forKey: "didAcceptRisk") {
            let alert = NSAlert()
            alert.messageText = "首次启动确认"
            alert.informativeText = "NetGuard 会用 PF 接管整台 Mac 的出站网络，不只影响 Claude。配置错误可能导致全机断网。\n\n请确认 Clash 已开启 TUN，所选 YAML 与 Clash 当前配置一致，并记住窗口中的“停止并恢复网络”按钮。下一步 macOS 会要求管理员授权。"
            alert.alertStyle = .warning
            alert.addButton(withTitle: "了解风险，启动保护")
            alert.addButton(withTitle: "取消")
            guard alert.runModal() == .alertFirstButtonReturn else { return }
            defaults.set(true, forKey: "didAcceptRisk")
        }

        let yaml = sourceYAML!
        setBusy(true, title: "正在检查并启动保护…")
        appendLog("\n===== 启动保护 =====")
        workQueue.async { [weak self] in
            guard let self else { return }
            self.appendLog("1/5 仅导入代理端点（不保存凭据）…")
            let configured = self.backend(["configure", "--from", yaml, "--tun", "auto",
                                           "--timezone", "America/Chicago", "--language", "en-US"])
            self.appendLog(configured.output)
            guard configured.succeeded else {
                self.finishStartWithError("配置导入失败", configured.output)
                return
            }

            self.appendLog("2/5 检查 TUN、代理端点和 PF 规则…")
            let plan = self.backend(["plan"])
            self.appendLog(plan.output)
            guard plan.succeeded else {
                if plan.output.contains("TUN") {
                    DispatchQueue.main.async {
                        self.setBusy(false)
                        self.refreshStatus()
                        let alert = NSAlert()
                        alert.messageText = "尚未检测到 Clash TUN"
                        alert.informativeText = "请先在 Clash Verge 中连接节点并打开 TUN 模式，然后回到 NetGuard 再点一次“一键启动保护”。防火墙尚未被修改。"
                        alert.addButton(withTitle: "打开 Clash Verge")
                        alert.addButton(withTitle: "知道了")
                        if alert.runModal() == .alertFirstButtonReturn { self.openClash() }
                    }
                } else {
                    self.finishStartWithError("规则预检失败", plan.output)
                }
                return
            }

            self.appendLog("3/5 检查当前代理出口…")
            let preflight = self.backend(["check", "--preflight"])
            self.appendLog(preflight.output)
            guard preflight.succeeded else {
                self.finishStartWithError("代理预检未通过", "防火墙尚未修改。请确认节点可用、TUN 已开启，并查看下面的检查输出。\n\n\(self.tail(preflight.output))")
                return
            }

            self.appendLog("4/5 请求 macOS 管理员授权并启用保护…")
            let enabled = self.privileged("enable")
            self.appendLog(enabled.output)
            let protectedNow = self.protectionPresent()

            self.appendLog("5/5 启用后检查终端、DNS 和 IPv6…")
            let checked = protectedNow ? self.backend(["check"]) : CommandResult(status: -1, output: "保护未启用，跳过完整检查。")
            self.appendLog(checked.output)

            DispatchQueue.main.async {
                self.setBusy(false)
                self.refreshStatus()
                if !enabled.succeeded {
                    if protectedNow {
                        self.showAlert("保护已写入，但启动流程未完全完成",
                                       "NetGuard 不会自动撤销防火墙来恢复直连。请查看运行记录，必要时使用“停止并恢复网络”。\n\n\(self.tail(enabled.output))")
                    } else if enabled.output.localizedCaseInsensitiveContains("cancel") {
                        self.showAlert("已取消授权", "没有启动新的保护，原网络状态保持不变。")
                    } else {
                        self.showAlert("启动未完成", "请查看运行记录。NetGuard 没有因失败而自动放开直连。\n\n\(self.tail(enabled.output))")
                    }
                } else if !checked.succeeded {
                    self.showAlert("保护已开启，但检查有异常",
                                   "系统会继续保持锁网，不会自动恢复家庭宽带直连。请查看运行记录；需要退出保护时点击“停止并恢复网络”。\n\n\(self.tail(checked.output))")
                } else {
                    self.appendLog("保护已启动，后台监控已运行。点击“检查环境”可额外检查 Chrome 浏览器。")
                }
            }
        }
    }

    private func finishStartWithError(_ title: String, _ output: String) {
        DispatchQueue.main.async {
            self.setBusy(false)
            self.refreshStatus()
            self.showAlert(title, self.tail(output))
        }
    }

    @objc private func stopProtection() {
        performStop(force: false)
    }

    @objc private func emergencyRecovery() {
        performStop(force: true)
    }

    private func performStop(force: Bool) {
        guard !busy else { return }
        if !force && !isProtected && !protectionPresent() {
            showAlert("当前未启用 NetGuard", "无需恢复。若你认为状态异常，可使用菜单 NetGuard → 紧急恢复网络。")
            return
        }
        let alert = NSAlert()
        alert.messageText = force ? "紧急恢复网络？" : "停止 NetGuard 保护？"
        alert.informativeText = "这会停止 NetGuard 后台监控并移除它自己的 PF 规则，恢复普通联网。不会关闭 Clash、修改节点或重置系统代理。"
        alert.alertStyle = .warning
        alert.addButton(withTitle: "停止并恢复")
        alert.addButton(withTitle: "取消")
        guard alert.runModal() == .alertFirstButtonReturn else { return }

        setBusy(true, title: "正在停止保护并恢复网络…")
        appendLog("\n===== 停止并恢复 =====")
        workQueue.async {
            let result = self.privileged("disable")
            self.appendLog(result.output)
            DispatchQueue.main.async {
                self.setBusy(false)
                self.refreshStatus()
                if result.succeeded {
                    self.appendLog("NetGuard 的防火墙规则和后台监控已移除。")
                } else {
                    self.showAlert("恢复命令未完成", "请查看运行记录，或打开终端执行：\nsudo /Applications/NetGuard.app/Contents/Resources/netguard/bin/netguard recovery\n\n\(self.tail(result.output))")
                }
            }
        }
    }

    @objc private func runEnvironmentCheck() {
        guard !busy else { return }
        let protectedNow = isProtected || protectionPresent()
        setBusy(true, title: "正在检查网络与浏览器环境…")
        appendLog("\n===== 环境检查（会打开 Chrome 本地诊断页） =====")
        workQueue.async {
            let args = protectedNow ? ["check", "--browser"] : ["check", "--preflight", "--browser"]
            let result = self.backend(args)
            self.appendLog(result.output)
            DispatchQueue.main.async {
                self.setBusy(false)
                self.refreshStatus()
                if !result.succeeded {
                    self.showAlert("检查发现异常", "如果保护已经开启，NetGuard 会继续保持锁网。请查看运行记录中的具体项目。\n\n\(self.tail(result.output))")
                }
            }
        }
    }

    @objc private func openClash() {
        let candidates = ["/Applications/Clash Verge.app", "/Applications/Clash Verge Rev.app"]
        if let path = candidates.first(where: { FileManager.default.fileExists(atPath: $0) }) {
            NSWorkspace.shared.openApplication(at: URL(fileURLWithPath: path), configuration: .init()) { _, error in
                if let error { self.appendLog("打开 Clash Verge 失败：\(error.localizedDescription)") }
            }
        } else {
            showAlert("没有找到 Clash Verge", "请手动打开你的 Clash/Mihomo 客户端，连接节点并开启 TUN。")
        }
    }

    private func refreshStatus() {
        guard !busy, !refreshing else { return }
        refreshing = true
        workQueue.async {
            let result = self.backend(["status"])
            let anchor = FileManager.default.fileExists(atPath: self.anchorPath)
            let monitor = self.process("/bin/launchctl", ["print", "system/com.netguard.monitor"]).succeeded
            DispatchQueue.main.async {
                self.refreshing = false
                self.updateStatus(result.output, anchor: anchor, monitor: monitor)
            }
        }
    }

    private func updateStatus(_ output: String, anchor: Bool, monitor: Bool) {
        isProtected = output.contains("NetGuard 配置：已启用") || anchor
        monitorRunning = monitor
        let tun = value(after: "TUN：", in: output) ?? "未知"
        let recent = value(after: "最近结果：", in: output) ?? "暂无"
        let healthy = output.contains("健康状态：正常")

        if isProtected {
            if healthy {
                statusDot.textColor = .systemGreen
                statusLabel.stringValue = "保护运行中"
            } else {
                statusDot.textColor = .systemOrange
                statusLabel.stringValue = "保护已开启 · 正在确认代理状态"
            }
            statusDetail.stringValue = "TUN：\(tun)  ·  后台监控：\(monitor ? "运行中" : "未运行或不可读")\n\(recent)"
            startButton.title = monitor ? "保护已开启" : "修复保护并重启监控"
            startButton.isEnabled = !monitor
        } else {
            statusDot.textColor = .systemOrange
            statusLabel.stringValue = "保护未开启"
            statusDetail.stringValue = "当前没有由 NetGuard 启用的保护。\n启动前请确保 Clash 节点可用并已开启 TUN。"
            startButton.title = "一键启动保护"
            startButton.isEnabled = true
        }
        stopButton.isEnabled = isProtected
    }

    private func value(after prefix: String, in text: String) -> String? {
        for line in text.components(separatedBy: .newlines) where line.hasPrefix(prefix) {
            return String(line.dropFirst(prefix.count)).trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return nil
    }

    private func setBusy(_ value: Bool, title: String? = nil) {
        busy = value
        chooseButton.isEnabled = !value
        checkButton.isEnabled = !value
        stopButton.isEnabled = !value && isProtected
        startButton.isEnabled = !value && (!isProtected || !monitorRunning)
        if value {
            statusDot.textColor = .systemBlue
            statusLabel.stringValue = title ?? "正在处理…"
        } else {
            startButton.title = isProtected ? (monitorRunning ? "保护已开启" : "修复保护并重启监控") : "一键启动保护"
        }
    }

    private func protectionPresent() -> Bool {
        if FileManager.default.fileExists(atPath: anchorPath) { return true }
        return backend(["status"]).output.contains("NetGuard 配置：已启用")
    }

    private func backend(_ arguments: [String]) -> CommandResult {
        var environment = ProcessInfo.processInfo.environment
        environment["NETGUARD_HOME"] = configHome.path
        environment["LC_ALL"] = "en_US.UTF-8"
        environment["LANG"] = "en_US.UTF-8"
        return process("/usr/bin/ruby", [cliPath] + arguments, environment: environment)
    }

    private func privileged(_ action: String) -> CommandResult {
        var environment = ProcessInfo.processInfo.environment
        environment["LC_ALL"] = "en_US.UTF-8"
        return process("/usr/bin/osascript", [privilegeScriptPath, action, helperPath, configHome.path],
                       environment: environment)
    }

    private func process(_ executable: String, _ arguments: [String],
                         environment: [String: String]? = nil) -> CommandResult {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: executable)
        task.arguments = arguments
        if let environment { task.environment = environment }
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = pipe
        do {
            try task.run()
        } catch {
            return CommandResult(status: -1, output: error.localizedDescription)
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        let output = String(data: data, encoding: .utf8) ?? String(decoding: data, as: UTF8.self)
        return CommandResult(status: task.terminationStatus, output: output.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    private func appendLog(_ message: String) {
        DispatchQueue.main.async {
            let formatter = DateFormatter()
            formatter.dateFormat = "HH:mm:ss"
            let line = "[\(formatter.string(from: Date()))] \(message)\n"
            self.logView.textStorage?.append(NSAttributedString(string: line, attributes: [
                .font: NSFont.monospacedSystemFont(ofSize: 11, weight: .regular),
                .foregroundColor: NSColor.labelColor
            ]))
            self.logView.scrollToEndOfDocument(nil)
        }
    }

    @objc private func clearLog() {
        logView.string = ""
    }

    private func tail(_ text: String) -> String {
        text.count > 1800 ? "…" + String(text.suffix(1800)) : text
    }

    private func showAlert(_ title: String, _ message: String) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.alertStyle = .warning
        alert.addButton(withTitle: "知道了")
        alert.runModal()
    }

    @objc private func showAbout() {
        let alert = NSAlert()
        alert.messageText = "NetGuard 0.2.0"
        alert.informativeText = "macOS 主机 fail-closed 网络锁。\n\n复用 Clash/Mihomo TUN，以 PF 兜底。它降低代理故障导致的意外直连风险，但不能保证账号不被封禁，也不提供 Cage 的独立文件系统或应用隔离。"
        alert.addButton(withTitle: "知道了")
        alert.runModal()
    }
}

let application = NSApplication.shared
let delegate = AppDelegate()
application.delegate = delegate
application.setActivationPolicy(.regular)
application.run()
