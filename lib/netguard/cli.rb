# frozen_string_literal: true
require 'optparse'
require 'json'

module NetGuard
  class CLI
    def self.start(argv)
      new.start(argv)
    end

    def start(argv)
      command = argv.shift || 'help'
      case command
      when 'doctor' then doctor
      when 'configure' then configure(argv)
      when 'plan' then plan
      when 'enable' then enable(argv)
      when 'disable', 'recovery' then recovery
      when 'check' then check(argv)
      when 'watch' then watch
      when 'boot-lock' then firewall.boot_lock!
      when 'status' then status
      when 'version', '--version' then puts VERSION
      when 'help', '--help', '-h' then help
      else raise ArgumentError, "未知命令：#{command}"
      end
      0
    rescue SecurityError, ArgumentError, RuntimeError => e
      warn "错误：#{e.message}"
      1
    end

    private

    def config
      @config ||= Config.new
    end

    def firewall
      @firewall ||= Firewall.new(config)
    end

    def doctor
      puts "NetGuard #{VERSION}（只读诊断，不修改系统）"
      puts "macOS 时区：#{System.timezone}"
      puts "默认物理接口：#{System.default_interface}"
      puts "检测到的 TUN：#{System.tun_interfaces.join(', ').empty? ? '无' : System.tun_interfaces.join(', ')}"
      puts "配置的 TUN：#{System.detect_tun(config.data['tun_interface']) || '未检测到'}"
      puts "代理端点数量：#{config.data['proxy_endpoints'].length}"
      puts "Chrome 语言：#{System.chrome_languages.join(', ')}"
      puts "PF 当前状态：#{System.pf_enabled? ? '已启用' : '未启用或不可读'}"
      puts "项目配置：#{config.path}"
      puts "\n下一步：configure → plan → check → sudo enable --apply。"
    end

    def configure(argv)
      options = {}
      OptionParser.new do |o|
        o.on('--from PATH', '从 Clash YAML 仅导入 server/port') { |v| options[:from] = v }
        o.on('--tun NAME') { |v| options[:tun_interface] = v }
        o.on('--timezone ZONE') { |v| options[:expected_timezone] = v }
        o.on('--language LANG') { |v| options[:expected_language] = v }
        o.on('--expected-ip IP') { |v| options[:expected_ip] = v }
        o.on('--no-lan') { options[:allow_lan] = false }
      end.parse!(argv)
      count = config.import_clash(File.expand_path(options[:from])) if options[:from]
      updates = options.reject { |k, _| k == :from }
      config.update(updates)
      puts "已保存配置：#{config.path}"
      if count
        puts "已导入 #{count} 个端点（未保存 UUID、密码或订阅内容）。"
        dns = config.data['bootstrap_dns'].map { |d| "#{d['scheme']}://#{d['ip']}:#{d['port']}" }
        puts "Clash 引导 DNS（将放行）：#{dns.empty? ? '无' : dns.join(', ')}"
        puts "未放行的 DNS 条目（非字面 IPv4）：#{config.skipped_dns.join(', ')}" if config.skipped_dns.any?
      end
      puts '尚未修改 PF 或系统代理。'
    end

    def plan
      rules = firewall.plan
      firewall.resolver.warnings.each { |w| warn "提示：#{w}" }
      puts rules
    end

    def enable(argv)
      apply = false
      OptionParser.new { |o| o.on('--apply', '实际写入 PF；否则仅提示') { apply = true } }.parse!(argv)
      unless apply
        puts '这是 dry-run。请先检查 plan；实际启用请运行：sudo bin/netguard enable --apply'
        return
      end
      print '这将接管整台 Mac 的出站网络。输入 ENABLE NETGUARD 继续：'
      confirmation = $stdin.gets.to_s.strip
      firewall.enable!(confirmation: confirmation)
      puts 'NetGuard 已启用。代理故障不会自动放开直连。'
      puts '立即运行 bin/netguard check --browser，并保留 sudo bin/netguard recovery 作为恢复入口。'
    end

    def recovery
      firewall.disable!
      puts 'NetGuard anchor 和托管配置已移除，其他网络设置未被重置。'
    end

    def check(argv)
      browser = false
      preflight = false
      OptionParser.new do |o|
        o.on('--browser') { browser = true }
        o.on('--preflight', '启用前只检查代理与环境，不要求直连已经阻断') { preflight = true }
      end.parse!(argv)
      results = if preflight
                  [Checks.public_ip(config.data), Checks.timezone_check(config.data), Checks.language_check(config.data)]
                else
                  Checks.all(config.data)
                end
      results.concat(BrowserCheck.new(config, File.join(ROOT, 'web')).run) if browser
      results.each { |r| puts "#{r.ok ? 'PASS' : 'FAIL'} #{r.name}: #{r.detail}" }
      critical_failure = results.any? { |r| r.critical && !r.ok }
      raise RuntimeError, '存在关键网络检查失败；请保持锁网并排查' if critical_failure
    end

    def watch
      raise SecurityError, '请先完成 enable，再启动监控' unless firewall.state['enabled_at']
      puts '监控已启动；网络异常只会保持 LOCKED，不会自动关闭 PF。Ctrl-C 停止监控不会关闭防火墙。'
      Monitor.new(config, firewall).run
    end

    def status
      health_path = File.join(config.home, 'health.json')
      health = File.file?(health_path) ? JSON.parse(File.read(health_path)) : {}
      puts "NetGuard 配置：#{firewall.state['enabled_at'] ? '已启用' : '未启用或已恢复'}"
      puts "PF：#{System.pf_enabled? ? '已启用' : '未启用或不可读'}"
      puts "TUN：#{System.detect_tun(config.data['tun_interface']) || '未检测到'}"
      puts "健康状态：#{health['healthy'] == true ? '正常' : '锁定/未知'}"
      puts "最近检查：#{health['checked_at'] || '无'}"
      puts "最近结果：#{health['detail'] || '无'}"
    end

    def help
      puts <<~HELP
        NetGuard #{VERSION} — macOS 主机 fail-closed 网络锁
        doctor                       只读检查环境
        configure --from FILE        仅导入代理 server/port
        plan                         显示将要生成的 PF 规则
        enable --apply               实际启用（需要 sudo 和二次输入）
        check [--preflight] [--browser]  启用前预检或启用后完整网络检查
        watch                        故障监控；永不自动放开直连
        status                       查看锁网与健康状态
        recovery                     紧急恢复（需要 sudo，不依赖网络）
        version                      版本
      HELP
    end
  end
end
