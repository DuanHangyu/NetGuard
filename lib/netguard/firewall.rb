# frozen_string_literal: true
require 'fileutils'
require 'time'
require 'digest'

module NetGuard
  class Firewall
    ANCHOR = 'com.netguard'
    ANCHOR_PATH = '/etc/pf.anchors/com.netguard'
PF_CONF = '/etc/pf.conf'
# Pass rules are stateless on purpose. PF's default `flags S/SA keep state`
# only matches SYN packets, so (1) connections opened before enabling (Clash's
# live node links, browser keep-alives to the proxy port) were dropped mid-stream,
# and (2) on lo0 both directions are "out", so the proxy's SYN-ACK back to the
# browser never matched and every system-proxy connection failed.
# Inbound traffic is not filtered, so return packets need no state.
STATELESS = 'flags any no state'
LOOPBACK_RULE = 'pass quick on lo0 all flags any no state'
# Optional "国内直连": mainland-China IPv4 ranges from Clash's own geoip.dat, so the
# connections Clash itself routes `GEOIP,CN,DIRECT` (WeChat, Alipay, ...) can leave
# via the physical uplink. Everything else stays proxy-only.
CN_TABLE = 'netguard_cn'
CN_TABLE_PATH = '/etc/pf.anchors/com.netguard.cn'
CN_MARK = '# cn-direct'

    attr_reader :config

    def resolver
      @resolver ||= Resolver.new(config)
    end

    def initialize(config)
      @config = config
    end

    def state_path
      File.join(config.home, 'state.yml')
    end

    def state
      File.file?(state_path) ? YAML.safe_load(File.read(state_path)) : {}
    rescue StandardError
      {}
    end

    def render(resolved, tun)
      raise ArgumentError, '没有已解析的代理端点' if resolved.empty?
      lines = [
        '# NetGuard fail-closed anchor; direct networking is never restored by the monitor.',
        LOOPBACK_RULE
      ]
      # Only with a live TUN: when Clash is down (lock-only) nothing goes direct.
      cn = tun && !tun.empty? ? cn_direct_cidrs : nil
      if cn
        lines.insert(1, "#{CN_MARK} #{cn.length} ranges sha256:#{Digest::SHA256.hexdigest(cn.join("\n"))[0, 16]}",
                     "table <#{CN_TABLE}> persist file \"#{CN_TABLE_PATH}\"")
      end
      lines << "pass out quick on #{tun} all #{STATELESS}" if tun && !tun.empty?
      resolved.uniq { |e| [e['ip'], e['port']] }.each do |endpoint|
        protocol = endpoint['protocol'] || 'tcp'
        lines << "pass out quick inet proto #{protocol} from any to #{endpoint['ip']} port #{endpoint['port']} #{STATELESS}"
      end
      # Clash's own bootstrap DNS (proxy-server-nameserver) must reach its exact
      # resolvers over the physical uplink, otherwise mihomo cannot resolve node domains.
      Array(config.data['bootstrap_dns']).uniq { |d| [d['ip'], d['port'], d['protocol']] }.each do |dns|
        lines << "pass out quick inet proto #{dns['protocol'] || 'tcp'} from any to #{dns['ip']} port #{dns['port']} #{STATELESS}"
      end
      # DNS blocking precedes LAN access so a router cannot be used as a bypass resolver.
      lines << 'block out quick inet proto { tcp, udp } from any to any port { 53, 853 }'
      # After the DNS block, so mainland resolvers cannot become a bypass for DNS.
      lines << "pass out quick inet from any to <#{CN_TABLE}> #{STATELESS}" if cn
      if config.data['allow_lan']
        lines << 'pass out quick inet to { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4 } ' + STATELESS
        lines << 'pass out quick inet proto udp from any to any port { 67, 68 } ' + STATELESS
      end
      # IPv6 is permitted only when it has already passed through the approved TUN rule.
      lines << 'block out quick inet6 all'
      lines << 'block out all'
      lines.join("\n") + "\n"
    end

    def plan
      tun = System.detect_tun(config.data['tun_interface'])
      raise ArgumentError, '未检测到 TUN 接口；可先使用 lock-only 保持断网' if tun.nil? || tun.empty?
      require_bootstrap_dns!
      resolved = resolver.resolve_endpoints(config.data['proxy_endpoints'])
      render(resolved, tun)
    end

    def lock_only
      resolved = resolver.resolve_endpoints(config.data['proxy_endpoints'])
      render(resolved, nil)
    rescue StandardError
      # If DNS is unavailable at boot, even proxy resolution fails: remain offline safely.
      [
        LOOPBACK_RULE,
        'block out quick inet proto { tcp, udp } from any to any port { 53, 853 }',
        'block out quick inet6 all',
        'block out all'
      ].join("\n") + "\n"
    end

    def warnings
      @warnings ||= []
    end

    def note_warning(message)
      warnings << message unless warnings.include?(message)
    end

    # Mainland ranges when 国内直连 is on and Clash's geoip.dat is readable; nil
    # otherwise (then nothing extra is allowed). Cached by file mtime because the
    # monitor re-renders every tick.
    def cn_direct_cidrs
      return nil unless config.data['allow_cn_direct']
      path = config.geoip_path
      unless path
        note_warning('已开启国内直连，但找不到 Clash Verge 的 geoip.dat；国内直连暂不放行')
        return nil
      end
      key = [path, File.mtime(path)]
      return @cn_cache[1] if @cn_cache && @cn_cache[0] == key
      cidrs = GeoIP.ipv4_cidrs(path, 'CN')
      raise ArgumentError, 'geoip.dat 中的 CN 网段数量异常' if cidrs.length < 1000
      @cn_cache = [key, cidrs]
      cidrs
    rescue StandardError => e
      note_warning("国内直连列表读取失败，暂不放行：#{e.message}")
      nil
    end

    # Status line source for CLI/monitor: nil when off.
    def cn_direct_summary
      return nil unless config.data['allow_cn_direct']
      cidrs = cn_direct_cidrs
      cidrs ? "#{cidrs.length} 个中国大陆 IPv4 网段（Clash geoip.dat）" : '已开启但列表不可用，未放行'
    end

    # Domain-based nodes only work if mihomo can still resolve them once PF is on.
    def require_bootstrap_dns!
      domains = Array(config.data['proxy_endpoints']).map { |e| e['host'].to_s }.reject { |h| Resolver.literal_ipv4?(h) }
      return if domains.empty? || Array(config.data['bootstrap_dns']).any?
      raise ArgumentError, '代理节点使用域名，但 YAML 的 dns 段没有可放行的 proxy-server-nameserver/nameserver（需字面 IPv4，如 tls://223.5.5.5:853）。' \
                           '启用后 Clash 将无法解析节点，拒绝生成规则。'
    end

    # Kept for compatibility: the monitor daemon (RunAtLoad) now performs the boot
    # lock itself via heal!, before any DNS or network work.
    def boot_lock!
      raise SecurityError, '需要 root' unless System.root?
      return false unless state['enabled_at']
      heal!(force: true)
      true
    end

    # Exit IP the monitor must see: an explicit config value wins, otherwise the
    # address recorded when protection was enabled.
    def expected_exit_ip
      explicit = config.data['expected_ip'].to_s.strip
      return explicit unless explicit.empty?
      locked = state['locked_exit_ip'].to_s.strip
      locked.empty? ? nil : locked
    end

    # Live PF state as root sees it. Anything other PF users, macOS updates or a
    # `pfctl -d` might have undone shows up here.
    def pf_status
      main, = System.run('/sbin/pfctl', '-s', 'rules')
      anchor, = System.run('/sbin/pfctl', '-a', ANCHOR, '-s', 'rules')
      pf_conf = File.file?(PF_CONF) ? File.read(PF_CONF) : ''
      {
        'pf_enabled' => System.pf_enabled?,
        'anchor_referenced' => main.to_s.lines.any? { |l| l.start_with?("anchor \"#{ANCHOR}\"") },
        'anchor_rules' => anchor.to_s.lines.count { |l| l.start_with?('pass', 'block') },
        'pf_conf_managed' => pf_conf.include?("load anchor \"#{ANCHOR}\"")
      }
    end

    def self.intact?(status)
      status['pf_enabled'] && status['anchor_referenced'] && status['anchor_rules'].to_i.positive? && status['pf_conf_managed']
    end

    def self.describe_problems(status)
      problems = []
      problems << 'PF 被关闭' unless status['pf_enabled']
      problems << '主规则集缺少 NetGuard anchor' unless status['anchor_referenced']
      problems << 'anchor 内没有规则' unless status['anchor_rules'].to_i.positive?
      problems << '/etc/pf.conf 缺少托管行' unless status['pf_conf_managed']
      problems
    end

    # Re-apply protection if anything was undone. Uses the last installed rules
    # first (no DNS needed, works at boot), else lock-only. Returns the problems
    # that were repaired, or [] when protection was already intact.
    def heal!(force: false)
      raise SecurityError, '需要 root' unless System.root?
      status = pf_status
      return [] if !force && self.class.intact?(status)
      problems = force ? ['启动时强制加载'] : self.class.describe_problems(status)
      rules = installed_rules.to_s
      rules = lock_only unless rules.include?('block out')
      install_anchor_rules(rules)
      problems
    end

    def installed_rules
      File.file?(ANCHOR_PATH) ? File.read(ANCHOR_PATH) : nil
    rescue StandardError
      nil
    end

    def enable!(confirmation: nil)
      raise SecurityError, '需要 root；请使用 sudo' unless System.root?
      raise SecurityError, '实际启用需要输入 ENABLE NETGUARD' unless confirmation == 'ENABLE NETGUARD'
      rules = plan
      exit_check = Checks.public_ip(config.data)
      raise RuntimeError, "代理当前不可用，拒绝在可能断网的状态下启用：#{exit_check.detail}" unless exit_check.ok?

      FileUtils.mkdir_p(config.home)
      backup = File.join(config.home, 'backups', Time.now.utc.strftime('%Y%m%dT%H%M%SZ'))
      FileUtils.mkdir_p(backup)
      FileUtils.cp(PF_CONF, File.join(backup, 'pf.conf')) if File.file?(PF_CONF)
      # The exit seen now is locked; the monitor alerts whenever it changes.
      File.write(state_path, YAML.dump({ 'pf_was_enabled' => System.pf_enabled?, 'backup' => backup,
                                         'enabled_at' => Time.now.utc.iso8601, 'locked_exit_ip' => exit_check.value }))
      File.chmod(0o600, state_path)
      begin
        install_anchor_rules(rules)
      rescue StandardError => e
        FileUtils.cp(File.join(backup, 'pf.conf'), PF_CONF) if File.file?(File.join(backup, 'pf.conf'))
        File.write(state_path, YAML.dump(state.merge('enabled_at' => nil, 'last_error' => e.message)))
        raise
      end
      true
    end

    def install_anchor_rules(rules)
      rules = prepare_cn_table(rules)
      File.write(ANCHOR_PATH, rules)
      File.chmod(0o600, ANCHOR_PATH)
      text = File.read(PF_CONF)
      unless text.include?('load anchor "com.netguard"')
        text << "\n# NetGuard managed lines\nanchor \"com.netguard\"\nload anchor \"com.netguard\" from \"#{ANCHOR_PATH}\"\n"
        File.write(PF_CONF, text)
      end
      out, err, status = System.run('/sbin/pfctl', '-f', PF_CONF)
      unless status.success?
        # 国内直连 is optional: never let it be the reason PF stays unloaded.
        stripped = strip_cn(rules)
        raise RuntimeError, "PF 加载失败：#{err}#{out}" if stripped == rules
        File.write(ANCHOR_PATH, stripped)
        out, err, status = System.run('/sbin/pfctl', '-f', PF_CONF)
        raise RuntimeError, "PF 加载失败：#{err}#{out}" unless status.success?
        note_warning("国内直连表加载失败，已退回全代理规则：#{err}#{out}".strip)
      end
      System.run('/sbin/pfctl', '-E')
    end

    def strip_cn(rules)
      rules.lines.reject { |l| l.start_with?(CN_MARK) || l.include?("<#{CN_TABLE}>") }.join
    end

    # A rule set referencing a missing table file would make `pfctl -f` fail and
    # leave the machine unprotected, so write the table first, or, if no list is
    # available (heal at boot with geoip unreadable and no previous file), drop
    # the 国内直连 lines and stay strictly proxy-only.
    def prepare_cn_table(rules)
      return rules unless rules.include?("<#{CN_TABLE}>")
      cidrs = cn_direct_cidrs
      if cidrs
        File.write(cn_table_path, cidrs.join("\n") + "\n")
        File.chmod(0o644, cn_table_path)
        return rules
      end
      # Keep a previously written list rather than dropping the rule (boot heal).
      return rules if config.data['allow_cn_direct'] && File.file?(cn_table_path) && File.size(cn_table_path).positive?
      strip_cn(rules)
    end

    def cn_table_path
      CN_TABLE_PATH
    end

    def disable!
      raise SecurityError, '需要 root；请使用 sudo' unless System.root?
      remove_managed_lines
      System.run('/sbin/pfctl', '-a', ANCHOR, '-F', 'all')
      File.delete(ANCHOR_PATH) if File.file?(ANCHOR_PATH)
      File.delete(cn_table_path) if File.file?(cn_table_path)
      if File.file?(PF_CONF)
        out, err, status = System.run('/sbin/pfctl', '-f', PF_CONF)
        raise RuntimeError, "恢复 PF 配置失败：#{err}#{out}" unless status.success?
      end
      previous = state['pf_was_enabled']
      System.run('/sbin/pfctl', '-d') if previous == false
      File.write(state_path, YAML.dump(state.merge('enabled_at' => nil, 'disabled_at' => Time.now.utc.iso8601)))
      true
    end

    def remove_managed_lines
      return unless File.file?(PF_CONF)
      lines = File.readlines(PF_CONF).reject do |line|
        line.include?('NetGuard managed lines') || line.strip == 'anchor "com.netguard"' || line.include?('load anchor "com.netguard"')
      end
      File.write(PF_CONF, lines.join)
    end
  end
end
