# frozen_string_literal: true
require 'fileutils'
require 'time'

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

    # Domain-based nodes only work if mihomo can still resolve them once PF is on.
    def require_bootstrap_dns!
      domains = Array(config.data['proxy_endpoints']).map { |e| e['host'].to_s }.reject { |h| Resolver.literal_ipv4?(h) }
      return if domains.empty? || Array(config.data['bootstrap_dns']).any?
      raise ArgumentError, '代理节点使用域名，但 YAML 的 dns 段没有可放行的 proxy-server-nameserver/nameserver（需字面 IPv4，如 tls://223.5.5.5:853）。' \
                           '启用后 Clash 将无法解析节点，拒绝生成规则。'
    end

    def boot_lock!
      raise SecurityError, '需要 root' unless System.root?
      return false unless state['enabled_at']
      rules = begin
        plan
      rescue StandardError
        lock_only
      end
      install_anchor_rules(rules)
      true
    end

    def enable!(confirmation: nil)
      raise SecurityError, '需要 root；请使用 sudo' unless System.root?
      raise SecurityError, '实际启用需要输入 ENABLE NETGUARD' unless confirmation == 'ENABLE NETGUARD'
      rules = plan
      raise RuntimeError, '代理当前不可用，拒绝在可能断网的状态下启用' unless Checks.public_ip(config.data).ok?

      FileUtils.mkdir_p(config.home)
      backup = File.join(config.home, 'backups', Time.now.utc.strftime('%Y%m%dT%H%M%SZ'))
      FileUtils.mkdir_p(backup)
      FileUtils.cp(PF_CONF, File.join(backup, 'pf.conf')) if File.file?(PF_CONF)
      File.write(state_path, YAML.dump({ 'pf_was_enabled' => System.pf_enabled?, 'backup' => backup, 'enabled_at' => Time.now.utc.iso8601 }))
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
      File.write(ANCHOR_PATH, rules)
      File.chmod(0o600, ANCHOR_PATH)
      text = File.read(PF_CONF)
      unless text.include?('load anchor "com.netguard"')
        text << "\n# NetGuard managed lines\nanchor \"com.netguard\"\nload anchor \"com.netguard\" from \"#{ANCHOR_PATH}\"\n"
        File.write(PF_CONF, text)
      end
      out, err, status = System.run('/sbin/pfctl', '-f', PF_CONF)
      raise RuntimeError, "PF 加载失败：#{err}#{out}" unless status.success?
      System.run('/sbin/pfctl', '-E')
    end

    def disable!
      raise SecurityError, '需要 root；请使用 sudo' unless System.root?
      remove_managed_lines
      System.run('/sbin/pfctl', '-a', ANCHOR, '-F', 'all')
      File.delete(ANCHOR_PATH) if File.file?(ANCHOR_PATH)
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
