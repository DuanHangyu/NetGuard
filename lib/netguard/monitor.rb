# frozen_string_literal: true
require 'json'
require 'time'

module NetGuard
  # Runs as the root LaunchDaemon com.netguard.monitor (RunAtLoad), so it is also
  # the boot-time lock. Every tick, in this order:
  #   1. heal PF  — re-apply protection if anything undid it (no DNS needed);
  #   2. follow the Clash config — re-import nodes after subscription/profile changes;
  #   3. update rules — TUN or node IP changes;
  #   4. check the exit IP against the address locked at enable time.
  # Each step fails independently; none of them ever disables the firewall.
  class Monitor
    attr_reader :heals

    def initialize(config, firewall)
      @config = config
      @firewall = firewall
      @last_rules = nil
      @heals = 0
      @last_heal = nil
      @clash_mtime = nil
      @clash_reloaded_at = nil
    end

    def run
      $stdout.sync = true
      loop do
        break unless enabled?
        tick
        sleep Integer(@config.data['check_interval'] || 20)
      end
      log '保护已被停止（state 中未启用），监控退出。'
    end

    def enabled?
      !@firewall.state['enabled_at'].nil?
    end

    def tick
      @config.reload!
      heal_pf if System.root?
      follow_clash_config
      tun = System.detect_tun(@config.data['tun_interface'])
      update_rules(tun) if System.root?
      expected = @firewall.expected_exit_ip
      network = Checks.public_ip(@config.data.merge('expected_ip' => expected))
      pf = System.root? ? @firewall.pf_status : nil
      pf_problems = pf ? Firewall.describe_problems(pf) : []
      exit_mismatch = !expected.nil? && !network.value.nil? && network.value != expected
      healthy = !tun.nil? && network.ok? && pf_problems.empty?
      write_health(
        'healthy' => healthy, 'tun' => tun, 'detail' => network.detail,
        'exit_ip' => network.value, 'expected_exit_ip' => expected, 'exit_mismatch' => exit_mismatch,
        'pf' => pf, 'pf_problems' => pf_problems,
        'heals' => @heals, 'last_heal' => @last_heal,
        'clash_config' => @config.follow_path, 'clash_reloaded_at' => @clash_reloaded_at,
        'cn_direct' => @firewall.cn_direct_summary
      )
      status = healthy ? 'OK' : 'LOCKED'
      status = 'ALERT 出口变化' if exit_mismatch
      log "#{status} #{network.detail}#{pf_problems.empty? ? '' : "；PF：#{pf_problems.join('、')}"}"
      healthy
    rescue StandardError => e
      write_health('healthy' => false, 'detail' => "监控异常：#{e.message}", 'heals' => @heals, 'last_heal' => @last_heal)
      log "LOCKED #{e.message}；防火墙保持启用"
      false
    end

    private

    def heal_pf
      repaired = @firewall.heal!
      return if repaired.empty?
      @heals += 1
      @last_heal = { 'at' => Time.now.utc.iso8601, 'problems' => repaired }
      @last_rules = nil
      log "自愈：#{repaired.join('、')}，已重新加载 NetGuard 规则"
    rescue StandardError => e
      log "自愈失败：#{e.message}；将在下个周期重试"
    end

    def follow_clash_config
      path = @config.follow_path
      return unless path && File.file?(path)
      mtime = File.mtime(path)
      return if mtime == @clash_mtime
      @clash_mtime = mtime
      extracted = Config.extract_clash(path)
      return unless @config.clash_changed?(extracted)
      @config.data['proxy_endpoints'] = extracted['proxy_endpoints']
      @config.data['bootstrap_dns'] = extracted['bootstrap_dns']
      @config.save
      @clash_reloaded_at = Time.now.utc.iso8601
      log "Clash 配置已变化（#{File.basename(path)}）：重新导入 #{extracted['proxy_endpoints'].length} 个节点、" \
          "#{extracted['bootstrap_dns'].length} 个引导 DNS"
    rescue StandardError => e
      log "读取 Clash 配置失败，保持现有规则：#{e.message}"
    end

    # Re-render every tick so TUN changes and node IP changes are followed;
    # reload PF only when the rules actually differ.
    def update_rules(tun)
      rules = tun ? @firewall.plan : @firewall.lock_only
      @last_rules ||= @firewall.installed_rules
      return if rules == @last_rules
      @firewall.install_anchor_rules(rules)
      @last_rules = rules
      log "PF 规则已更新（TUN：#{tun || '无，lock-only'}）"
    rescue StandardError => e
      log "规则更新失败，保留当前规则：#{e.message}"
    end

    def write_health(data)
      data = data.merge('checked_at' => Time.now.utc.iso8601, 'firewall_policy' => 'fail-closed; never auto-disabled')
      path = File.join(@config.home, 'health.json')
      File.write(path, JSON.pretty_generate(data))
      File.chmod(0o644, path)
    rescue StandardError
      nil
    end

    def log(message)
      puts "#{Time.now.strftime('%H:%M:%S')} #{message}"
    end
  end
end
