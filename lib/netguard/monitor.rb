# frozen_string_literal: true
require 'json'
require 'time'
require 'fileutils'

module NetGuard
  # Runs as the root LaunchDaemon com.netguard.monitor (RunAtLoad), so it is also
  # the boot-time lock.
  #
  # PF itself is verified every heal_interval (default 2 s; local pfctl only, no
  # network). That bounds how long protection can stay switched off by anything
  # else. The full tick runs every check_interval (default 20 s), in this order:
  #   1. heal PF  — re-apply protection if anything undid it (no DNS needed);
  #   2. follow the Clash config — re-import nodes after subscription/profile changes;
  #   3. update rules — TUN or node IP changes;
  #   4. check the exit IP against the address locked at enable time.
  # Each step fails independently; none of them ever disables the firewall.
  class Monitor
    LOG_LIMIT = 1_000_000 # bytes; one previous file is kept as watch.log.1
    HEARTBEAT = 1800      # seconds between repeated identical status lines

    attr_reader :heals

    def initialize(config, firewall)
      @config = config
      @firewall = firewall
      @last_rules = nil
      @heals = 0
      @last_heal = nil
      @clash_mtime = nil
      @clash_reloaded_at = nil
      @last_status = nil
      @last_status_at = nil
      @log_writes = 0
    end

    def run
      $stdout.sync = true
      rotate_log
      next_tick = Time.at(0)
      loop do
        break unless enabled?
        if Time.now >= next_tick
          tick
          next_tick = Time.now + interval('check_interval', 20)
        elsif System.root? && heal_pf
          # Report the repair (health.json, GUI notification) right away.
          next_tick = Time.at(0)
        end
        pause(interval('heal_interval', 2))
      end
      log '保护已被停止（state 中未启用），监控退出。'
    end

    def enabled?
      !@firewall.state['enabled_at'].nil?
    end

    def interval(key, default)
      value = Integer(@config.data[key] || default)
      value.positive? ? value : default
    rescue ArgumentError, TypeError
      default
    end

    def pause(seconds)
      sleep seconds
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
      log_status "#{status} #{network.detail}#{pf_problems.empty? ? '' : "；PF：#{pf_problems.join('、')}"}"
      healthy
    rescue StandardError => e
      write_health('healthy' => false, 'detail' => "监控异常：#{e.message}", 'heals' => @heals, 'last_heal' => @last_heal)
      log_status "LOCKED #{e.message}；防火墙保持启用"
      false
    end

    # Returns true when something had to be repaired.
    def heal_pf
      repaired = @firewall.heal!
      return false if repaired.empty?
      @heals += 1
      @last_heal = { 'at' => Time.now.utc.iso8601, 'problems' => repaired }
      @last_rules = nil
      log "自愈：#{repaired.join('、')}，已重新加载 NetGuard 规则"
      true
    rescue StandardError => e
      log "自愈失败：#{e.message}；将在下个周期重试"
      false
    end

    private

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

    # Steady state is not logged every 20 s: a line is written when the status
    # changes, plus a heartbeat every HEARTBEAT seconds. health.json always has
    # the latest result.
    def log_status(message)
      now = Time.now
      return if message == @last_status && @last_status_at && now - @last_status_at < HEARTBEAT
      @last_status = message
      @last_status_at = now
      log message
    end

    def log(message)
      puts "#{Time.now.strftime('%m-%d %H:%M:%S')} #{message}"
      @log_writes += 1
      rotate_log if (@log_writes % 50).zero?
    end

    # launchd points stdout/stderr at watch.log. Rotate by copy + truncate, then
    # reopen in append mode so writes continue at the start of the empty file.
    def rotate_log
      path = File.join(@config.home, 'watch.log')
      return unless File.file?(path) && File.size(path) > LOG_LIMIT && logging_to?(path)
      FileUtils.cp(path, "#{path}.1")
      File.truncate(path, 0)
      $stdout.reopen(path, 'a')
      $stderr.reopen(path, 'a')
      $stdout.sync = true
    rescue StandardError
      nil
    end

    def logging_to?(path)
      out = $stdout.stat
      file = File.stat(path)
      out.dev == file.dev && out.ino == file.ino
    rescue StandardError
      false
    end
  end
end
