# frozen_string_literal: true
require 'json'
require 'time'

module NetGuard
  class Monitor
    def initialize(config, firewall)
      @config = config
      @firewall = firewall
      @last_rules = nil
    end

    def run
      $stdout.sync = true
      loop do
        tick
        sleep Integer(@config.data['check_interval'] || 20)
      end
    end

    def tick
      tun = System.detect_tun(@config.data['tun_interface'])
      network = Checks.public_ip(@config.data)
      healthy = !tun.nil? && network.ok?
      if System.root?
        # Re-render every tick so TUN changes *and* node IP changes (re-resolved via
        # the allowed bootstrap DNS) are followed; reload PF only when rules differ.
        rules = tun ? @firewall.plan : @firewall.lock_only
        @last_rules ||= (File.read(Firewall::ANCHOR_PATH) rescue nil)
        if rules != @last_rules
          @firewall.install_anchor_rules(rules)
          @last_rules = rules
          puts "#{Time.now.strftime('%H:%M:%S')} PF 规则已更新（TUN：#{tun || '无，lock-only'}）"
        end
      end
      state = { 'healthy' => healthy, 'tun' => tun, 'checked_at' => Time.now.utc.iso8601, 'detail' => network.detail, 'firewall_policy' => 'fail-closed; never auto-disabled' }
      File.write(File.join(@config.home, 'health.json'), JSON.pretty_generate(state))
      puts "#{Time.now.strftime('%H:%M:%S')} #{healthy ? 'OK' : 'LOCKED'} #{network.detail}"
      healthy
    rescue StandardError => e
      puts "#{Time.now.strftime('%H:%M:%S')} LOCKED #{e.message}；防火墙保持启用"
      false
    end
  end
end
