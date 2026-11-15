# frozen_string_literal: true
require 'minitest/autorun'
require 'tmpdir'
require 'open3'
require 'json'
$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
require 'netguard'

class NetGuardTest < Minitest::Test
  def setup
    @tmp = Dir.mktmpdir('netguard-test')
    @config = NetGuard::Config.new(@tmp)
  end

  def teardown
    FileUtils.remove_entry(@tmp)
  end

  def test_import_keeps_only_endpoint_metadata
    count = @config.import_clash(File.expand_path('fixture.yml', __dir__))
    @config.save
    assert_equal 2, count
    endpoints = @config.data['proxy_endpoints']
    assert_equal [{ 'host' => '192.0.2.10', 'port' => 443, 'protocol' => 'tcp' }, { 'host' => '192.0.2.20', 'port' => 1080, 'protocol' => 'tcp' }], endpoints
    refute_includes File.read(@config.path), 'not-saved'
    assert_equal 0o600, File.stat(@config.path).mode & 0o777
  end

  def test_firewall_is_fail_closed_and_dns_precedes_lan
    @config.data['proxy_endpoints'] = [{ 'host' => '192.0.2.10', 'port' => 443, 'protocol' => 'tcp' }]
    @config.data['tun_interface'] = 'utun99'
    rules = NetGuard::Firewall.new(@config).plan
    assert_includes rules, 'pass out quick on utun99 all'
    assert_includes rules, 'pass out quick inet proto tcp from any to 192.0.2.10 port 443'
    assert_includes rules, 'block out quick inet6 all'
    assert_includes rules, 'block out all'
    assert rules.index('port { 53, 853 }') < rules.index('10.0.0.0/8'), 'DNS block must precede LAN pass'
    refute_includes rules, 'not-saved'
  end

  def test_udp_endpoint_is_explicitly_scoped
    rules = NetGuard::Firewall.new(@config).render([{ 'ip' => '192.0.2.30', 'port' => 443, 'protocol' => 'udp' }], 'utun7')
    assert_includes rules, 'proto udp from any to 192.0.2.30 port 443'
  end

  def test_empty_endpoints_fail_before_writing_rules
    assert_raises(ArgumentError) { NetGuard::Firewall.new(@config).render([], 'utun7') }
  end

  def test_missing_tun_uses_lock_only_instead_of_opening_network
    @config.data['tun_interface'] = ''
    @config.data['proxy_endpoints'] = [{ 'host' => '192.0.2.10', 'port' => 443 }]
    firewall = NetGuard::Firewall.new(@config)
    assert_raises(ArgumentError) { firewall.plan }
    rules = firewall.lock_only
    refute_includes rules, 'on utun'
    assert_includes rules, 'block out all'
  end

  def test_timezone_check_uses_expected_zone
    @config.data['expected_timezone'] = NetGuard::System.timezone
    assert NetGuard::Checks.timezone_check(@config.data).ok?
  end

  def test_lock_only_survives_endpoint_resolution_failure
    firewall = NetGuard::Firewall.new(@config)
    @config.data['proxy_endpoints'] = [{ 'host' => 'node.example.net', 'port' => 443 }]
    resolver = ->(*) { raise SocketError, 'offline test' }
    firewall.resolver.stub(:resolve_endpoints, resolver) do
      rules = firewall.lock_only
      assert_includes rules, 'block out all'
      refute_includes rules, 'pass out quick on utun'
    end
  end

  def test_monitor_failure_never_calls_disable
    @config.save
    firewall = fake_firewall(state: { 'enabled_at' => 'x' }, pf: INTACT.merge('pf_enabled' => false))
    firewall.define_singleton_method(:lock_only) { "block out all\n" }
    failed = NetGuard::Checks::Result.new('public_ip', false, 'offline test', true)
    NetGuard::System.stub(:root?, true) do
      NetGuard::System.stub(:detect_tun, nil) do
        NetGuard::Checks.stub(:public_ip, failed) do
          refute NetGuard::Monitor.new(@config, firewall).tick
        end
      end
    end
    health = JSON.parse(File.read(File.join(@tmp, 'health.json')))
    assert_equal 'offline test', health['detail'], 'tick must complete, not crash'
    assert_includes health['firewall_policy'], 'never auto-disabled'
    refute_empty firewall.loads, 'a failing proxy must still leave PF rules installed'
  end

  def test_cli_doctor_is_read_only
    env = { 'NETGUARD_HOME' => @tmp }
    out, err, status = Open3.capture3(env, RbConfig.ruby, File.expand_path('../bin/netguard', __dir__), 'doctor')
    assert status.success?, err
    out = out.force_encoding('UTF-8')
    assert_includes out, '只读诊断'
    refute File.exist?(File.join(@tmp, 'state.yml'))
  end
  def test_import_keeps_literal_bootstrap_dns_only
    @config.import_clash(File.expand_path('fixture.yml', __dir__))
    assert_equal [
      { 'scheme' => 'tls', 'ip' => '223.5.5.5', 'port' => 853, 'protocol' => 'tcp' },
      { 'scheme' => 'https', 'ip' => '1.12.12.12', 'port' => 443, 'protocol' => 'tcp' },
      { 'scheme' => 'udp', 'ip' => '119.29.29.29', 'port' => 53, 'protocol' => 'udp' }
    ], @config.data['bootstrap_dns']
    assert_equal ['tls://dns.example.net'], @config.skipped_dns
  end

  def test_bootstrap_dns_is_allowed_before_dns_block
    @config.data['bootstrap_dns'] = [{ 'scheme' => 'tls', 'ip' => '223.5.5.5', 'port' => 853, 'protocol' => 'tcp' }]
    rules = NetGuard::Firewall.new(@config).render([{ 'ip' => '203.0.113.5', 'port' => 443 }], 'utun6')
    allow = rules.index('pass out quick inet proto tcp from any to 223.5.5.5 port 853')
    assert allow, rules
    assert allow < rules.index('port { 53, 853 }'), 'bootstrap DNS must precede the DNS block'
  end

  def test_domain_endpoints_without_bootstrap_dns_are_refused
    @config.data['tun_interface'] = 'utun6'
    @config.data['proxy_endpoints'] = [{ 'host' => 'node.example.net', 'port' => 443 }]
    @config.data['bootstrap_dns'] = []
    error = assert_raises(ArgumentError) { NetGuard::Firewall.new(@config).plan }
    assert_includes error.message, 'proxy-server-nameserver'
  end

  def test_resolver_never_accepts_fake_ip
    @config.data['bootstrap_dns'] = []
    resolver = NetGuard::Resolver.new(@config)
    fake = [Addrinfo.tcp('198.18.0.7', 0)]
    Addrinfo.stub(:getaddrinfo, fake) do
      assert_raises(ArgumentError) { resolver.resolve_endpoints([{ 'host' => 'node.example.net', 'port' => 443 }]) }
    end
  end

  def test_resolver_prefers_bootstrap_and_preserves_protocol
    @config.data['bootstrap_dns'] = [{ 'scheme' => 'tls', 'ip' => '223.5.5.5', 'port' => 853 }]
    resolver = NetGuard::Resolver.new(@config)
    resolver.stub(:query_bootstrap, ['203.0.113.9']) do
      Addrinfo.stub(:getaddrinfo, ->(*) { flunk 'system resolver should not be needed' }) do
        result = resolver.resolve_endpoints([{ 'host' => 'node.example.net', 'port' => 8443, 'protocol' => 'udp' }])
        assert_equal [{ 'host' => 'node.example.net', 'port' => 8443, 'ip' => '203.0.113.9', 'protocol' => 'udp' }], result
      end
    end
    assert_equal 0o600, File.stat(resolver.cache_path).mode & 0o777
  end

  def test_resolver_falls_back_to_cached_real_ip_when_dns_is_blocked
    @config.data['bootstrap_dns'] = [{ 'scheme' => 'tls', 'ip' => '223.5.5.5', 'port' => 853 }]
    endpoints = [{ 'host' => 'node.example.net', 'port' => 443 }]
    first = NetGuard::Resolver.new(@config)
    first.stub(:query_bootstrap, ['203.0.113.9']) { first.resolve_endpoints(endpoints) }
    later = NetGuard::Resolver.new(@config)
    later.stub(:query_bootstrap, ->(*) { raise Errno::ETIMEDOUT }) do
      Addrinfo.stub(:getaddrinfo, [Addrinfo.tcp('198.18.0.7', 0)]) do
        assert_equal ['203.0.113.9'], later.resolve_endpoints(endpoints).map { |e| e['ip'] }
      end
    end
    assert_match(/缓存/, later.warnings.first)
  end

  def test_parse_nameserver_variants
    parse = NetGuard::Config.method(:parse_nameserver)
    assert_equal 853, parse.call('tls://223.5.5.5')['port']
    assert_equal 5353, parse.call('udp://9.9.9.9:5353')['port']
    assert_equal 'tcp', parse.call('tcp://8.8.8.8')['protocol']
    assert_nil parse.call('https://dns.google/dns-query')
    assert_nil parse.call('dhcp://en0')
    assert_nil parse.call('system')
  end
  # Regression: stateful pass rules (default flags S/SA keep state) dropped the
  # proxy's SYN-ACK on lo0 and every connection opened before enabling.
  def test_pass_rules_are_stateless_and_loopback_is_bidirectional
    @config.data['bootstrap_dns'] = [{ 'scheme' => 'tls', 'ip' => '223.5.5.5', 'port' => 853, 'protocol' => 'tcp' }]
    firewall = NetGuard::Firewall.new(@config)
    rules = firewall.render([{ 'ip' => '203.0.113.5', 'port' => 443 }], 'utun6')
    pass_rules = rules.lines.grep(/\Apass /)
    refute_empty pass_rules
    pass_rules.each { |rule| assert_includes rule, 'flags any no state', rule }
    assert_includes rules, "pass quick on lo0 all flags any no state\n"
    NetGuard::System.stub(:root?, false) do
      firewall.resolver.stub(:resolve_endpoints, ->(*) { raise SocketError }) do
        assert_includes firewall.lock_only, "pass quick on lo0 all flags any no state\n"
      end
    end
  end
  def test_ipv6_check_judges_by_exit_address
    ok = Struct.new(:success?).new(true)
    NetGuard::System.stub(:run, ["203.0.113.8\n", '', ok]) do
      assert NetGuard::Checks.ipv6_check.ok?, 'IPv4 exit via TUN proxy is not a leak'
    end
    NetGuard::System.stub(:run, ["240e:1::5\n", '', ok]) do
      refute NetGuard::Checks.ipv6_check.ok?, 'a real IPv6 exit is a leak'
    end
  end
  # ---- self-heal, exit lock, boot, Clash runtime config ----------------------

  OK_STATUS = Struct.new(:success?).new(true)
  INTACT = { 'pf_enabled' => true, 'anchor_referenced' => true, 'anchor_rules' => 5, 'pf_conf_managed' => true }.freeze

  def fake_firewall(state: {}, pf: INTACT, installed: "pass quick on lo0 all\nblock out all\n")
    firewall = NetGuard::Firewall.new(@config)
    firewall.define_singleton_method(:state) { state }
    firewall.define_singleton_method(:pf_status) { pf }
    firewall.define_singleton_method(:installed_rules) { installed }
    firewall.define_singleton_method(:disable!) { |*| raise 'monitor must never disable the firewall' }
    loads = []
    firewall.define_singleton_method(:install_anchor_rules) { |rules| loads << rules }
    firewall.define_singleton_method(:loads) { loads }
    firewall
  end

  def test_pf_status_parses_live_pfctl_output
    firewall = NetGuard::Firewall.new(@config)
    outputs = {
      %w[-s rules] => "anchor \"com.apple/*\" all\nanchor \"com.netguard\" all\n",
      %w[-a com.netguard -s rules] => "pass quick on lo0 all no state\nblock drop out all\n"
    }
    run = ->(_bin, *args) { [outputs.fetch(args, ''), '', OK_STATUS] }
    NetGuard::System.stub(:run, run) do
      NetGuard::System.stub(:pf_enabled?, true) do
        status = firewall.pf_status
        assert_equal 2, status['anchor_rules']
        assert status['anchor_referenced']
      end
    end
  end

  def test_intact_and_problem_descriptions
    assert NetGuard::Firewall.intact?(INTACT)
    broken = INTACT.merge('pf_enabled' => false, 'anchor_rules' => 0)
    refute NetGuard::Firewall.intact?(broken)
    assert_equal ['PF 被关闭', 'anchor 内没有规则'], NetGuard::Firewall.describe_problems(broken)
  end

  def test_heal_reapplies_last_rules_when_pf_was_disabled
    firewall = fake_firewall(pf: INTACT.merge('pf_enabled' => false))
    NetGuard::System.stub(:root?, true) do
      assert_equal ['PF 被关闭'], firewall.heal!
    end
    assert_equal ["pass quick on lo0 all\nblock out all\n"], firewall.loads
  end

  def test_heal_is_a_noop_when_intact_and_falls_back_to_lock_only
    firewall = fake_firewall
    NetGuard::System.stub(:root?, true) { assert_empty firewall.heal! }
    assert_empty firewall.loads
    bare = fake_firewall(installed: nil)
    bare.define_singleton_method(:lock_only) { "block out all\n" }
    NetGuard::System.stub(:root?, true) { bare.heal!(force: true) }
    assert_equal ["block out all\n"], bare.loads
  end

  def test_expected_exit_ip_prefers_config_then_locked_state
    firewall = fake_firewall(state: { 'locked_exit_ip' => '203.0.113.1' })
    assert_equal '203.0.113.1', firewall.expected_exit_ip
    @config.data['expected_ip'] = '198.51.100.9'
    assert_equal '198.51.100.9', firewall.expected_exit_ip
  end

  def test_monitor_heals_first_and_flags_exit_change
    @config.save
    firewall = fake_firewall(state: { 'enabled_at' => 'x', 'locked_exit_ip' => '203.0.113.1' },
                             pf: INTACT.merge('pf_enabled' => false))
    firewall.define_singleton_method(:plan) { "pass quick on lo0 all\nblock out all\n" }
    changed = NetGuard::Checks::Result.new('public_ip', false, '出口变化', true, '203.0.113.99')
    seen_expected = nil
    check = lambda { |data| seen_expected = data['expected_ip']; changed }
    monitor = NetGuard::Monitor.new(@config, firewall)
    NetGuard::System.stub(:root?, true) do
      NetGuard::System.stub(:detect_tun, 'utun6') do
        NetGuard::Checks.stub(:public_ip, check) do
          refute monitor.tick
        end
      end
    end
    assert_equal '203.0.113.1', seen_expected
    assert_equal 1, monitor.heals
    health = JSON.parse(File.read(File.join(@tmp, 'health.json')))
    assert health['exit_mismatch']
    assert_equal '203.0.113.99', health['exit_ip']
    assert_equal ['PF 被关闭'], health['pf_problems']
    assert_equal ['PF 被关闭'], health.dig('last_heal', 'problems')
  end

  def test_monitor_reimports_changed_clash_config_and_survives_bad_yaml
    source = File.join(@tmp, 'clash-verge.yaml')
    File.write(source, File.read(File.expand_path('fixture.yml', __dir__)))
    @config.import_clash(source)
    @config.save
    firewall = fake_firewall(state: { 'enabled_at' => 'x' })
    ok = NetGuard::Checks::Result.new('public_ip', true, 'ok', true, '203.0.113.1')
    monitor = NetGuard::Monitor.new(@config, firewall)
    run_tick = lambda do
      NetGuard::System.stub(:detect_tun, nil) do
        NetGuard::Checks.stub(:public_ip, ok) { monitor.tick }
      end
    end
    run_tick.call
    File.write(source, "proxies:\n  - {name: n, type: vless, server: 203.0.113.50, port: 8443}\n")
    File.utime(Time.now + 5, Time.now + 5, source)
    run_tick.call
    assert_equal [{ 'host' => '203.0.113.50', 'port' => 8443, 'protocol' => 'tcp' }],
                 NetGuard::Config.new(@tmp).data['proxy_endpoints']
    File.write(source, "proxies: [ broken")
    File.utime(Time.now + 10, Time.now + 10, source)
    run_tick.call
    assert_equal 1, NetGuard::Config.new(@tmp).data['proxy_endpoints'].length, 'bad YAML must keep the last good nodes'
  end

  def test_monitor_stops_once_protection_is_disabled
    firewall = fake_firewall(state: {})
    monitor = NetGuard::Monitor.new(@config, firewall)
    def monitor.tick
      raise 'must not tick while disabled'
    end
    out, = capture_io { monitor.run }
    assert_includes out, '监控退出'
  end

  def test_enable_locks_current_exit_ip
    firewall = NetGuard::Firewall.new(@config)
    firewall.define_singleton_method(:plan) { "block out all\n" }
    firewall.define_singleton_method(:install_anchor_rules) { |_| true }
    ok = NetGuard::Checks::Result.new('public_ip', true, 'ok', true, '203.0.113.7')
    NetGuard::System.stub(:root?, true) do
      NetGuard::System.stub(:pf_enabled?, false) do
        NetGuard::Checks.stub(:public_ip, ok) do
          firewall.enable!(confirmation: 'ENABLE NETGUARD')
        end
      end
    end
    assert_equal '203.0.113.7', firewall.state['locked_exit_ip']
    assert_equal '203.0.113.7', firewall.expected_exit_ip
  end

  def test_watch_without_enable_exits_cleanly
    env = { 'NETGUARD_HOME' => @tmp }
    out, _, status = Open3.capture3(env, RbConfig.ruby, File.expand_path('../bin/netguard', __dir__), 'watch')
    assert status.success?
    assert_includes out.force_encoding('UTF-8'), '未启用'
  end

  def test_verge_runtime_path_lookup
    assert_nil NetGuard::Config.verge_runtime_path(@tmp)
    path = File.join(@tmp, NetGuard::Config::VERGE_RUNTIME)
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, 'proxies: []')
    assert_equal path, NetGuard::Config.verge_runtime_path(@tmp)
  end

  def test_follow_path_prefers_verge_runtime_under_the_users_home
    @config.data['clash_config'] = '/Users/someone/Downloads/sub.yaml'
    assert_equal '/Users/someone/Downloads/sub.yaml', @config.follow_path
    runtime = File.join(File.dirname(@tmp), NetGuard::Config::VERGE_RUNTIME)
    created = !File.exist?(runtime)
    FileUtils.mkdir_p(File.dirname(runtime))
    File.write(runtime, 'proxies: []') if created
    assert_equal runtime, @config.follow_path
  ensure
    FileUtils.rm_rf(File.join(File.dirname(@tmp), 'Library')) if created
  end
end
