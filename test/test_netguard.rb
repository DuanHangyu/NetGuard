# frozen_string_literal: true
require 'minitest/autorun'
require 'tmpdir'
require 'open3'
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
    firewall = Object.new
    def firewall.disable!(*)
      raise 'monitor must never disable the firewall'
    end
    failed = NetGuard::Checks::Result.new('public_ip', false, 'offline test', true)
    NetGuard::System.stub(:root?, false) do
      NetGuard::System.stub(:detect_tun, nil) do
        NetGuard::Checks.stub(:public_ip, failed) do
          refute NetGuard::Monitor.new(@config, firewall).tick
        end
      end
    end
    health = File.read(File.join(@tmp, 'health.json'))
    assert_includes health, 'fail-closed; never auto-disabled'
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
end
