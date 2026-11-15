# frozen_string_literal: true
require 'yaml'
require 'fileutils'

module NetGuard
  class Config
    DEFAULTS = {
      'version' => 1,
      'tun_interface' => 'auto',
      'expected_timezone' => 'America/Chicago',
      'expected_language' => 'en-US',
      'expected_ip' => nil,
      'allow_lan' => true,
      'block_ipv6' => true,
      'check_url' => 'https://api.ipify.org',
      'check_interval' => 20,
      'proxy_endpoints' => [],
      'bootstrap_dns' => []
    }.freeze

    attr_reader :home, :path, :data

    def initialize(home = nil)
      @home = home || ENV['NETGUARD_HOME'] || File.join(System.user_home, '.netguard')
      @path = File.join(@home, 'config.yml')
      @data = DEFAULTS.merge(File.file?(@path) ? YAML.safe_load(File.read(@path)) : {})
    end

    def save
      FileUtils.mkdir_p(@home)
      File.write(@path, YAML.dump(@data))
      File.chmod(0o600, @path)
    end

    def import_clash(path)
      parsed = YAML.safe_load(File.read(path))
      proxies = parsed.is_a?(Hash) ? parsed['proxies'] : nil
      raise ArgumentError, 'YAML 中没有 proxies 数组' unless proxies.is_a?(Array)
      endpoints = proxies.map do |proxy|
        next unless proxy.is_a?(Hash) && proxy['server'] && proxy['port']
        transport = proxy['type'].to_s.match?(/hysteria|tuic/i) ? 'udp' : 'tcp'
        { 'host' => proxy['server'].to_s, 'port' => Integer(proxy['port']), 'protocol' => transport }
      end.compact.uniq
      raise ArgumentError, '没有找到可用代理端点' if endpoints.empty?
      @data['proxy_endpoints'] = endpoints
      @data['bootstrap_dns'], @skipped_dns = self.class.bootstrap_dns_from(parsed['dns'])
      endpoints.length
    end

    # Entries that could not be turned into a PF rule (domains, IPv6, dhcp://, system).
    def skipped_dns
      @skipped_dns || []
    end

    # mihomo resolves node domains with proxy-server-nameserver (falling back to
    # nameserver). Those queries leave via the physical interface, so PF must
    # allow exactly these resolver IP:port pairs or Clash cannot reach any node.
    def self.bootstrap_dns_from(dns)
      return [[], []] unless dns.is_a?(Hash)
      list = Array(dns['proxy-server-nameserver'])
      list = Array(dns['nameserver']) if list.empty?
      servers = []
      skipped = []
      list.each do |entry|
        server = parse_nameserver(entry.to_s.strip)
        server ? servers << server : skipped << entry.to_s
      end
      [servers.uniq, skipped]
    end

    def self.parse_nameserver(entry)
      match = entry.match(%r{\A(?:(tls|https|tcp|udp)://)?([^/:#\s]+)(?::(\d+))?(?:[/#].*)?\z})
      return nil unless match
      scheme = match[1] || 'udp'
      host = match[2]
      return nil unless Resolver.literal_ipv4?(host)
      default_port = { 'tls' => 853, 'https' => 443, 'tcp' => 53, 'udp' => 53 }.fetch(scheme)
      { 'scheme' => scheme, 'ip' => host, 'port' => Integer(match[3] || default_port),
        'protocol' => scheme == 'udp' ? 'udp' : 'tcp' }
    end

    def update(options)
      options.each { |key, value| @data[key.to_s] = value unless value.nil? }
      save
    end
  end
end
