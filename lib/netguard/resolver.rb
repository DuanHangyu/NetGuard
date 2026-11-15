# frozen_string_literal: true
require 'ipaddr'
require 'openssl'
require 'resolv'
require 'socket'
require 'time'
require 'timeout'
require 'yaml'

module NetGuard
  # Resolves proxy endpoints to their *real* addresses.
  #
  # With Clash/Mihomo TUN in fake-ip mode the system resolver answers every
  # domain with 198.18.0.0/15. Allowing those in PF is useless: mihomo itself
  # connects to the real node IP over the physical interface. So we ask the
  # same bootstrap DNS servers mihomo uses (proxy-server-nameserver), with the
  # socket bound to the physical interface (IP_BOUND_IF), and never accept a
  # fake-ip answer. Results are cached so the root monitor can keep working
  # with the last known good IPs when DNS is unavailable.
  class Resolver
    FAKE_IP_RANGE = IPAddr.new('198.18.0.0/15')
    IP_BOUND_IF = 25 # <netinet/in.h> on macOS
    QUERY_TIMEOUT = 5

    attr_reader :warnings

    def self.fake_ip?(ip)
      FAKE_IP_RANGE.include?(IPAddr.new(ip))
    rescue IPAddr::InvalidAddressError
      false
    end

    def self.literal_ipv4?(host)
      IPAddr.new(host).ipv4?
    rescue IPAddr::InvalidAddressError
      false
    end

    def initialize(config)
      @config = config
      @warnings = []
    end

    def cache_path
      File.join(@config.home, 'endpoint-cache.yml')
    end

    def resolve_endpoints(endpoints = @config.data['proxy_endpoints'])
      @warnings = []
      cache = load_cache
      resolved = endpoints.flat_map do |endpoint|
        host = endpoint.fetch('host').to_s
        port = Integer(endpoint.fetch('port'))
        ips = self.class.literal_ipv4?(host) ? [host] : addresses_for(host, cache)
        ips.map { |ip| { 'host' => host, 'port' => port, 'ip' => ip, 'protocol' => endpoint['protocol'] || 'tcp' } }
      end
      save_cache(cache)
      resolved
    end

    private

    def addresses_for(host, cache)
      fresh = lookup(host)
      if fresh.any?
        cache[host] = { 'ips' => fresh, 'resolved_at' => Time.now.utc.iso8601 }
        return fresh
      end
      cached = Array(cache.dig(host, 'ips')).reject { |ip| self.class.fake_ip?(ip) }
      if cached.any?
        @warnings << "#{host} 暂时无法解析，使用缓存的真实 IP（#{cache.dig(host, 'resolved_at')}）"
        return cached
      end
      raise ArgumentError, "无法获得 #{host} 的真实 IP：系统解析只返回 fake-ip 或失败，" \
                           '经物理网卡查询 Clash 引导 DNS 也失败，且没有缓存。可在 Clash 中开启 TUN 前先运行一次 plan，或改用 IP 节点。'
    end

    # Bootstrap DNS over the physical interface first (same view as mihomo),
    # then the system resolver (correct when TUN is off), never fake-ip.
    def lookup(host)
      Array(@config.data['bootstrap_dns']).each do |server|
        ips = query_bootstrap(server, host)
        return ips if ips.any?
      rescue StandardError
        next
      end
      system_lookup(host)
    end

    def system_lookup(host)
      Addrinfo.getaddrinfo(host, nil, :INET, :STREAM).map(&:ip_address).uniq.reject { |ip| self.class.fake_ip?(ip) }
    rescue StandardError
      []
    end

    def query_bootstrap(server, host)
      scheme = server['scheme']
      return [] unless %w[tls tcp udp].include?(scheme)
      message = Resolv::DNS::Message.new(rand(0xffff))
      message.rd = 1
      message.add_question(host, Resolv::DNS::Resource::IN::A)
      reply = Timeout.timeout(QUERY_TIMEOUT) { exchange(server, scheme, message.encode) }
      decoded = Resolv::DNS::Message.decode(reply)
      return [] unless decoded.id == message.id
      decoded.answer.map { |_, _, rr| rr.is_a?(Resolv::DNS::Resource::IN::A) ? rr.address.to_s : nil }
             .compact.uniq.reject { |ip| self.class.fake_ip?(ip) }
    end

    def exchange(server, scheme, packet)
      socket = Socket.new(:INET, scheme == 'udp' ? :DGRAM : :STREAM)
      bind_physical(socket)
      socket.connect(Socket.sockaddr_in(Integer(server['port']), server['ip']))
      if scheme == 'udp'
        socket.send(packet, 0)
        return socket.recv(4096)
      end
      io = scheme == 'tls' ? tls_wrap(socket, server['ip']) : socket
      io.write([packet.bytesize].pack('n') + packet)
      length = io.read(2).unpack1('n')
      io.read(length)
    ensure
      io&.close unless io.equal?(socket)
      socket&.close unless socket&.closed?
    end

    def tls_wrap(socket, ip)
      context = OpenSSL::SSL::SSLContext.new
      context.set_params(verify_mode: OpenSSL::SSL::VERIFY_PEER)
      tls = OpenSSL::SSL::SSLSocket.new(socket, context)
      tls.sync_close = true
      tls.connect
      tls.post_connection_check(ip)
      tls
    end

    def bind_physical(socket)
      index = System.interface_index(System.physical_interface)
      raise RuntimeError, '找不到物理网卡' unless index
      socket.setsockopt(Socket::IPPROTO_IP, IP_BOUND_IF, [index].pack('L'))
    end

    def load_cache
      data = File.file?(cache_path) ? YAML.safe_load(File.read(cache_path)) : {}
      data.is_a?(Hash) ? data : {}
    rescue StandardError
      {}
    end

    def save_cache(cache)
      return if cache.empty?
      File.write(cache_path, YAML.dump(cache))
      File.chmod(0o600, cache_path)
    rescue StandardError
      nil
    end
  end
end
