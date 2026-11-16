# frozen_string_literal: true
require 'ipaddr'
require 'socket'

module NetGuard
  # Helpers that decide whether an address seen by a remote party is the user's
  # real address. Used by the host IPv6 check and the browser WebRTC/IPv6 checks.
  module Leak
    module_function

    NON_PUBLIC = %w[
      0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12
      192.168.0.0/16 198.18.0.0/15 224.0.0.0/4 240.0.0.0/4
      ::1/128 ::/128 fc00::/7 fe80::/10 ff00::/8
    ].map { |cidr| IPAddr.new(cidr) }.freeze

    def parse(ip)
      IPAddr.new(ip.to_s.sub(/%.*\z/, ''))
    rescue IPAddr::Error, ArgumentError
      nil
    end

    def public?(ip)
      addr = parse(ip)
      return false unless addr
      NON_PUBLIC.none? { |net| net.family == addr.family && net.include?(addr) }
    end

    # Global IPv6 addresses on the Mac's own (non-TUN) interfaces: the real
    # IPv6 identity a leak would expose.
    def local_ipv6
      Socket.getifaddrs.map do |ifa|
        addr = ifa.addr
        next unless addr&.ipv6? && !ifa.name.start_with?('utun', 'lo')
        ip = addr.ip_address.sub(/%.*\z/, '')
        public?(ip) ? ip : nil
      end.compact.uniq
    rescue StandardError
      []
    end

    # The same /64 means the same household line even after privacy-address rotation.
    def own_ipv6?(ip, locals = local_ipv6)
      addr = parse(ip)
      return false unless addr&.ipv6?
      locals.any? do |local|
        other = parse(local)
        other && other.mask(64) == addr.mask(64)
      end
    end

    # Any public address other than the proxy exit is the user's own.
    def exposes_real_ip?(ip, exit_ip, locals = local_ipv6)
      return false unless public?(ip)
      return true if own_ipv6?(ip, locals)
      ip.to_s != exit_ip.to_s
    end
  end
end
