# frozen_string_literal: true
require 'json'
require 'timeout'

module NetGuard
  class Checks
    Result = Struct.new(:name, :ok, :detail, :critical) do
      def ok?
        !!ok
      end

      def to_h
        { 'name' => name, 'ok' => ok, 'detail' => detail, 'critical' => critical }
      end
    end

    def self.public_ip(config)
      url = config['check_url']
      out, err, status = System.run('/usr/bin/curl', '-4', '--silent', '--show-error', '--fail', '--max-time', '10', url)
      ip = out.strip
      return Result.new('public_ip', false, "公网检查失败：#{err.strip}", true) unless status.success? && ip.match?(/\A\d{1,3}(\.\d{1,3}){3}\z/)
      expected = config['expected_ip']
      if expected && !expected.to_s.empty? && expected != ip
        return Result.new('public_ip', false, "出口变化：期望 #{expected}，实际 #{ip}", true)
      end
      Result.new('public_ip', true, "终端出口：#{ip}", true)
    end

    def self.all(config)
      results = [public_ip(config)]
      results << direct_interface_check(config)
      results << direct_dns_check
      results << ipv6_check if config['block_ipv6']
      results << timezone_check(config)
      results << language_check(config)
      results
    end

    def self.direct_interface_check(config)
      iface = System.physical_interface
      _, _, status = System.run('/usr/bin/curl', '-4', '--silent', '--fail', '--max-time', '5', '--interface', iface, '--noproxy', '*', config['check_url'])
      Result.new('direct_interface', !status.success?, status.success? ? "警告：绑定 #{iface} 仍可直连" : "绑定 #{iface} 的直连未成功", true)
    end

    def self.direct_dns_check
      _, _, status = System.run('/usr/bin/dig', '+time=2', '+tries=1', '@8.8.8.8', 'example.com', 'A')
      route = System.route_interface('8.8.8.8')
      if status.success? && !route.to_s.start_with?('utun')
        return Result.new('direct_dns', false, "公共 DNS 请求经 #{route || '未知接口'} 成功，需检查直连", true)
      end
      detail = status.success? ? "公共 DNS 请求由 #{route} 接管" : '公共 DNS 直连未成功'
      Result.new('direct_dns', true, detail, true)
    end

    def self.ipv6_check
      out, _, status = System.run('/usr/bin/curl', '-6', '--silent', '--fail', '--max-time', '5', 'https://api64.ipify.org')
      return Result.new('ipv6', true, 'IPv6 公网直连未成功', true) unless status.success?
      # Under Clash fake-ip the AAAA answer is a TUN address, so the request succeeds
      # through the proxy and the service sees the node's IPv4. Only a real IPv6
      # exit address means traffic left over the local IPv6 uplink.
      exit_ip = out.strip
      if exit_ip.include?(':')
        Result.new('ipv6', false, "IPv6 直连泄漏：出口为 #{exit_ip}", true)
      else
        Result.new('ipv6', true, "IPv6 请求经 TUN 代理，出口 #{exit_ip}", true)
      end
    end

    def self.timezone_check(config)
      actual = System.timezone
      expected = config['expected_timezone']
      Result.new('timezone', actual == expected, "系统时区：#{actual}（期望 #{expected}）", false)
    end

    def self.language_check(config)
      languages = System.chrome_languages
      expected = config['expected_language']
      Result.new('chrome_language', languages.first == expected, "Chrome 语言：#{languages.join(',')}（期望首位 #{expected}）", false)
    end
  end
end
