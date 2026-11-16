# frozen_string_literal: true
require 'json'
require 'timeout'
require 'ipaddr'
require 'socket'

module NetGuard
  class Checks
    Result = Struct.new(:name, :ok, :detail, :critical, :value) do
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
        return Result.new('public_ip', false, "出口变化：期望 #{expected}，实际 #{ip}", true, ip)
      end
      Result.new('public_ip', true, "终端出口：#{ip}", true, ip)
    end

    def self.all(config)
      results = [public_ip(config)]
      results << direct_interface_check(config)
      results << direct_dns_check
      results << system_dns_check
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

    def self.ipv6_check(locals = Leak.local_ipv6)
      out, _, status = System.run('/usr/bin/curl', '-6', '--silent', '--fail', '--max-time', '5', 'https://api64.ipify.org')
      return Result.new('ipv6', true, 'IPv6 公网直连未成功', true) unless status.success?
      # Under Clash fake-ip the AAAA answer is a TUN address, so the request succeeds
      # through the proxy and the service sees the node's IPv4. Only a real IPv6
      # exit address means traffic left over the local IPv6 uplink.
      # An IPv6 exit is only a leak when it is this Mac's own address/prefix; a
      # proxy node with IPv6 would show its own address instead.
      exit_ip = out.strip
      if Leak.own_ipv6?(exit_ip, locals)
        Result.new('ipv6', false, "IPv6 直连泄漏：出口为本机宽带 IPv6 #{exit_ip}", true)
      elsif exit_ip.include?(':')
        Result.new('ipv6', true, "IPv6 请求经代理，出口为节点 IPv6 #{exit_ip}", true)
      else
        Result.new('ipv6', true, "IPv6 请求经 TUN 代理，出口 #{exit_ip}", true)
      end
    end

    # Under Clash TUN with fake-ip, the system resolver answers from 198.18.0.0/15:
    # every lookup is answered by Clash and none reaches the ISP's DNS server.
    def self.system_dns_check
      answers = Timeout.timeout(5) { Addrinfo.getaddrinfo('example.com', 443, :INET, :STREAM).map(&:ip_address).uniq }
      fake = Resolver::FAKE_IP_RANGE
      if !answers.empty? && answers.all? { |ip| fake.include?(IPAddr.new(ip)) }
        Result.new('system_dns', true, "系统 DNS 由 Clash 接管（fake-ip #{answers.first}），不会发往运营商 DNS", false)
      else
        Result.new('system_dns', false, "系统 DNS 返回真实地址 #{answers.join(',')}：未确认由 Clash 接管（非 fake-ip 模式时属正常，PF 仍拦截直连 DNS）", false)
      end
    rescue StandardError => e
      Result.new('system_dns', false, "系统 DNS 解析失败：#{e.message}", false)
    end

    def self.timezone_check(config)
      actual = System.timezone
      expected = config['expected_timezone']
      Result.new('timezone', actual == expected, "系统时区：#{actual}（期望 #{expected}）", false)
    end

    def self.language_check(config)
      languages = System.chrome_languages
      expected = config['expected_language']
      if languages.empty?
        # macOS privacy (TCC) often blocks reading Chrome's profile; the browser
        # check (--browser) reports the real navigator.languages instead.
        return Result.new('chrome_language', true, "Chrome 语言：设置文件不可读（macOS 隐私限制），以 --browser 实测为准", false)
      end
      Result.new('chrome_language', languages.first == expected, "Chrome 语言：#{languages.join(',')}（期望首位 #{expected}）", false)
    end
  end
end
