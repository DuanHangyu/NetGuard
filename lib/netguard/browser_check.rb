# frozen_string_literal: true
require 'socket'
require 'json'
require 'timeout'
require 'uri'

module NetGuard
  class BrowserCheck
    def initialize(config, web_root)
      @config = config
      @web_root = web_root
    end

    def run(wait_seconds = 60, exit_ip: nil)
      server = TCPServer.new('127.0.0.1', 0)
      port = server.addr[1]
      report = nil
      thread = Thread.new do
        Timeout.timeout(wait_seconds) do
          while report.nil?
            client = server.accept
            request_line = client.gets
            next client.close unless request_line
            method, path, = request_line.split
            headers = {}
            while (line = client.gets)
              break if line.strip.empty?
              key, value = line.split(':', 2)
              headers[key.downcase] = value.to_s.strip
            end
            if method == 'POST' && path == '/report'
              length = headers['content-length'].to_i
              body = client.read(length)
              report = JSON.parse(body)
              respond(client, 200, 'application/json', '{"ok":true}')
            elsif method == 'GET' && path == '/'
              html = File.read(File.join(@web_root, 'diagnostics.html'))
              respond(client, 200, 'text/html; charset=utf-8', html)
            else
              respond(client, 404, 'text/plain', 'Not found')
            end
            client.close
          end
        end
      rescue Timeout::Error
        nil
      end
      system('/usr/bin/open', '-a', 'Google Chrome', "http://127.0.0.1:#{port}/")
      thread.join(wait_seconds + 2)
      raise RuntimeError, '等待浏览器报告超时' unless report
      evaluate(report, exit_ip)
    ensure
      server.close if server && !server.closed?
    end

    # Pure: turns the page's report into results. exit_ip is the terminal's proxy
    # exit (nil when unknown).
    def evaluate(report, exit_ip, locals = Leak.local_ipv6)
      checks = []
      expected_tz = @config.data['expected_timezone'].to_s
      expected_tz = System.timezone if expected_tz.empty?
      checks << Checks::Result.new('browser_timezone', report['timezone'] == expected_tz,
                                   "浏览器时区：#{report['timezone']}（期望 #{expected_tz}）", false)
      languages = Array(report['languages'])
      expected_lang = @config.data['expected_language'].to_s
      lang_ok = expected_lang.empty? || languages.first == expected_lang
      checks << Checks::Result.new('browser_language', lang_ok,
                                   "浏览器语言：#{languages.join(',')}#{expected_lang.empty? ? '' : "（期望首位 #{expected_lang}）"}", false)
      checks << browser_exit(report['browser_ipv4'], exit_ip)
      checks << browser_ipv6(report['browser_ipv6'], exit_ip, locals)
      checks << webrtc(report['webrtc'] || {}, exit_ip, locals)
      checks
    end

    private

    def browser_exit(ip, exit_ip)
      return Checks::Result.new('browser_exit', false, '浏览器无法获取 IPv4 出口（代理断开或被拦截）', false) if ip.to_s.empty?
      if exit_ip && ip != exit_ip
        return Checks::Result.new('browser_exit', false, "浏览器出口 #{ip} 与终端出口 #{exit_ip} 不同：浏览器走了别的路径", true)
      end
      Checks::Result.new('browser_exit', true, "浏览器出口：#{ip}#{exit_ip ? '（与终端一致）' : ''}", true)
    end

    def browser_ipv6(ip, exit_ip, locals)
      return Checks::Result.new('browser_ipv6', true, '浏览器 IPv6 直连未成功', true) if ip.to_s.empty?
      if Leak.own_ipv6?(ip, locals)
        return Checks::Result.new('browser_ipv6', false, "浏览器 IPv6 泄漏：出口为本机宽带 IPv6 #{ip}", true)
      end
      Checks::Result.new('browser_ipv6', true, "浏览器 IPv6 请求经代理（#{ip}）", true)
    end

    def webrtc(rtc, exit_ip, locals)
      return Checks::Result.new('webrtc', true, '浏览器不支持 WebRTC', true) if rtc['supported'] == false
      addresses = Array(rtc['candidates']).map { |c| c['address'].to_s }.uniq
      leaked = addresses.select { |ip| Leak.exposes_real_ip?(ip, exit_ip, locals) }
      unless leaked.empty?
        return Checks::Result.new('webrtc', false, "WebRTC 泄漏真实 IP：#{leaked.join(', ')}", true)
      end
      seen = addresses.select { |ip| Leak.public?(ip) }
      detail = seen.empty? ? 'WebRTC 未暴露任何公网 IP（STUN 未获得地址）' : "WebRTC 只看到代理出口 #{seen.join(', ')}"
      Checks::Result.new('webrtc', true, detail, true)
    end

    def respond(client, status, type, body)
      client.write("HTTP/1.1 #{status} OK\r\nContent-Type: #{type}\r\nContent-Length: #{body.bytesize}\r\nCache-Control: no-store\r\n\r\n#{body}")
    end
  end
end
