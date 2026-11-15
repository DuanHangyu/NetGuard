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

    def run(wait_seconds = 60)
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
      checks = []
      expected_tz = @config.data['expected_timezone']
      expected_lang = @config.data['expected_language']
      checks << Checks::Result.new('browser_timezone', report['timezone'] == expected_tz, "浏览器时区：#{report['timezone']}", false)
      languages = Array(report['languages'])
      checks << Checks::Result.new('browser_language', languages.first == expected_lang, "浏览器语言：#{languages.join(',')}", false)
      checks
    ensure
      server.close if server && !server.closed?
    end

    private

    def respond(client, status, type, body)
      client.write("HTTP/1.1 #{status} OK\r\nContent-Type: #{type}\r\nContent-Length: #{body.bytesize}\r\nCache-Control: no-store\r\n\r\n#{body}")
    end
  end
end
