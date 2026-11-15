# frozen_string_literal: true
require 'open3'
require 'json'
require 'socket'

module NetGuard
  module System
    module_function

    def run(*args)
      Open3.capture3(*args)
    end

    def command?(name)
      system('command', '-v', name, out: File::NULL, err: File::NULL)
    end

    def root?
      Process.uid.zero?
    end

    def user_home
      sudo_user = ENV['SUDO_USER']
      return Dir.home(sudo_user) if sudo_user && !sudo_user.empty?
      Dir.home
    rescue ArgumentError
      Dir.home
    end

    def default_interface
      out, = run('/sbin/route', '-n', 'get', 'default')
      out[/interface:\s*(\S+)/, 1] || 'en0'
    rescue StandardError
      'en0'
    end

    # The real uplink (en0 etc.), never the Clash TUN, even while auto-route is on.
    def physical_interface
      out, = run('/usr/sbin/scutil', stdin_data: "show State:/Network/Global/IPv4\n")
      primary = out[/PrimaryInterface\s*:\s*(\S+)/, 1]
      return primary if primary && !primary.start_with?('utun')
      route = default_interface
      route.start_with?('utun') ? 'en0' : route
    rescue StandardError
      'en0'
    end

    def interface_index(name)
      Socket.getifaddrs.find { |i| i.name == name }&.ifindex
    rescue StandardError
      nil
    end

    def route_interface(ip)
      out, = run('/sbin/route', '-n', 'get', ip)
      out[/interface:\s*(\S+)/, 1]
    rescue StandardError
      nil
    end

    def interfaces
      out, = run('/sbin/ifconfig', '-l')
      out.split
    rescue StandardError
      []
    end

    def interface_address(name)
      out, = run('/sbin/ifconfig', name)
      out
    rescue StandardError
      ''
    end

    def tun_interfaces
      interfaces.select do |name|
        next false unless name.start_with?('utun')
        text = interface_address(name)
        text.include?('198.18.') || text.include?('172.19.') || text.include?('172.20.') || text.include?('198.51.100.')
      end
    end

    def detect_tun(configured = 'auto')
      return configured if configured && configured != 'auto'
      tun_interfaces.first
    end

    def timezone
      File.readlink('/etc/localtime').sub(%r{^.*/zoneinfo/}, '')
    rescue StandardError
      'unknown'
    end

    def chrome_preferences
      path = File.join(user_home, 'Library/Application Support/Google/Chrome/Default/Preferences')
      JSON.parse(File.read(path))
    rescue StandardError
      {}
    end

    def chrome_languages
      prefs = chrome_preferences
      intl = prefs['intl'] || {}
      value = intl['accept_languages'] || intl['selected_languages'] || ''
      value.split(',').map(&:strip).reject(&:empty?)
    end

    def pf_enabled?
      out, = run('/sbin/pfctl', '-s', 'info')
      out.include?('Status: Enabled')
    rescue StandardError
      false
    end
  end
end
