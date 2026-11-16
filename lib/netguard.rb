# frozen_string_literal: true
require_relative 'netguard/system'
require_relative 'netguard/resolver'
require_relative 'netguard/geoip'
require_relative 'netguard/config'
require_relative 'netguard/leak'
require_relative 'netguard/checks'
require_relative 'netguard/firewall'
require_relative 'netguard/browser_check'
require_relative 'netguard/monitor'
require_relative 'netguard/cli'

module NetGuard
  VERSION = '0.5.0'
  ROOT = File.expand_path('..', __dir__)
end
