# frozen_string_literal: true
require 'ipaddr'

module NetGuard
  # Reads the IPv4 ranges for one country from a v2ray/mihomo geoip.dat — the same
  # file Clash Verge uses for `GEOIP,CN,DIRECT` (geodata-mode: true) — so PF allows
  # exactly the destinations Clash itself sends DIRECT, and nothing broader.
  #
  # Format (protobuf): GeoIPList { repeated GeoIP entry = 1 }
  #   GeoIP { string country_code = 1; repeated CIDR cidr = 2; bool reverse_match = 3 }
  #   CIDR  { bytes ip = 1; uint32 prefix = 2 }
  module GeoIP
    module_function

    def ipv4_cidrs(path, country)
      data = File.binread(path)
      wanted = country.to_s.upcase
      each_field(data, 0, data.bytesize) do |field, wire, value|
        next unless field == 1 && wire == 2
        entry = data.byteslice(value[0], value[1])
        cidrs = parse_entry(entry, wanted)
        return cidrs if cidrs
      end
      raise ArgumentError, "geoip.dat 中没有国家代码 #{wanted}"
    end

    # Returns nil when the entry is another country (stops early, no CIDR parsing).
    def parse_entry(entry, wanted)
      cidrs = []
      each_field(entry, 0, entry.bytesize) do |field, wire, value|
        if field == 1 && wire == 2
          return nil unless entry.byteslice(value[0], value[1]).upcase == wanted
        elsif field == 3 && wire == 0 && value == 1
          raise ArgumentError, "geoip.dat 中 #{wanted} 为反向匹配，无法转换为放行列表"
        elsif field == 2 && wire == 2
          cidr = parse_cidr(entry.byteslice(value[0], value[1]))
          cidrs << cidr if cidr
        end
      end
      cidrs
    end

    def parse_cidr(bytes)
      ip = nil
      prefix = nil
      each_field(bytes, 0, bytes.bytesize) do |field, wire, value|
        ip = bytes.byteslice(value[0], value[1]) if field == 1 && wire == 2
        prefix = value if field == 2 && wire == 0
      end
      return nil unless ip && ip.bytesize == 4
      prefix ||= 32
      # Never let a malformed or absurdly wide entry open large parts of the internet.
      return nil if prefix < 8 || prefix > 32
      address = IPAddr.new(ip.unpack('C4').join('.')).mask(prefix)
      "#{address}/#{prefix}"
    end

    # Yields [field_number, wire_type, value]; length-delimited values are [offset, length].
    def each_field(data, pos, limit)
      while pos < limit
        key, pos = varint(data, pos)
        field = key >> 3
        wire = key & 7
        case wire
        when 0
          value, pos = varint(data, pos)
          yield field, wire, value
        when 2
          length, pos = varint(data, pos)
          raise ArgumentError, 'geoip.dat 已损坏（长度越界）' if pos + length > limit
          yield field, wire, [pos, length]
          pos += length
        when 1 then pos += 8
        when 5 then pos += 4
        else raise ArgumentError, "geoip.dat 已损坏（未知类型 #{wire}）"
        end
      end
    end

    def varint(data, pos)
      result = 0
      shift = 0
      loop do
        byte = data.getbyte(pos)
        raise ArgumentError, 'geoip.dat 已损坏（截断）' if byte.nil?
        pos += 1
        result |= (byte & 0x7f) << shift
        return [result, pos] if byte < 0x80
        shift += 7
      end
    end
  end
end
