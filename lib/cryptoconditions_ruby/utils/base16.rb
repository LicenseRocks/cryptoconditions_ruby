module CryptoconditionsRuby
  module Utils
    class Base16
      def self.encode(data)
        ret = ''
        data.each_char do |c|
          ch = c.ord.to_s(16)
          ch = '0' + ch if ch.size == 1
          ret += ch
        end
        ret.upcase
      end

      def self.decode(data)
        chars = ''
        ret = ''
        data.each_char do |c|
          chars += c
          if chars.size == 2
            ret += chars.to_i(16).chr
            chars = ''
          end
        end
        ret
      end
    end
  end
end
