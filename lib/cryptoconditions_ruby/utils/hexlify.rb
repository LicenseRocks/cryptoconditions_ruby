module CryptoconditionsRuby
  module Utils
    module Hexlify
      def hexlify(msg)
        msg.split('').collect { |c| c[0].to_s(16) }.join
      end

      def unhexlify(msg)
        msg.scan(/../).collect { |c| c.to_i(16).chr }.join
      end
    end
  end
end
