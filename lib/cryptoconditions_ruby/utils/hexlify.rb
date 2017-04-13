module CryptoconditionsRuby
  module Utils
    module Hexlify
      def hexlify(msg)
        msg.unpack('H*')[0]
      end

      def unhexlify(msg)
        [msg].pack('H*')
      end
    end
  end
end
