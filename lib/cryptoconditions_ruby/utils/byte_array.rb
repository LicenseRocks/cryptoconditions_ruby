module CryptoconditionsRuby
  module Utils
    class ByteArray
      include Enumerable

      def initialize(string_or_array)
        @original = string_or_array
        @collection = string_or_array.is_a?(Array) ? string_or_array : string_or_array.bytes
      end

      def each
        @collection.each
      end
    end
  end
end
