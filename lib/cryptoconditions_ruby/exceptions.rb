module CryptoconditionsRuby
  module Exceptions
    class ParsingError < StandardError; end
    class UnsupportedTypeError < StandardError; end
    class ValidationError < StandardError; end
    class UnknownEncodingError < StandardError; end
  end
end
