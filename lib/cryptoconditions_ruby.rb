require "cryptoconditions_ruby/version"

module CryptoconditionsRuby
  module Utils
    autoload :Writer, 'cryptoconditions_ruby/utils/writer'
    autoload :Hasher, 'cryptoconditions_ruby/utils/hasher'
    autoload :Predictor, 'cryptoconditions_ruby/utils/predictor'
    autoload :Reader, 'cryptoconditions_ruby/utils/reader'
    autoload :Bytes, 'cryptoconditions_ruby/utils/bytes'
  end
  autoload :TypeRegistry, 'cryptoconditions_ruby/type_registry'
end
