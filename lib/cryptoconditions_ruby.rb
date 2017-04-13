require 'cryptoconditions_ruby/version'

module CryptoconditionsRuby
  module Utils
    autoload :Writer, 'cryptoconditions_ruby/utils/writer'
    autoload :Hasher, 'cryptoconditions_ruby/utils/hasher'
    autoload :Predictor, 'cryptoconditions_ruby/utils/predictor'
    autoload :Reader, 'cryptoconditions_ruby/utils/reader'
    autoload :Bytes, 'cryptoconditions_ruby/utils/bytes'
    autoload :Base58, 'cryptoconditions_ruby/utils/base58'
    autoload :Base16, 'cryptoconditions_ruby/utils/base16'
    autoload :Hexlify, 'cryptoconditions_ruby/utils/hexlify'
    autoload :ByteArray, 'cryptoconditions_ruby/utils/byte_array'
  end
  module Types
    autoload :BaseSha256Fulfillment, 'cryptoconditions_ruby/types/base_sha_256_fulfillment'
    autoload :InvertedThresholdSha256Fulfillment, 'cryptoconditions_ruby/types/inverted_threshold_sha_256_fulfillment'
    autoload :PreimageSha256Fulfillment, 'cryptoconditions_ruby/types/preimage_sha_256_fulfillment'
    autoload :TimeoutFulfillment, 'cryptoconditions_ruby/types/timeout_fulfillment'
    autoload :Ed25519Fulfillment, 'cryptoconditions_ruby/types/ed25519_fulfillment'
    autoload :ThresholdSha256Fulfillment, 'cryptoconditions_ruby/types/threshold_sha_256_fulfillment'
  end
  autoload :TypeRegistry, 'cryptoconditions_ruby/type_registry'
  autoload :Crypto, 'cryptoconditions_ruby/crypto'
  autoload :Fulfillment, 'cryptoconditions_ruby/fulfillment'
  autoload :Condition, 'cryptoconditions_ruby/condition'
  autoload :Exceptions, 'cryptoconditions_ruby/exceptions'
end
