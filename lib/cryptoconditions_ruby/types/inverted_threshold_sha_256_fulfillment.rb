module CryptoconditionsRuby
  CONDITION = 'condition'.freeze
  FULFILLMENT = 'fulfillment'.freeze

  module Types
    class InvertedThresholdSha256Fulfillment < ThresholdSha256Fulfillment
      TYPE_ID = 98
      FEATURE_BITMASK = 0x09

      def validate(message = nil, **kwargs)
        !super.validate(message, **kwargs)
      end
    end
  end
end
