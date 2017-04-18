module CryptoconditionsRuby
  TIMESTAMP_REGEX = /^\d{10}(\.\d+)?$/

  module Types
    class TimeoutFulfillment < PreimageSha256Fulfillment
      TYPE_ID = 99
      FEATURE_BITMASK = 0x09
      REGEX = TIMESTAMP_REGEX

      def self.timestamp(time)
        format('%6f', time.to_f)
      end

      def initialize(expire_time = nil)
        if expire_time.is_a?(String) && !expire_time.match(REGEX)
          raise TypeError, "Expire time must be conform UTC unix time, was: #{expire_time}"
        end
        super if expire_time
      end

      def expire_time
        preimage
      end

      def to_dict
        {
          'type' => 'fulfillment',
          'type_id' => TYPE_ID,
          'bitmask' => bitmask,
          'expire_time' => expire_time
        }
      end

      def parse_dict(data)
        self.preimage = data['expire_time']
      end

      def validate(message = nil, now = nil, **_kwargs)
        unless now || now.match(REGEX)
          raise TypeError, "message must be of unix time format, was: #{message}"
        end
        now.to_f <= expire_time.to_f
      end
    end
  end
end
