require 'base64'

module CryptoconditionsRuby
  CONDITION_REGEX = \
    /^cc:([1-9a-f][0-9a-f]{0,3}|0):[1-9a-f][0-9a-f]{0,15}:[a-zA-Z0-9_-]{0,86}:([1-9][0-9]{0,17}|0)$/

  CONDITION_REGEX_STRICT = \
    /^cc:([1-9a-f][0-9a-f]{0,3}|0):[1-9a-f][0-9a-f]{0,7}:[a-zA-Z0-9_-]{0,86}:([1-9][0-9]{0,17}|0)$/

  class Condition
    extend Crypto::Helpers
    include Crypto::Helpers

    MAX_SAFE_BITMASK = 0xffffffff
    SUPPORTED_BITMASK = 0x3f
    MAX_FULFILLMENT_LENGTH = 65_535
    REGEX = CONDITION_REGEX
    REGEX_STRICT = CONDITION_REGEX_STRICT
    attr_accessor :bitmask, :type_id, :hash, :max_fulfillment_length

    def self.from_uri(serialized_condition)
      return serialized_condition if serialized_condition.is_a?(Condition)
      unless serialized_condition.is_a?(String)
        raise TypeError, 'Serialized condition must be a string'
      end

      pieces = serialized_condition.split(':')
      unless pieces.first == 'cc'
        raise TypeError, 'Serialized condition must start with "cc:"'
      end

      unless serialized_condition.match(CONDITION_REGEX_STRICT)
        raise TypeError, 'Invalid condition format'
      end

      new.tap do |condition|
        condition.type_id = pieces[1].to_i(16)
        condition.bitmask = pieces[2].to_i(16)
        condition.hash = Base64.urlsafe_decode64(base64_add_padding(pieces[3]))
        condition.max_fulfillment_length = pieces[4].to_i
      end
    end

    def self.from_binary(reader)
      reader = Utils::Reader.from_source(reader)
      new.tap do |condition|
        condition.parse_binary(reader)
      end
    end

    def self.from_dict(data)
      new.tap do |condition|
        condition.parse_dict(data)
      end
    end

    def hash
      raise TypeError unless @hash
      @hash
    end

    def max_fulfillment_length
      raise TypeError unless @max_fulfillment_length.is_a?(Integer)
      @max_fulfillment_length
    end

    def serialize_uri
      format(
        'cc:%x:%x:%s:%s',
        type_id,
        bitmask,
        base64_remove_padding(Base64.urlsafe_encode64(hash)),
        max_fulfillment_length
      )
    end

    def serialize_binary
      writer = Utils::Writer.new
      writer.write_uint16(type_id)
      writer.write_var_uint(bitmask)
      writer.write_var_octet_string(hash)
      writer.write_var_uint(max_fulfillment_length)
      writer.buffer
    end

    def parse_binary(reader)
      self.type_id = reader.read_uint16
      self.bitmask = reader.read_var_uint

      self.hash = reader.read_var_octet_string
      self.max_fulfillment_length = reader.read_var_uint
    end

    def to_dict
      {
        'type' => 'condition',
        'type_id' => type_id,
        'bitmask' => bitmask,
        'hash' => Utils::Base58.encode(hash),
        'max_fulfillment_length' => max_fulfillment_length
      }
    end

    def parse_dict(data)
      self.type_id = data['type_id']
      self.bitmask = data['bitmask']

      self.hash = Utils::Base58.encode(data['hash'])
      self.max_fulfillment_length = data['max_fulfillment_length']
    end

    def validate
      TypeRegistry.get_class_from_type_id(type_id)

      if bitmask > Condition::MAX_SAFE_BITMASK
        raise ValueError, 'Bitmask too large to be safely represented'
      end

      if bitmask & ~Condition::SUPPORTED_BITMASK
        raise ValueError, 'Condition requested unsupported feature suites'
      end

      if max_fulfillment_length > Condition::MAX_FULFILLMENT_LENGTH
        raise ValueError, 'Condition requested too large of a max fulfillment size'
      end
      true
    end
  end
end
