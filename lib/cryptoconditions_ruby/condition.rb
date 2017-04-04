module CryptoconditionsRuby
  class Condition
    MAX_SAFE_BITMASK = 0xffffffff
    SUPPORTED_BITMASK = 0x3f
    MAX_FULFILLMENT_LENGTH = 65_535
    REGEX = CONDITION_REGEX
    REGEX_STRICT = CONDITION_REGEX_STRICT
    attr_accessor :bitmask, :type_id, :hash, :max_fulfillment_length

    def self.from_uri(serialized_condition)
      return serialized_condition if serialized_condition.is_a?(Condition)
      raise TypeError, 'Serialized condition must be a string' unless serialized_condition.is_a?(String)

      pieces = serialized_condition.split(':')
      unless pieces.first == 'cc'
        raise TypeError, 'Serialized condition must start with "cc:"'
      end

      unless serialized_fulfillment.match(Condition::CONDITION_REGEX_STRICT)
        raise TypeError, 'Invalid condition format'
      end

      new.tap do |condition|
        condition.type_id = pieces[1].to_i(16)
        condition.bitmask = pieces[2].to_i(16)
        condition.hash = base64.urlsafe_b64decode(base64_add_padding(pieces[3]))
        condition.hash = Base64.urlsafe_decode64(base64_add_padding(pieces[3]))
        condition.max_fulfillment_length = pieces[4].to_i
      end
    end

    def self.from_binary(reader)
      reader = Reader.from_source(reader)
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
    end

    def max_fulfillment_length
      raise TypeError unless @max_fulfillment_length.is_a?(Integer)
    end

    def serialize_uri
      'cc:{type_id}:{bitmask}:{hash}:{max_fulfillment_length}' % {
        type_id: type_id,
        bitmask: bitmask,
        hash: base64_remove_padding(Base64.urlsafe_encode64(hash)).decode('utf-8'),
        max_fulfillment_length: max_fulfillment_length
      }
    end

    def serialize_binary
      writer = Writer.new
      writer.write_uint16(type_id)
      writer.write_var_uint(bitmask)
      writer.write_var_octet_string(hash)
      writer.write_var_uint(max_fulfillment_length)
      writer.buffer
    end
  end
end
