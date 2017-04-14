require 'base64'

module CryptoconditionsRuby
  FULFILLMENT_REGEX = /^cf:([1-9a-f][0-9a-f]{0,3}|0):[a-zA-Z0-9_-]*$/

  class Fulfillment
    extend Crypto::Helpers
    include Crypto::Helpers
    TYPE_ID = nil
    REGEX = FULFILLMENT_REGEX
    FEATURE_BITMASK = nil

    def self.from_uri(serialized_fulfillment)
      return serialized_fulfillment if serialized_fulfillment.is_a?(Fulfillment)

      unless serialized_fulfillment.is_a?(String)
        raise TypeError, 'Serialized fulfillment must be a string'
      end

      pieces = serialized_fulfillment.split(':', -1)

      unless pieces.first == 'cf'
        raise TypeError, 'Serialized fulfillment must start with "cf:"'
      end

      unless serialized_fulfillment.match(Fulfillment::REGEX)
        raise TypeError, 'Invalid fulfillment format'
      end

      type_id = pieces[1].to_i(16)
      payload = Base64.urlsafe_decode64(base64_add_padding(pieces[2]))

      cls = TypeRegistry.get_class_from_type_id(type_id)
      fulfillment = cls.new

      fulfillment.parse_payload(Utils::Reader.from_source(payload), payload.length)
      fulfillment
    end

    def self.from_binary(reader)
      reader = Utils::Reader.from_source(reader)

      cls_type = reader.read_uint16
      cls = TypeRegistry.get_class_from_type_id(cls_type)

      fulfillment = cls
      payload_length = reader.read_length_prefix
      fulfillment.parse_payload(reader, payload_length)
      fulfillment
    end

    def self.from_dict(data)
      cls_type = data['type_id']
      cls = TypeRegistry.get_class_from_type_id(cls_type)
      fulfillment = cls.new
      fulfillment.parse_dict(data)
      fulfillment
    end

    def type_id
      self.class::TYPE_ID
    end

    def bitmask
      self.class::FEATURE_BITMASK
    end

    def condition
      condition = Condition.new
      condition.type_id = type_id
      condition.bitmask = bitmask
      condition.hash = generate_hash
      condition.max_fulfillment_length = calculate_max_fulfillment_length
      condition
    end

    def condition_uri
      condition.serialize_uri
    end

    def condition_binary
      condition.serialize_binary
    end

    def generate_hash
      raise 'Implement me'
    end

    def calculate_max_fulfillment_length
      predictor = Utils::Predictor.new
      write_payload(predictor)
      predictor.size
    end

    def serialize_uri
      format(
        'cf:%x:%s',
        type_id,
        base64_remove_padding(
          Base64.urlsafe_encode64(serialize_payload)
        )
      )
    end

    def serialize_binary
      writer = Utils::Writer.new
      writer.write_uint16(type_id)
      writer.write_var_octet_string(serialize_payload)
      writer.buffer
    end

    def serialize_payload
      writer = Utils::Writer.new
      write_payload(writer)
      writer.buffer
    end

    def write_payload(_writer)
      raise 'Implement me'
    end

    def parse_payload(_reader, *_args)
      raise 'Implement me'
    end

    def to_dict
      raise 'Implement me'
    end

    def parse_dict(_data)
      raise 'Implement me'
    end

    def validate(*_args, **_kwargs)
      raise 'Implement me'
    end
  end
end
