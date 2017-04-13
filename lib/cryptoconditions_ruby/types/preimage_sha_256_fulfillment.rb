module CryptoconditionsRuby
  module Types
    class PreimageSha256Fulfillment < BaseSha256Fulfillment
      TYPE_ID = 0
      FEATURE_BITMASK = 0x03

      attr_accessor :preimage
      private :preimage
      def initialize(preimage = nil)
        if preimage && !preimage.respond_to?(:bytes)
          raise TypeError, "Preimage must be bytes, was #{preimage.class.name}"
        end
        @preimage = preimage
      end

      def bitmask
        FEATURE_BITMASK
      end

      def write_hash_payload(hasher)
        unless hasher.is_a?(Utils::Hasher)
          raise TypeError, 'hasher must be a Hasher instance'
        end
        unless preimage
          raise TypeError, 'Could not calculate hash, no preimage provided'
        end
        hasher.write(preimage)
      end

      def parse_payload(reader, payload_size)
        unless reader.is_a?(Utils::Reader)
          raise TypeError, 'reader must be a Reader instance'
        end
        self.preimage = reader.read(payload_size)
      end

      def write_payload(writer)
        unless [Utils::Writer, Utils::Predictor].include?(writer.class)
          raise TypeError, 'writer must be a Writer instance'
        end
        raise TypeError, 'Preimage must be specified' unless preimage
        writer.write(preimage)
        writer
      end

      def to_dict
        {
          'type' => 'fulfillment',
          'type_id' => TYPE_ID,
          'bitmask' => bitmask,
          'preimage' => preimage
        }
      end

      def parse_dict(data)
        self.preimage = data['preimage'].encode
      end

      def validate(*_args, **_kwargs)
        true
      end
    end
  end
end
