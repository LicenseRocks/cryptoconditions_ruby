module CryptoconditionsRuby
  module Types
    class Ed25519Fulfillment < Fulfillment
      TYPE_ID = 4
      FEATURE_BITMASK = 0x20
      PUBKEY_LENGTH = 32
      SIGNATURE_LENGTH = 64
      FULFILLMENT_LENGTH = PUBKEY_LENGTH + SIGNATURE_LENGTH

      attr_accessor :public_key, :signature
      private :public_key, :signature
      def initialize(public_key = nil)
        if public_key
          public_key = Crypto::Ed25519VerifyingKey.new(public_key) if public_key.is_a?(String)
          raise TypeError unless public_key.is_a?(Crypto::Ed25519VerifyingKey)
        end
        @public_key = public_key
        @signature = nil
      end

      def write_common_header(writer)
        writer.write_var_octet_string(public_key)
      end

      def sign(message, private_key)
        sk = private_key
        vk = sk.verify_key

        self.public_key = vk

        self.signature = sk.sign(message, 'bytes')
      end

      def generate_hash
        raise ValueError, 'Requires a public publicKey' unless public_key
        public_key.to_s
      end

      def parse_payload(reader, *_args)
        self.public_key = Crypto::Ed25519VerifyingKey.new(
          Utils::Base58.encode(reader.read_octet_string(Ed25519Fulfillment::PUBKEY_LENGTH))
        )
        self.signature = reader.read_octet_string(Ed25519Fulfillment::SIGNATURE_LENGTH)
      end

      def write_payload(writer)
        writer.tap do |w|
          w.write_octet_string(public_key.to_s, Ed25519Fulfillment::PUBKEY_LENGTH)
          w.write_octet_string(signature, Ed25519Fulfillment::SIGNATURE_LENGTH)
        end
      end

      def calculate_max_fulfillment_length
        Ed25519Fulfillment::FULFILLMENT_LENGTH
      end

      def to_dict
        {
          'type' => 'fulfillment',
          'type_id' => TYPE_ID,
          'bitmask' => bitmask,
          'public_key' => Utils::Base58.encode(public_key.to_s),
          'signature' => (Utils::Base58.encode(signature) if signature)
        }
      end

      def parse_dict(data)
        self.public_key = Crypto::Ed25519VerifyingKey.new(data['public_key'])
        self.signature = (Base58.decode(data['signature']) if data['signature'])
      end

      def validate(message = nil, **_kwargs)
        return false unless message && signature
        public_key.verify(signature, message)
      end
    end
  end
end
