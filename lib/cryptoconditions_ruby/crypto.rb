require 'base64'
require 'base32'
require 'rbnacl'

module CryptoconditionsRuby
  module Crypto
    def self.ed25519_generate_key_pair
      sk = Ed25519SigningKey.generate
      private_value_base58 = sk.private_key
      public_value_compressed_base58 = sk.public_key
      [private_value_base58, public_value_compressed_base58]
    end

    def self.base64_add_padding(data)
      data = data.encode('utf-8') if data.is_a?(String)
      missing_padding = (4 - data.length) % 4
      data += '=' * missing_padding if missing_padding
      data
    end

    def self.base64_remove_padding(data)
      data = data.encode('utf-8') if data.is_a?(String)
      data.sub(/=+\Z/, '')
    end

    def get_nacl_encoder(encoding)
      case encoding
      when 'base58' then Base58Encoder
      when 'base64' then Base64Encoder
      when 'base32' then Base32Encoder
      when 'base16' then Base16Encoder
      when 'hex' then HexEncoder
      when 'bytes' then RawEncoder
      else raise UnknownEncodingError.new("Unknown or unsupported encoding")
      end
    end

    class Base58Encoder
      def encode(data)
        CryptoconditionsRuby::Utils::Base58.encode(data)
      end

      def decode(data)
        CryptoconditionsRuby::Utils::Base58.decode(data)
      end
    end

    class Base64Encoder
      def encode(data)
        Base64.encode64(data)
      end

      def decode(data)
        Base64.decode64(data)
      end
    end

    class Base32Encoder
      def encode(data)
        Base32.encode(data)
      end

      def decode(data)
        Base32.decode(data)
      end
    end

    class Base16Encoder
      def encode(data)
        CryptoconditionsRuby::Utils::Base16.encode(data)
      end

      def decode(data)
        CryptoconditionsRuby::Utils::Base16.decode(data)
      end
    end

    class HexEncoder
      def encode(data)
        data.split(//).map(&:ord).map { |c| c.to_s(16) }.join
      end

      def decode(data)
        data.scan(/../).map(&:hex).map(&:chr).join
      end
    end

    class RawEncoder
      def encode(data)
        data
      end

      def decode(data)
        data
      end
    end

    class Ed25519SigningKey
      CryptoKeypair = Struct.new(:private_key, :public_key)

      attr_accessor :key, :encoder
      private :key, :encoder

      def initialize(encoder: Base58Encoder, key: nil)
        @encoder = encoder
        @key = key
      end

      def self.generate
        inst = new
        encoder = Base58Encoder.new

        CryptoKeypair.new(
          encoder.encode(inst.signing_key.to_s),
          encoder.encode(inst.verify_key.to_s)
        )
      end

      def verifying_key
        Ed25519VerifyingKey.new(key: encoder.new.encode(verify_key.to_s), encoder: encoder)
      end

      def sign(data)
        encoder.new.encode(raw_sign(data))
      end

      def raw_sign(data)
        signing_key.sign(data)
      end

      def signing_key
        @signing_key ||= generate_signing_key
      end

      def verify_key
        @verify_key ||= signing_key.verify_key
      end

      def encode
        encoder.encode(signing_key)
      end

      private

      def generate_signing_key
        if key
          ::RbNaCl::SigningKey.new(key)
        else
          ::RbNaCl::SigningKey.generate
        end
      end
    end

    class Ed25519VerifyingKey < ::RbNaCl::VerifyKey
      attr_accessor :encoder
      private :encoder

      def initialize(key: nil, encoder: Base58Encoder)
        @encoder = encoder
        super(encoder.new.decode(key))
      end

      def verify(signature, data)
        super(encoder.new.decode(signature), data)
      rescue ::RbNaCl::BadSignatureError
        false
      end
    end
  end
end
