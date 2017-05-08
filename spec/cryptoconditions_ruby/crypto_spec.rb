require 'spec_helper'

module CryptoconditionsRuby
  module Crypto
    describe Helpers do
      let(:klass) { Class.new { include Helpers } }

      describe 'ed25519_generate_key_pair' do
        it 'generates a key pair' do
          expect(klass.new.ed25519_generate_key_pair).to be_an(Array)
        end
      end

      describe 'base64_add_padding' do
        it 'adds padding if missing' do
          expect(klass.new.base64_add_padding('hi there!')).to eq('hi there!===')
          expect(klass.new.base64_add_padding('hi there')).to eq('hi there')
        end
      end

      describe 'base64_removes_padding' do
        it 'removes padding if existing' do
          expect(klass.new.base64_remove_padding('hi there!===')).to eq('hi there!')
          expect(klass.new.base64_add_padding('hi there')).to eq('hi there')
        end
      end
    end

    context 'encoders' do
      shared_examples 'an encoder and decoder' do
        let(:message) do
          'Oh I do like to be beside the seaside! 1, 2, 3, 4, 5 - once I caught a FISH'
        end
        let(:encoder) { described_class.new }
        let(:encoded_message) { encoder.encode(message) }

        it 'decodes the encoded message' do
          expect(encoder.decode(encoded_message)).to eq(message)
        end
      end

      describe(Base58Encoder) { it_behaves_like 'an encoder and decoder' }
      describe(Base64Encoder) { it_behaves_like 'an encoder and decoder' }
      describe(Base32Encoder) { it_behaves_like 'an encoder and decoder' }
      describe(Base16Encoder) { it_behaves_like 'an encoder and decoder' }
      describe(HexEncoder) { it_behaves_like 'an encoder and decoder' }
      describe(RawEncoder) { it_behaves_like 'an encoder and decoder' }
    end

    describe Ed25519SigningKey do
      describe '.generate' do
        it 'returns a key pair' do
          expect(described_class.generate.to_s.encoding).to eq(Encoding::ASCII_8BIT)
          expect(described_class.generate.verify_key.to_s.encoding).to eq(Encoding::ASCII_8BIT)
        end
      end

      describe '#verifying_key' do
        it 'returns an Ed25519VerifyingKey instance' do
          expect(described_class.generate.verify_key).to be_a(RbNaCl::Signatures::Ed25519::VerifyKey)
        end
      end

      describe '#sign' do
        subject { described_class.new(Array.new(32) { '1' }.join) }

        it 'returns the data, signed and encoded' do
          expect(subject.sign("I'm a little teapot")).to eq(
            '3AHi496wasLgG7U8ZBsJz3cTTvxBqYwVPXubafmJgRNJ26rkV8fXG2ZmN4UkJYvrnLxYDamXZJGd5iuQGLEz3oUq'
          )
        end
      end
    end

    describe Ed25519VerifyingKey do
      let(:signing_key) { Ed25519SigningKey.new(Array.new(32) { '1' }.join) }
      let(:message) { "I'm a little teapot" }
      let(:signature) { signing_key.sign(message) }
      subject { signing_key.verify_key }

      describe '#verify' do
        context 'signature check succeeds' do
          it 'returns true' do
            expect(subject.verify(Utils::Base58.decode(signature), message)).to be true
          end
        end

        context 'signature check succeeds' do
          let(:bad_message) { "I'm a BAD little teapot" }
          it 'returns true' do
            expect { subject.verify(Utils::Base58.decode(signature), bad_message) }
              .to raise_error(RbNaCl::BadSignatureError)
          end
        end
      end
    end
  end
end
