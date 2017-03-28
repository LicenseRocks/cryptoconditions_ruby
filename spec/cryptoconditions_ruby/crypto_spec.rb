require 'spec_helper'

module CryptoconditionsRuby
  describe Crypto do
    describe '.ed25519_generate_key_pair' do
      it 'generates a key pair' do
        expect(described_class.ed25519_generate_key_pair).to be_an(Array)
      end
    end

    describe '.base64_add_padding' do
      it 'adds padding if missing' do
        expect(described_class.base64_add_padding('hi there!')).to eq('hi there!===')
        expect(described_class.base64_add_padding('hi there')).to eq('hi there')
      end
    end

    describe '.base64_removes_padding' do
      it 'removes padding if existing' do
        expect(described_class.base64_remove_padding('hi there!===')).to eq('hi there!')
        expect(described_class.base64_add_padding('hi there')).to eq('hi there')
      end
    end
  end

  module Crypto
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
        it 'returns a base58-encoded crypto key pair' do
          expect(described_class.generate).to respond_to(:private_key)
          expect(described_class.generate).to respond_to(:public_key)
        end
      end

      describe '#verifying_key' do
        it 'returns an Ed25519VerifyingKey instance' do
          expect(described_class.new.verifying_key).to be_a(Ed25519VerifyingKey)
        end
      end

      describe '#sign' do
        subject { described_class.new(key: Array.new(32) { '1' }.join) }

        it 'returns the data, signed and encoded' do
          expect(subject.sign("I'm a little teapot")).to eq(
            'XhCGfdAJtaVeDWVNgJVkgm9dEJxz3gSQEJsnE3PfDjCkMpZ4DV8MGjeRqjtxz1qiB8NT1gvSEZVD5bJj5Q7ZDez'
          )
        end
      end
    end

    describe Ed25519VerifyingKey do
      let(:signing_key) { Ed25519SigningKey.new(key: Array.new(32) { '1' }.join) }
      let(:message) { "I'm a little teapot" }
      let(:signature) { signing_key.sign(message) }
      subject { signing_key.verifying_key }

      describe '#verify' do
        context 'signature check succeeds' do
          it 'returns true' do
            expect(subject.verify(signature, message)).to be true
          end
        end

        context 'signature check succeeds' do
          let(:bad_message) { "I'm a BAD little teapot" }
          it 'returns true' do
            expect(subject.verify(signature, bad_message)).to be false
          end
        end
      end
    end
  end
end
