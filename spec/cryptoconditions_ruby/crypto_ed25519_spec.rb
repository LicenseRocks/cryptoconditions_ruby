require 'spec_helper'

module CryptoconditionsRuby
  context 'Crypto ED25519' do
    context 'signing key encode' do
      let(:sk) { Crypto::Ed25519SigningKey.new(sk_ilp['b64'], 'base64') }

      it 'works' do
        expect(sk.encode('base58')).to eq(sk_ilp['b58'])
      end
    end

    context 'signing key init' do
      let(:sk) { Crypto::Ed25519SigningKey.new(sk_ilp['b64'], 'base64') }

      it 'works' do
        expect(sk.encode('base64')).to eq(sk_ilp['b64'])
        # expect(sk.encode('bytes')).to eq(sk_ilp['byt']) pending figuring out how to assign the bytes
      end
    end

    context 'signing key encode' do
      let(:sk) { Crypto::Ed25519SigningKey.new(sk_ilp['b64'], 'base64') }

      it 'works' do
        expect(sk.encode('base58')).to eq(sk_ilp['b58'])
      end
    end

    context 'signing key init' do
      let(:sk) { Crypto::Ed25519SigningKey.new(sk_ilp['b58']) }

      it 'works' do
        expect(sk.encode('base64')).to eq(sk_ilp['b64'])
        # expect(sk.encode('bytes')).to eq(sk_ilp['byt']) pending figuring out how to assign the bytes
      end
    end

    context 'signing key decode' do
      let(:sk) { Crypto::Ed25519SigningKey.new(sk_ilp['b58']) }

      it 'works' do
        expect(sk.encode('base64')).to eq(sk_ilp['b64'])
      end
    end

    context 'verify key encode' do
      let(:vk) { Crypto::Ed25519VerifyingKey.new(vk_ilp['b64'], 'base64') }

      it 'works' do
        expect(vk.encode('base58')).to eq(vk_ilp['b58'])
      end
    end

    context 'verifying key init' do
      let(:vk) { Crypto::Ed25519VerifyingKey.new(vk_ilp['b64'], 'base64') }

      it 'works' do
        expect(vk.encode('base64')).to eq(vk_ilp['b64'])
        # expect(vk.encode('bytes')).to eq(vk_ilp['byt']) pending figuring out how to assign the bytes
      end
    end

    context 'verifying key decode' do
      let(:vk) { Crypto::Ed25519VerifyingKey.new(vk_ilp['b58']) }

      it 'works' do
        expect(vk.encode('base64')).to eq(vk_ilp['b64'])
      end
    end

    context 'sign verify' do
      let(:message) { 'Hello World!' }
      let(:sk) { Crypto::Ed25519SigningKey.new(sk_ilp['b58']) }
      let(:vk) { Crypto::Ed25519VerifyingKey.new(vk_ilp['b58']) }
      let(:wrong_vk) { Crypto::Ed25519VerifyingKey.new(vk_ilp[2]['b64'], 'base64') }

      it 'works' do
        expect(vk.verify(sk.sign(message), message)).to be_truthy
        expect(vk.verify(sk.sign(message), message + 'foo')).to be_falsey
        expect(vk.verify(sk.sign(message + 'foo'), message)).to be_falsey
        expect(wrong_vk.verify(sk.sign(message), message)).to be_falsey
      end
    end

    context 'to bytes' do
      let(:sk) { Crypto::Ed25519SigningKey.new(sk_ilp['b58']) }
      let(:vk) { Crypto::Ed25519VerifyingKey.new(vk_ilp['b58']) }

      it 'works' do
        expect(sk.encode('base58')).to eq(sk_ilp['b58'])
        expect(sk.encode('base64')).to eq(sk_ilp['b64'])

        expect(vk.encode('base58')).to eq(vk_ilp['b58'])
        expect(vk.encode('base64')).to eq(vk_ilp['b64'])
      end
    end

    context 'get verifying key' do
      let(:sk) { Crypto::Ed25519SigningKey.new(sk_ilp['b58']) }
      let(:vk) { Crypto::Ed25519VerifyingKey.new(vk_ilp['b58']) }
      let(:vk_from_sk) { sk.get_verifying_key }

      it 'works' do
        expect(vk.encode('bytes')).to eq(vk_from_sk.encode('bytes'))
      end
    end

    context 'valid condition valid signature ilp' do
      let(:vk) { Crypto::Ed25519VerifyingKey.new(vk_ilp[2]['b64'], 'base64') }
      let(:msg) { Base64.decode64(signature['msg']) }

      it 'works' do
        expect(vk.verify(signature['sig'], msg, 'base64')).to be_truthy
        expect(
          vk.verify(Utils::Hexlify.hexlify(Base64.decode64(signature['sig'])), msg, 'hex')
        ).to be_truthy
        expect(vk.verify(Base64.decode64(signature['sig']), msg, 'bytes')).to be_truthy
      end
    end

    context 'valid condition invalid signature ilp' do
      let(:vk) { Crypto::Ed25519VerifyingKey.new(vk_ilp[2]['b64'], 'base64') }
      let(:msg) { Base64.decode64(signature['msg']) }

      it 'works'
    end

    context 'generate key pair' do
      let(:receiver) { Class.new { include Crypto::Helpers }.new }

      it 'works' do
        sk_b58, vk_b58 = receiver.ed25519_generate_key_pair
        expect(Utils::Base58.decode(sk_b58).length).to eq(32)
        expect(Utils::Base58.decode(vk_b58).length).to eq(32)
        expect(Crypto::Ed25519SigningKey.new(sk_b58).encode).to eq(sk_b58)
        expect(Crypto::Ed25519VerifyingKey.new(vk_b58).encode).to eq(vk_b58)
      end
    end

    context 'generate sign verify' do
      let(:receiver) { Class.new { include Crypto::Helpers }.new }
      let(:message) { 'Hello world' }

      it 'works' do
        sk_b58, vk_b58 = receiver.ed25519_generate_key_pair
        sk = Crypto::Ed25519SigningKey.new(sk_b58)
        vk = Crypto::Ed25519VerifyingKey.new(vk_b58)

        expect(vk.verify(sk.sign(message), message)).to be_truthy
        expect(vk.verify(sk.sign(message + 'dummy'), message)).to be_falsey
        expect(vk.verify(sk.sign(message), message + 'dummy')).to be_falsey
        vk = Crypto::Ed25519VerifyingKey.new(vk_ilp[2]['b64'], 'base64')
        expect(vk.verify(sk.sign(message), message)).to be_falsey
      end
    end
  end
end
