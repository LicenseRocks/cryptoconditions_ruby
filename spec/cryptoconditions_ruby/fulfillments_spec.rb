require 'spec_helper'

module CryptoconditionsRuby
  MESSAGE = 'Hello World! Conditions are here!'.freeze

  context 'Sha256Condition' do
    let(:example_condition) { fulfillment_sha256['condition_uri'] }

    context 'test_deserialize_condition' do
      let(:condition) { Condition.from_uri(example_condition) }

      it 'returns the fulfillment condition uri' do
        expect(condition.serialize_uri).to eq(example_condition)
      end
    end

    context 'test_create_condition' do
      let(:condition) { Condition.new }
      before do
        condition.type_id = Types::PreimageSha256Fulfillment::TYPE_ID
        condition.bitmask = Types::PreimageSha256Fulfillment::FEATURE_BITMASK
        condition.hash = unhexlify(fulfillment_sha256['condition_hash'])
        condition.max_fulfillment_length = 0
      end

      it 'returns the fulfillment condition uri' do
        expect(condition.serialize_uri).to eq(example_condition)
      end
    end
  end

  context 'Sha256Fulfillment' do
    before do
      TypeRegistry.register_type(Types::PreimageSha256Fulfillment)
      TypeRegistry.register_type(Types::ThresholdSha256Fulfillment)
      TypeRegistry.register_type(Types::InvertedThresholdSha256Fulfillment)
      TypeRegistry.register_type(Types::Ed25519Fulfillment)
      TypeRegistry.register_type(Types::TimeoutFulfillment)
    end

    let(:example_condition) { fulfillment_sha256['condition_uri'] }
    let(:example_fulfillment) { fulfillment_sha256['fulfillment_uri'] }
    let(:fulfillment) { Fulfillment.from_uri(example_fulfillment) }

    context 'test_deserialize_and_validate_fulfillment' do
      it 'deserializes and validates' do
        expect(fulfillment.serialize_uri).to eq(example_fulfillment)
        expect(fulfillment.condition.serialize_uri).to eq(example_condition)
        expect(fulfillment.validate).to be_truthy
      end
    end

    context 'test_fulfillment_serialize_to_dict' do
      let(:parsed_fulfillment) { Fulfillment.from_dict(fulfillment.to_dict) }

      it 'displays the fulfillment in a hash format' do
        expect(parsed_fulfillment.serialize_uri).to eq(fulfillment.serialize_uri)
        expect(parsed_fulfillment.condition.serialize_uri).to eq(fulfillment.condition.serialize_uri)
        expect(parsed_fulfillment.to_dict).to eq(fulfillment.to_dict)
      end
    end

    context 'test_deserialize_condition_and_validate_fulfillment' do
      let(:condition) { Condition.from_uri(fulfillment_sha256['condition_uri']) }
      let(:fulfillment) { Types::PreimageSha256Fulfillment.new }

      before { fulfillment.preimage = '' }

      it 'validates' do
        expect(fulfillment.serialize_uri).to eq(fulfillment_sha256['fulfillment_uri'])
        expect(fulfillment.condition.serialize_uri).to eq(condition.serialize_uri)
        expect(fulfillment.validate).to be_truthy
      end
    end

    context 'test_condition_from_fulfillment' do
      let(:fulfillment) { Types::PreimageSha256Fulfillment.new }
      let(:verify_fulfillment) { Types::PreimageSha256Fulfillment.new }
      let(:condition) { fulfillment.condition }

      before do
        expect { fulfillment.condition }.to raise_error(TypeError)
        fulfillment.preimage = 'Hello World!'
        verify_fulfillment.preimage = 'Hello World!'
      end

      it 'validates' do
        expect(verify_fulfillment.condition.serialize_uri).to eq(condition.serialize_uri)
        expect(verify_fulfillment.validate).to be_truthy
      end
    end
  end

  context 'Ed25519Fulfillment' do
    before do
      TypeRegistry.register_type(Types::PreimageSha256Fulfillment)
      TypeRegistry.register_type(Types::ThresholdSha256Fulfillment)
      TypeRegistry.register_type(Types::InvertedThresholdSha256Fulfillment)
      TypeRegistry.register_type(Types::Ed25519Fulfillment)
      TypeRegistry.register_type(Types::TimeoutFulfillment)
    end

    context 'test_ilp_keys' do
      let(:sk) { Crypto::Ed25519SigningKey.new(sk_ilp['b58']) }
      let(:vk) { Crypto::Ed25519VerifyingKey.new(vk_ilp['b58']) }

      it 'returns a correctly encoded signing key' do
        expect(sk.encode('base64')).to eq(sk_ilp['b64'])
        expect(hexlify(sk.encode('bytes').slice(0...32))).to eq(sk_ilp['hex'])
      end
    end

    context 'test create' do
      let(:fulfillment1) { Types::Ed25519Fulfillment.new(vk_ilp['b58']) }
      let(:vk) { Crypto::Ed25519VerifyingKey.new(vk_ilp['b58']) }
      let(:fulfillment2) { Types::Ed25519Fulfillment.new(vk) }

      it 'works' do
        expect(fulfillment1.condition.serialize_uri).to eq(fulfillment2.condition.serialize_uri)
      end
    end

    context 'serialize condition and validate fulfillment' do
      let(:sk) { Crypto::Ed25519SigningKey.new(sk_ilp['b58']) }
      let(:vk) { Crypto::Ed25519VerifyingKey.new(vk_ilp['b58']) }
      let(:fulfillment) { Types::Ed25519Fulfillment.new(vk) }

      it 'works' do
        expect(fulfillment.condition.serialize_uri).to eq(fulfillment_ed25519['condition_uri'])
        expect(hexlify(fulfillment.condition.hash)).to eq(fulfillment_ed25519['condition_hash'])
        expect(fulfillment.validate).to be_falsey

        fulfillment.sign(MESSAGE, sk)

        expect(fulfillment.serialize_uri).to eq(fulfillment_ed25519['fulfillment_uri'])
        expect(fulfillment.validate(MESSAGE)).to be_truthy
      end
    end

    context 'deserialize condition' do
      let(:deserialized_condition) { Condition.from_uri(fulfillment_ed25519['condition_uri']) }

      it 'works' do
        expect(deserialized_condition.serialize_uri).to eq(fulfillment_ed25519['condition_uri'])
        expect(hexlify(deserialized_condition.hash)).to eq(fulfillment_ed25519['condition_hash'])
      end
    end

    context 'serialize signed dict to fulfillment' do
      let(:fulfillment) { Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri']) }

      it 'works' do
        expect(fulfillment.to_dict).to eq(
          'bitmask' => 32,
          'public_key' => 'Gtbi6WQDB6wUePiZm8aYs5XZ5pUqx9jMMLvRVHPESTjU',
          'signature' => '4eCt6SFPCzLQSAoQGW7CTu3MHdLj6FezSpjktE7tHsYGJ4pNSUnpHtV9XgdHF2XYd62M9fTJ4WYdhTVck27qNoHj',
          'type' => 'fulfillment',
          'type_id' => 4
        )

        expect(fulfillment.validate(MESSAGE)).to be_truthy
      end
    end

    context 'serialize unsigned dict to fulfillment' do
      let(:fulfillment) { Types::Ed25519Fulfillment.new(vk_ilp['b58']) }

      it 'fails' do
        expect(fulfillment.to_dict).to eq(
          'bitmask' => 32,
          'public_key' => 'Gtbi6WQDB6wUePiZm8aYs5XZ5pUqx9jMMLvRVHPESTjU',
          'signature' => nil,
          'type' => 'fulfillment',
          'type_id' => 4
        )

        expect(fulfillment.validate(MESSAGE)).to be_falsey
      end
    end

    context 'deserialize signed dict to fulfillment' do
      let(:fulfillment) { Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri']) }
      let(:parsed_fulfillment) { Fulfillment.from_dict(fulfillment.to_dict) }

      it 'works' do
        expect(parsed_fulfillment.serialize_uri).to eq(fulfillment.serialize_uri)
        expect(parsed_fulfillment.condition.serialize_uri).to eq(fulfillment.condition.serialize_uri)
        expect(parsed_fulfillment.to_dict).to eq(fulfillment.to_dict)
      end
    end

    context 'deserialize unsigned dict to fulfillment' do
      let(:fulfillment) { Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri']) }
      let(:parsed_fulfillment) { Fulfillment.from_dict(fulfillment.to_dict) }

      it 'works' do
        expect(parsed_fulfillment.condition.serialize_uri).to eq(fulfillment.condition.serialize_uri)
        expect(parsed_fulfillment.to_dict).to eq(fulfillment.to_dict)
      end
    end

    context 'serialize deserialized condition' do
      let(:vk) { Crypto::Ed25519VerifyingKey.new(vk_ilp['b58']) }
      let(:fulfillment) { Types::Ed25519Fulfillment.new(vk) }
      let(:condition) { fulfillment.condition }
      let(:deserialized_condition) { Condition.from_uri(condition.serialize_uri) }

      it 'works' do
        expect(deserialized_condition.bitmask).to eq(condition.bitmask)
        expect(deserialized_condition.hash).to eq(condition.hash)
        expect(deserialized_condition.max_fulfillment_length).to eq(condition.max_fulfillment_length)
        expect(deserialized_condition.serialize_uri).to eq(condition.serialize_uri)
      end
    end

    context 'deserialize fulfillment' do
      let(:fulfillment) { Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri']) }

      it 'works' do
        expect(fulfillment).to be_a(Types::Ed25519Fulfillment)
        expect(fulfillment.serialize_uri).to eq(fulfillment_ed25519['fulfillment_uri'])
        expect(fulfillment.condition.serialize_uri).to eq(fulfillment_ed25519['condition_uri'])
        expect(hexlify(fulfillment.condition.hash)).to eq(fulfillment_ed25519['condition_hash'])
        expect(Crypto::HexEncoder.new.encode(fulfillment.public_key)).to eq(vk_ilp['hex'])
        expect(fulfillment.validate(MESSAGE)).to be_truthy
      end
    end

    context 'deserialize fulfillment 2' do
      let(:fulfillment) { Fulfillment.from_uri(fulfillment_ed25519_2['fulfillment_uri']) }
      it 'works' do
        expect(fulfillment).to be_a(Types::Ed25519Fulfillment)
        expect(fulfillment.serialize_uri).to eq(fulfillment_ed25519_2['fulfillment_uri'])
        expect(fulfillment.condition.serialize_uri).to eq(fulfillment_ed25519_2['condition_uri'])
        expect(hexlify(fulfillment.condition.hash)).to eq(fulfillment_ed25519_2['condition_hash'])
        expect(Crypto::HexEncoder.new.encode(fulfillment.public_key)).to eq(vk_ilp[2]['hex'])
        expect(fulfillment.validate(MESSAGE)).to be_truthy
      end
    end

    context 'serialize a deserialized fulfillment' do
      let(:sk) { Crypto::Ed25519SigningKey.new(sk_ilp['b58']) }
      let(:vk) { Crypto::Ed25519VerifyingKey.new(vk_ilp['b58']) }
      let(:fulfillment) { Types::Ed25519Fulfillment.new(vk) }
      let(:deserialized_fulfillment) { Fulfillment.from_uri(fulfillment.serialize_uri) }

      it 'works' do
        fulfillment.sign(MESSAGE, sk)

        expect(fulfillment.validate(MESSAGE)).to be_truthy
        expect(deserialized_fulfillment.serialize_uri).to eq(fulfillment.serialize_uri)
        expect(deserialized_fulfillment.condition.serialize_uri).to eq(fulfillment.condition.serialize_uri)
        expect(deserialized_fulfillment.public_key).to eq(fulfillment.public_key)
        expect(deserialized_fulfillment.validate(MESSAGE)).to be_truthy
      end
    end
  end
end
