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
        expect(fulfillment.validate(message: MESSAGE)).to be_truthy
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

        expect(fulfillment.validate(message: MESSAGE)).to be_truthy
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

        expect(fulfillment.validate(message: MESSAGE)).to be_falsey
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
        expect(fulfillment.validate(message: MESSAGE)).to be_truthy
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
        expect(fulfillment.validate(message: MESSAGE)).to be_truthy
      end
    end

    context 'serialize a deserialized fulfillment' do
      let(:sk) { Crypto::Ed25519SigningKey.new(sk_ilp['b58']) }
      let(:vk) { Crypto::Ed25519VerifyingKey.new(vk_ilp['b58']) }
      let(:fulfillment) { Types::Ed25519Fulfillment.new(vk) }
      let(:deserialized_fulfillment) { Fulfillment.from_uri(fulfillment.serialize_uri) }

      it 'works' do
        fulfillment.sign(MESSAGE, sk)

        expect(fulfillment.validate(message: MESSAGE)).to be_truthy
        expect(deserialized_fulfillment.serialize_uri).to eq(fulfillment.serialize_uri)
        expect(deserialized_fulfillment.condition.serialize_uri).to eq(fulfillment.condition.serialize_uri)
        expect(deserialized_fulfillment.public_key).to eq(fulfillment.public_key)
        expect(deserialized_fulfillment.validate(message: MESSAGE)).to be_truthy
      end
    end
  end

  context 'ThresholdSha256Fulfillment' do
    before do
      TypeRegistry.register_type(Types::PreimageSha256Fulfillment)
      TypeRegistry.register_type(Types::ThresholdSha256Fulfillment)
      TypeRegistry.register_type(Types::InvertedThresholdSha256Fulfillment)
      TypeRegistry.register_type(Types::Ed25519Fulfillment)
      TypeRegistry.register_type(Types::TimeoutFulfillment)
    end

    let(:fulfillment_ed25519sha256) do
      sk = Crypto::Ed25519SigningKey.new(sk_ilp['b58'])
      vk = Crypto::Ed25519VerifyingKey.new(vk_ilp['b58'])

      Types::Ed25519Fulfillment.new(vk).tap { |f| f.sign(MESSAGE, sk) }
    end

    context 'serialize condition and validate fulfillment' do
      let(:ilp_fulfillment_ed25519) { Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri']) }
      let(:ilp_fulfillment_sha) { Fulfillment.from_uri(fulfillment_sha256['fulfillment_uri']) }
      let(:threshold) { 1 }
      let(:fulfillment) { Types::ThresholdSha256Fulfillment.new(threshold) }

      before do
        fulfillment.add_subfulfillment(ilp_fulfillment_ed25519)
        fulfillment.add_subfulfillment(ilp_fulfillment_sha)
      end

      it 'works' do
        expect(ilp_fulfillment_ed25519.validate(message: MESSAGE)).to be_truthy
        expect(ilp_fulfillment_sha.validate(message: MESSAGE)).to be_truthy
        expect(fulfillment.condition.serialize_uri).to eq(fulfillment_threshold['condition_uri'])
        expect(fulfillment.serialize_uri).to eq(fulfillment_threshold['fulfillment_uri'])
        expect(fulfillment.validate(message: MESSAGE)).to be_truthy
      end
    end

    context 'deserialize fulfillment' do
      let(:num_fulfillments) { 2 }
      let(:threshold) { 1 }

      let(:fulfillment) { Fulfillment.from_uri(fulfillment_threshold['fulfillment_uri']) }

      it 'works' do
        expect(fulfillment).to be_a(Types::ThresholdSha256Fulfillment)
        expect(fulfillment.threshold).to eq(threshold)
        expect(fulfillment.subconditions.select { |f| f['type'] == 'fulfillment' }.length).to eq(threshold)
        expect(fulfillment.serialize_uri).to eq(fulfillment_threshold['fulfillment_uri'])
        expect(fulfillment.subconditions.length).to eq(num_fulfillments)
        expect(fulfillment.validate(message: MESSAGE)).to be_truthy
      end
    end

    context 'serialize signed dict to fulfillment' do
      let(:fulfillment) { Fulfillment.from_uri(fulfillment_threshold['fulfillment_uri']) }

      it 'works' do
        expect(fulfillment.to_dict).to eq(
          'bitmask' => 43,
          'subfulfillments' => [
            {
              'bitmask' => 3,
              'preimage' => '',
              'type' => 'fulfillment',
              'type_id' => 0,
              'weight' => 1
            },
            {
              'bitmask' => 32,
              'hash' => 'Gtbi6WQDB6wUePiZm8aYs5XZ5pUqx9jMMLvRVHPESTjU',
              'max_fulfillment_length' => 96,
              'type' => 'condition',
              'type_id' => 4,
              'weight' => 1
            }
          ],
          'threshold' => 1,
          'type' => 'fulfillment',
          'type_id' => 2
        )
      end
    end

    context 'serialize unsigned dict to fulfillment' do
      let(:threshold) { 1 }
      let(:fulfillment) { Types::ThresholdSha256Fulfillment.new(threshold) }

      before do
        fulfillment.add_subfulfillment(Types::Ed25519Fulfillment.new(Crypto::Ed25519VerifyingKey.new(vk_ilp['b58'])))
        fulfillment.add_subfulfillment(Types::Ed25519Fulfillment.new(Crypto::Ed25519VerifyingKey.new(vk_ilp['b58'])))
      end

      it 'works' do
        expect(fulfillment.to_dict).to eq(
          'bitmask' => 41,
          'subfulfillments' => [
            {
              'bitmask' => 32,
              'public_key' => 'Gtbi6WQDB6wUePiZm8aYs5XZ5pUqx9jMMLvRVHPESTjU',
              'signature' => nil,
              'type' => 'fulfillment',
              'type_id' => 4,
              'weight' => 1
            },
            {
              'bitmask' => 32,
              'public_key' => 'Gtbi6WQDB6wUePiZm8aYs5XZ5pUqx9jMMLvRVHPESTjU',
              'signature' => nil,
              'type' => 'fulfillment',
              'type_id' => 4,
              'weight' => 1
            }
          ],
          'threshold' => 1,
          'type' => 'fulfillment',
          'type_id' => 2
        )
      end
    end

    context 'deserialized signed dict to fulfillment' do
      let(:fulfillment) { Fulfillment.from_uri(fulfillment_threshold['fulfillment_uri']) }
      let(:parsed_fulfillment) { Fulfillment.from_dict(fulfillment.to_dict) }

      it 'works' do
        expect(parsed_fulfillment.serialize_uri).to eq(fulfillment_threshold['fulfillment_uri'])

        expect(parsed_fulfillment.condition.serialize_uri).to eq(fulfillment.condition.serialize_uri)
        expect(parsed_fulfillment.to_dict).to eq(fulfillment.to_dict)
      end
    end

    context 'deserialize unsigned dict to fulfillment' do
      let(:threshold) { 1 }
      let(:fulfillment) { Types::ThresholdSha256Fulfillment.new(threshold) }
      let(:parsed_fulfillment) { Fulfillment.from_dict(fulfillment.to_dict) }

      before do
        fulfillment.add_subfulfillment(Types::Ed25519Fulfillment.new(Crypto::Ed25519VerifyingKey.new(vk_ilp['b58'])))
        fulfillment.add_subfulfillment(Types::Ed25519Fulfillment.new(Crypto::Ed25519VerifyingKey.new(vk_ilp['b58'])))
      end

      it 'works' do
        expect(parsed_fulfillment.condition.serialize_uri).to eq(fulfillment.condition.serialize_uri)
        expect(parsed_fulfillment.to_dict).to eq(fulfillment.to_dict)
      end
    end

    context 'test weights' do
      let(:ilp_fulfillment) { Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri']) }

      let(:fulfillment_1) { Types::ThresholdSha256Fulfillment.new(2) }
      let(:parsed_fulfillment_1) { Fulfillment.from_dict(fulfillment_1.to_dict) }

      let(:fulfillment_2) { Types::ThresholdSha256Fulfillment.new(3) }
      let(:parsed_fulfillment_2) { Fulfillment.from_dict(fulfillment_2.to_dict) }

      let(:fulfillment_3) { Types::ThresholdSha256Fulfillment.new(3) }
      let(:parsed_fulfillment_3) { Fulfillment.from_dict(fulfillment_3.to_dict) }

      let(:fulfillment_4) { Types::ThresholdSha256Fulfillment.new(2) }

      before do
        fulfillment_1.add_subfulfillment(ilp_fulfillment, 2)
        fulfillment_2.add_subfulfillment(ilp_fulfillment, 2)
        fulfillment_3.add_subfulfillment(ilp_fulfillment, 3)
      end

      it 'works' do
        expect(parsed_fulfillment_1.condition.serialize_uri).to eq(fulfillment_1.condition.serialize_uri)
        expect(parsed_fulfillment_1.to_dict).to eq(fulfillment_1.to_dict)
        expect(parsed_fulfillment_1.subconditions.first['weight']).to eq(2)
        expect(parsed_fulfillment_1.validate(message: MESSAGE)).to be_truthy

        expect(parsed_fulfillment_2.subconditions.first['weight']).to eq(2)
        expect(parsed_fulfillment_2.validate(message: MESSAGE)).to be_falsey

        expect(parsed_fulfillment_3.condition.serialize_uri).to eq(fulfillment_3.condition.serialize_uri)
        expect(fulfillment_3.condition.serialize_uri).to_not eq(fulfillment_1.condition.serialize_uri)
        expect(parsed_fulfillment_3.validate(message: MESSAGE)).to be_truthy

        expect { fulfillment_4.add_subfulfillment(ilp_fulfillment, -2) }.to raise_error StandardError
      end
    end

    context 'serialize and deserialize fulfillment' do
      let(:ilp_fulfillment) { Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri']) }
      let(:num_fulfillments) { 20 }
      let(:threshold) { (num_fulfillments * 2 / 3.0).ceil }
      let(:fulfillment) { Types::ThresholdSha256Fulfillment.new(threshold) }
      let(:deserialized_fulfillment) { Fulfillment.from_uri(fulfillment.serialize_uri) }

      before do
        num_fulfillments.times do
          fulfillment.add_subfulfillment(ilp_fulfillment)
        end
      end

      it 'works' do
        expect(fulfillment.validate(message: MESSAGE)).to be_truthy
        expect(deserialized_fulfillment).to be_a(Types::ThresholdSha256Fulfillment)
        expect(deserialized_fulfillment.threshold).to eq(threshold)
        expect(deserialized_fulfillment.subconditions.select { |f| f['type'] == 'fulfillment' }.length).to eq(threshold)
        expect(deserialized_fulfillment.subconditions.length).to eq(num_fulfillments)
        expect(deserialized_fulfillment.serialize_uri).to eq(fulfillment.serialize_uri)
        expect(deserialized_fulfillment.validate(message: MESSAGE)).to be_truthy
      end
    end

    context 'fulfillment did not reach threshold' do
      let(:ilp_fulfillment) { Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri']) }
      let(:threshold) { 10 }
      let(:fulfillment) { Types::ThresholdSha256Fulfillment.new(threshold) }
      let(:deserialized_fulfillment) { Fulfillment.from_uri(fulfillment.serialize_uri) }

      before do
        (threshold - 1).times do
          fulfillment.add_subfulfillment(ilp_fulfillment)
        end
      end

      it 'works' do
        expect { fulfillment.serialize_uri }.to raise_error NoMethodError
        expect(fulfillment.validate(message: MESSAGE)).to be_falsey

        fulfillment.add_subfulfillment(ilp_fulfillment)

        expect(fulfillment.validate(message: MESSAGE)).to be_truthy
        expect(deserialized_fulfillment).to be_a(Types::ThresholdSha256Fulfillment)
        expect(deserialized_fulfillment.threshold).to eq(threshold)
        expect(deserialized_fulfillment.subconditions.select { |f| f['type'] == 'fulfillment' }.length).to eq(threshold)
        expect(deserialized_fulfillment.subconditions.length).to eq(threshold)
        expect(deserialized_fulfillment.serialize_uri).to eq(fulfillment.serialize_uri)
        expect(deserialized_fulfillment.validate(message: MESSAGE)).to be_truthy

        fulfillment.add_subfulfillment(Types::Ed25519Fulfillment.new(Crypto::Ed25519VerifyingKey.new(vk_ilp['b58'])))
        expect(deserialized_fulfillment.validate(message: MESSAGE)).to be_truthy
      end
    end

    context 'fulfillment nested and or' do
      let(:ilp_fulfillment_sha) { Fulfillment.from_uri(fulfillment_sha256['fulfillment_uri']) }
      let(:ilp_fulfillment_ed) { Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri']) }
      let(:fulfillment) { Types::ThresholdSha256Fulfillment.new(2) }
      let(:nested_fulfillment) { Types::ThresholdSha256Fulfillment.new(1) }

      it 'works' do
        fulfillment.add_subfulfillment(ilp_fulfillment_sha)

        expect(fulfillment.validate(message: MESSAGE)).to be_falsey

        nested_fulfillment.add_subfulfillment(ilp_fulfillment_ed)
        expect(nested_fulfillment.validate(message: MESSAGE)).to be_truthy

        nested_fulfillment.add_subfulfillment(ilp_fulfillment_ed)
        expect(nested_fulfillment.validate(message: MESSAGE)).to be_truthy

        fulfillment.add_subfulfillment(nested_fulfillment)
        expect(fulfillment.validate(message: MESSAGE)).to be_truthy

        fulfillment_uri = fulfillment.serialize_uri
        expect(fulfillment.condition_uri).to eq(fulfillment_threshold_nested_and_or['condition_uri'])
        expect(fulfillment_uri).to eq(fulfillment_threshold_nested_and_or['fulfillment_uri'])

        deserialized_fulfillment = Fulfillment.from_uri(fulfillment_uri)

        condition_uri = fulfillment.condition.serialize_uri
        deserialized_condition = Condition.from_uri(condition_uri)

        expect(deserialized_fulfillment).to be_a(Types::ThresholdSha256Fulfillment)
        expect(deserialized_fulfillment.threshold).to eq(2)
        expect(deserialized_fulfillment.subconditions.length).to eq(2)
        expect(deserialized_fulfillment.subconditions.last['body'].subconditions.length).to eq(2)
        expect(deserialized_fulfillment.serialize_uri).to eq(fulfillment_uri)
        expect(deserialized_fulfillment.validate(message: MESSAGE)).to be_truthy
        expect(deserialized_fulfillment.condition.serialize_uri).to eq(condition_uri)
        vk = Utils::Base58.encode(ilp_fulfillment_ed.public_key.to_s)
        expect(fulfillment.get_subcondition_from_vk(vk).length).to eq(2)
        expect(deserialized_fulfillment.get_subcondition_from_vk(vk).length).to eq(1)
      end
    end

    context 'fulfillment nested' do
      let(:ilp_fulfillment_sha) { Fulfillment.from_uri(fulfillment_sha256['fulfillment_uri']) }
      let(:ilp_fulfillment_ed1) { Fulfillment.from_uri(fulfillment_ed25519_2['fulfillment_uri']) }
      let(:original_fulfillment) { Types::ThresholdSha256Fulfillment.new(2) }
      let(:max_depth) { 6 }

      let(:add_nested_fulfillment) do
        lambda do |parent, current_depth = 0|
          current_depth += 1
          child = Types::ThresholdSha256Fulfillment.new(1)
          if current_depth < max_depth
            add_nested_fulfillment.call(child, current_depth)
          else
            child.add_subfulfillment(ilp_fulfillment_ed1)
          end
          parent.add_subfulfillment(child)
          parent
        end
      end

      before do
        original_fulfillment.add_subfulfillment(ilp_fulfillment_sha)
      end

      it 'works' do
        fulfillment = add_nested_fulfillment.call(original_fulfillment)

        expect(fulfillment.validate(message: MESSAGE)).to be_truthy
        expect(fulfillment.subconditions.length).to eq(2)
        expect(fulfillment.subconditions.last['body']).to be_a(Types::ThresholdSha256Fulfillment)
        expect(fulfillment.subconditions.last['body'].subconditions.first['body']).to be_a(Types::ThresholdSha256Fulfillment)

        fulfillment_uri = fulfillment.serialize_uri
        deserialized_fulfillment = Fulfillment.from_uri(fulfillment_uri)

        condition_uri = fulfillment.condition.serialize_uri
        deserialized_condition = Condition.from_uri(condition_uri)

        expect(deserialized_fulfillment.serialize_uri).to eq(fulfillment_uri)
        expect(deserialized_fulfillment.validate(message: MESSAGE)).to be_truthy
        expect(deserialized_condition.serialize_uri).to eq(condition_uri)
      end
    end

    context 'InvertedThresholdSha256Fulfillment' do
      context 'serialize condition and validate fulfillment' do
        let(:ilp_fulfillment_ed) { Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri']) }
        let(:fulfillment) { Types::InvertedThresholdSha256Fulfillment.new(1) }
        let(:parsed_fulfillment) { Fulfillment.from_dict(fulfillment.to_dict) }

        before do
          fulfillment.add_subfulfillment(ilp_fulfillment_ed)
        end

        it 'works' do
          expect(parsed_fulfillment.condition_uri).to eq(fulfillment.condition_uri)
          expect(parsed_fulfillment.serialize_uri).to eq(fulfillment.serialize_uri)
          expect(parsed_fulfillment.validate(message: MESSAGE)).to be_falsey
          expect(parsed_fulfillment.validate).to be_truthy
          expect(parsed_fulfillment).to be_a(Types::InvertedThresholdSha256Fulfillment)
        end
      end
    end

    context 'TimeoutFulfillment' do
      context 'serialize condition and validate fulfillment' do
        let(:time_now) { -> { Types::TimeoutFulfillment.timestamp(Time.now) } }
        let(:time_future) { -> { Types::TimeoutFulfillment.timestamp(Time.now + 1_000) } }
        let(:fulfillment_now) { Types::TimeoutFulfillment.new(time_now.call) }
        let(:parsed_fulfillment_now) { Fulfillment.from_dict(fulfillment_now.to_dict) }
        let(:fulfillment_future) { Types::TimeoutFulfillment.new(time_future.call) }
        let(:parsed_fulfillment_future) { Fulfillment.from_dict(fulfillment_future.to_dict) }

        it 'works' do
          expect(parsed_fulfillment_now.condition_uri).to eq(fulfillment_now.condition_uri)
          expect(parsed_fulfillment_now.serialize_uri).to eq(fulfillment_now.serialize_uri)
          expect(parsed_fulfillment_now.validate(now: time_now.call)).to be_falsey

          expect(parsed_fulfillment_future.condition_uri).to eq(fulfillment_future.condition_uri)
          expect(parsed_fulfillment_future.serialize_uri).to eq(fulfillment_future.serialize_uri)
          expect(parsed_fulfillment_future.validate(now: time_now.call)).to be_truthy
        end
      end
    end

    context 'Escrow' do
      context 'serialize condition and validate fulfillment' do
        it 'works' do
          ilp_fulfillment_sha = Fulfillment.from_uri(fulfillment_sha256['fulfillment_uri'])
          ilp_fulfillment_ed = Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri'])

          fulfillment_escrow = Types::ThresholdSha256Fulfillment.new(1)
          fulfillment_timeout = Types::TimeoutFulfillment.new(Types::TimeoutFulfillment.timestamp(Time.now + 1_000))
          fulfillment_timeout_inverted = Types::InvertedThresholdSha256Fulfillment.new(1)
          fulfillment_timeout_inverted.add_subfulfillment(fulfillment_timeout)

          fulfillment_and_execute = Types::ThresholdSha256Fulfillment.new(2)
          fulfillment_and_execute.add_subfulfillment(ilp_fulfillment_ed)
          fulfillment_and_execute.add_subfulfillment(fulfillment_timeout)

          expect(fulfillment_and_execute.validate(message: MESSAGE, now: Types::TimeoutFulfillment.timestamp(Time.now))).to be_truthy

          fulfillment_and_abort = Types::ThresholdSha256Fulfillment.new(2)
          fulfillment_and_abort.add_subfulfillment(ilp_fulfillment_sha)
          fulfillment_and_abort.add_subfulfillment(fulfillment_timeout_inverted)

          expect(fulfillment_and_abort.validate(message: MESSAGE, now: Types::TimeoutFulfillment.timestamp(Time.now))).to be_falsey

          fulfillment_escrow.add_subfulfillment(fulfillment_and_execute)
          fulfillment_escrow.add_subfulfillment(fulfillment_and_abort)

          parsed_fulfillment = Fulfillment.from_dict(fulfillment_escrow.to_dict())

          expect(parsed_fulfillment.condition_uri).to eq(fulfillment_escrow.condition_uri)
          expect(parsed_fulfillment.serialize_uri).to eq(fulfillment_escrow.serialize_uri)
          expect(parsed_fulfillment.validate(message: MESSAGE, now: Types::TimeoutFulfillment.timestamp(Time.now))).to be_truthy
        end
      end

      context 'escrow execute' do
        it 'works' do
          ilp_fulfillment_sha = Fulfillment.from_uri(fulfillment_sha256['fulfillment_uri'])
          ilp_fulfillment_ed = Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri'])

          time_sleep = 3

          fulfillment_escrow = Types::ThresholdSha256Fulfillment.new(1)
          fulfillment_timeout = Types::TimeoutFulfillment.new(Types::TimeoutFulfillment.timestamp(Time.now + time_sleep))
          fulfillment_timeout_inverted = Types::InvertedThresholdSha256Fulfillment.new(1)
          fulfillment_timeout_inverted.add_subfulfillment(fulfillment_timeout)

          ## fulfill execute branch
          fulfillment_and_execute = Types::ThresholdSha256Fulfillment.new(2)
          fulfillment_and_execute.add_subfulfillment(ilp_fulfillment_ed)
          fulfillment_and_execute.add_subfulfillment(fulfillment_timeout)

          ## do not fulfill abort branch
          fulfillment_and_abort = Types::ThresholdSha256Fulfillment.new(2)
          fulfillment_and_abort.add_subcondition(ilp_fulfillment_sha.condition)
          fulfillment_and_abort.add_subfulfillment(fulfillment_timeout_inverted)

          fulfillment_escrow.add_subfulfillment(fulfillment_and_execute)
          fulfillment_escrow.add_subfulfillment(fulfillment_and_abort)

          ## in-time validation
          expect(fulfillment_escrow.validate(message: MESSAGE, now: Types::TimeoutFulfillment.timestamp(Time.now))).to be_truthy

          sleep(3)
          ## out-of-time validation
          expect(fulfillment_escrow.validate(message: MESSAGE, now: Types::TimeoutFulfillment.timestamp(Time.now))).to be_falsey
        end
      end

      context 'escrow abort' do
        it 'works' do
          ilp_fulfillment_sha = Fulfillment.from_uri(fulfillment_sha256['fulfillment_uri'])
          ilp_fulfillment_ed = Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri'])

          time_sleep = 0

          fulfillment_escrow = Types::ThresholdSha256Fulfillment.new(1)
          fulfillment_timeout = Types::TimeoutFulfillment.new(Types::TimeoutFulfillment.timestamp(Time.now + time_sleep))
          fulfillment_timeout_inverted = Types::InvertedThresholdSha256Fulfillment.new(1)
          fulfillment_timeout_inverted.add_subfulfillment(fulfillment_timeout)

          ## do not fulfill execute branch
          fulfillment_and_execute = Types::ThresholdSha256Fulfillment.new(2)
          fulfillment_and_execute.add_subcondition(ilp_fulfillment_ed.condition)
          fulfillment_and_execute.add_subfulfillment(fulfillment_timeout)

          fulfillment_and_abort = Types::ThresholdSha256Fulfillment.new(2)
          fulfillment_and_abort.add_subfulfillment(ilp_fulfillment_sha)
          fulfillment_and_abort.add_subfulfillment(fulfillment_timeout_inverted)

          fulfillment_escrow.add_subfulfillment(fulfillment_and_execute)
          fulfillment_escrow.add_subfulfillment(fulfillment_and_abort)

          ## out-of-time validation
          expect(fulfillment_escrow.validate(message: MESSAGE, now: Types::TimeoutFulfillment.timestamp(Time.now))).to be_truthy
        end
      end

      context 'escrow execute abort' do
        it 'works' do
          ilp_fulfillment_sha = Fulfillment.from_uri(fulfillment_sha256['fulfillment_uri'])
          ilp_fulfillment_ed = Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri'])

          time_sleep = 3

          fulfillment_escrow_execute = Types::ThresholdSha256Fulfillment.new(1)
          fulfillment_timeout = Types::TimeoutFulfillment.new(Types::TimeoutFulfillment.timestamp(Time.now + time_sleep))
          fulfillment_timeout_inverted = Types::InvertedThresholdSha256Fulfillment.new(1)
          fulfillment_timeout_inverted.add_subfulfillment(fulfillment_timeout)

          ## fulfill execute branch
          fulfillment_and_execute = Types::ThresholdSha256Fulfillment.new(2)
          fulfillment_and_execute.add_subfulfillment(ilp_fulfillment_ed)
          fulfillment_and_execute.add_subfulfillment(fulfillment_timeout)

          ## do not fulfill abort branch
          fulfillment_and_abort = Types::ThresholdSha256Fulfillment.new(2)
          fulfillment_and_abort.add_subcondition(ilp_fulfillment_sha.condition)
          fulfillment_and_abort.add_subfulfillment(fulfillment_timeout_inverted)

          fulfillment_escrow_execute.add_subfulfillment(fulfillment_and_execute)
          fulfillment_escrow_execute.add_subfulfillment(fulfillment_and_abort)

          ## in-time validation
          expect(fulfillment_escrow_execute.validate(message: MESSAGE, now: Types::TimeoutFulfillment.timestamp(Time.now))).to be_truthy

          sleep(3)
          ## out-of-time validation
          expect(fulfillment_escrow_execute.validate(message: MESSAGE, now: Types::TimeoutFulfillment.timestamp(Time.now))).to be_falsey

          fulfillment_escrow_abort = Types::ThresholdSha256Fulfillment.new(1)

          ## do not fulfill execute branch
          fulfillment_and_execute = Types::ThresholdSha256Fulfillment.new(2)
          fulfillment_and_execute.add_subcondition(ilp_fulfillment_ed.condition)
          fulfillment_and_execute.add_subfulfillment(fulfillment_timeout)

          ## fulfill abort branch
          fulfillment_and_abort = Types::ThresholdSha256Fulfillment.new(2)
          fulfillment_and_abort.add_subfulfillment(ilp_fulfillment_sha)
          fulfillment_and_abort.add_subfulfillment(fulfillment_timeout_inverted)

          fulfillment_escrow_abort.add_subfulfillment(fulfillment_and_execute)
          fulfillment_escrow_abort.add_subfulfillment(fulfillment_and_abort)

          expect(fulfillment_escrow_abort.validate(message: MESSAGE, now: Types::TimeoutFulfillment.timestamp(Time.now))).to be_truthy
        end
      end
    end
  end
end


#class TestEscrow:
    #def test_escrow_execute_abort(self, fulfillment_sha256, fulfillment_ed25519):
        #ilp_fulfillment_sha = Fulfillment.from_uri(fulfillment_sha256['fulfillment_uri'])
        #ilp_fulfillment_ed = Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri'])

        #time_sleep = 3

        #fulfillment_escrow_execute = ThresholdSha256Fulfillment(threshold=1)
        #fulfillment_timeout = TimeoutFulfillment(expire_time=str(float(timestamp()) + time_sleep))
        #fulfillment_timeout_inverted = InvertedThresholdSha256Fulfillment(threshold=1)
        #fulfillment_timeout_inverted.add_subfulfillment(fulfillment_timeout)

        ## fulfill execute branch
        #fulfillment_and_execute = ThresholdSha256Fulfillment(threshold=2)
        #fulfillment_and_execute.add_subfulfillment(ilp_fulfillment_ed)
        #fulfillment_and_execute.add_subfulfillment(fulfillment_timeout)

        ## do not fulfill abort branch
        #fulfillment_and_abort = ThresholdSha256Fulfillment(threshold=2)
        #fulfillment_and_abort.add_subcondition(ilp_fulfillment_sha.condition)
        #fulfillment_and_abort.add_subfulfillment(fulfillment_timeout_inverted)

        #fulfillment_escrow_execute.add_subfulfillment(fulfillment_and_execute)
        #fulfillment_escrow_execute.add_subfulfillment(fulfillment_and_abort)

        ## in-time validation
        #assert fulfillment_escrow_execute.validate(MESSAGE, now=timestamp()) is True

        #sleep(3)
        ## out-of-time validation
        #assert fulfillment_escrow_execute.validate(MESSAGE, now=timestamp()) is False

        #fulfillment_escrow_abort = ThresholdSha256Fulfillment(threshold=1)

        ## do not fulfill execute branch
        #fulfillment_and_execute = ThresholdSha256Fulfillment(threshold=2)
        #fulfillment_and_execute.add_subcondition(ilp_fulfillment_ed.condition)
        #fulfillment_and_execute.add_subfulfillment(fulfillment_timeout)

        ## fulfill abort branch
        #fulfillment_and_abort = ThresholdSha256Fulfillment(threshold=2)
        #fulfillment_and_abort.add_subfulfillment(ilp_fulfillment_sha)
        #fulfillment_and_abort.add_subfulfillment(fulfillment_timeout_inverted)

        #fulfillment_escrow_abort.add_subfulfillment(fulfillment_and_execute)
        #fulfillment_escrow_abort.add_subfulfillment(fulfillment_and_abort)

        #assert fulfillment_escrow_abort.validate(MESSAGE, now=timestamp()) is True


