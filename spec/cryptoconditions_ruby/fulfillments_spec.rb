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
        expect(ilp_fulfillment_ed25519.validate(MESSAGE)).to be_truthy
        expect(ilp_fulfillment_sha.validate(MESSAGE)).to be_truthy
        expect(fulfillment.condition.serialize_uri).to eq(fulfillment_threshold['condition_uri'])
        expect(fulfillment.serialize_uri).to eq(fulfillment_threshold['fulfillment_uri'])
        expect(fulfillment.validate(MESSAGE)).to be_truthy
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
        expect(fulfillment.validate(MESSAGE)).to be_truthy

      end
    end
  end
end

#class TestThresholdSha256Fulfillment:

    #def test_deserialize_fulfillment(self, fulfillment_threshold):
        #num_fulfillments = 2
        #threshold = 1

        #fulfillment = Fulfillment.from_uri(fulfillment_threshold['fulfillment_uri'])

        #assert isinstance(fulfillment, ThresholdSha256Fulfillment)
        #assert fulfillment.threshold == threshold
        #assert len([f for f in fulfillment.subconditions if f['type'] == 'fulfillment']) == threshold
        #assert fulfillment.serialize_uri() == fulfillment_threshold['fulfillment_uri']
        #assert len(fulfillment.subconditions) == num_fulfillments
        #assert fulfillment.validate(MESSAGE)

    #def test_serialize_signed_dict_to_fulfillment(self, fulfillment_threshold):
        #fulfillment = Fulfillment.from_uri(fulfillment_threshold['fulfillment_uri'])

        #assert fulfillment.to_dict() == \
            #{'bitmask': 43,
             #'subfulfillments': [{'bitmask': 3,
                                  #'preimage': '',
                                  #'type': 'fulfillment',
                                  #'type_id': 0,
                                  #'weight': 1},
                                 #{'bitmask': 32,
                                  #'hash': 'Gtbi6WQDB6wUePiZm8aYs5XZ5pUqx9jMMLvRVHPESTjU',
                                  #'max_fulfillment_length': 96,
                                  #'type': 'condition',
                                  #'type_id': 4,
                                  #'weight': 1}],
             #'threshold': 1,
             #'type': 'fulfillment',
             #'type_id': 2}

    #def test_serialize_unsigned_dict_to_fulfillment(self, vk_ilp):
        #fulfillment = ThresholdSha256Fulfillment(threshold=1)
        #fulfillment.add_subfulfillment(Ed25519Fulfillment(public_key=VerifyingKey(vk_ilp['b58'])))
        #fulfillment.add_subfulfillment(Ed25519Fulfillment(public_key=VerifyingKey(vk_ilp['b58'])))

        #assert fulfillment.to_dict() == \
            #{'bitmask': 41,
             #'subfulfillments': [{'bitmask': 32,
                                  #'public_key': 'Gtbi6WQDB6wUePiZm8aYs5XZ5pUqx9jMMLvRVHPESTjU',
                                  #'signature': None,
                                  #'type': 'fulfillment',
                                  #'type_id': 4,
                                  #'weight': 1},
                                 #{'bitmask': 32,
                                  #'public_key': 'Gtbi6WQDB6wUePiZm8aYs5XZ5pUqx9jMMLvRVHPESTjU',
                                  #'signature': None,
                                  #'type': 'fulfillment',
                                  #'type_id': 4,
                                  #'weight': 1}],
             #'threshold': 1,
             #'type': 'fulfillment',
             #'type_id': 2}

    #def test_deserialize_signed_dict_to_fulfillment(self, fulfillment_threshold):
        #fulfillment = Fulfillment.from_uri(fulfillment_threshold['fulfillment_uri'])
        #parsed_fulfillment = fulfillment.from_dict(fulfillment.to_dict())

        #assert parsed_fulfillment.serialize_uri() == fulfillment_threshold['fulfillment_uri']
        #assert parsed_fulfillment.condition.serialize_uri() == fulfillment.condition.serialize_uri()
        #assert parsed_fulfillment.to_dict() == fulfillment.to_dict()

    #def test_deserialize_unsigned_dict_to_fulfillment(self, vk_ilp):
        #fulfillment = ThresholdSha256Fulfillment(threshold=1)
        #fulfillment.add_subfulfillment(Ed25519Fulfillment(public_key=VerifyingKey(vk_ilp['b58'])))
        #fulfillment.add_subfulfillment(Ed25519Fulfillment(public_key=VerifyingKey(vk_ilp['b58'])))
        #parsed_fulfillment = fulfillment.from_dict(fulfillment.to_dict())

        #assert parsed_fulfillment.condition.serialize_uri() == fulfillment.condition.serialize_uri()
        #assert parsed_fulfillment.to_dict() == fulfillment.to_dict()

    #def test_weights(self, fulfillment_ed25519):
        #ilp_fulfillment = Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri'])

        #fulfillment1 = ThresholdSha256Fulfillment(threshold=2)
        #fulfillment1.add_subfulfillment(ilp_fulfillment, weight=2)
        #parsed_fulfillment1 = fulfillment1.from_dict(fulfillment1.to_dict())

        #assert parsed_fulfillment1.condition.serialize_uri() == fulfillment1.condition.serialize_uri()
        #assert parsed_fulfillment1.to_dict() == fulfillment1.to_dict()
        #assert parsed_fulfillment1.subconditions[0]['weight'] == 2
        #assert parsed_fulfillment1.validate(MESSAGE) is True

        #fulfillment2 = ThresholdSha256Fulfillment(threshold=3)
        #fulfillment2.add_subfulfillment(ilp_fulfillment, weight=2)
        #parsed_fulfillment2 = fulfillment1.from_dict(fulfillment2.to_dict())

        #assert parsed_fulfillment2.subconditions[0]['weight'] == 2
        #assert parsed_fulfillment2.validate(MESSAGE) is False

        #fulfillment3 = ThresholdSha256Fulfillment(threshold=3)
        #fulfillment3.add_subfulfillment(ilp_fulfillment, weight=3)
        #parsed_fulfillment3 = fulfillment1.from_dict(fulfillment3.to_dict())

        #assert parsed_fulfillment3.condition.serialize_uri() == fulfillment3.condition.serialize_uri()
        #assert not (fulfillment3.condition.serialize_uri() == fulfillment1.condition.serialize_uri())
        #assert parsed_fulfillment3.validate(MESSAGE) is True

        #fulfillment4 = ThresholdSha256Fulfillment(threshold=2)
        #with pytest.raises(ValueError):
            #fulfillment4.add_subfulfillment(ilp_fulfillment, weight=-2)

    #def test_serialize_deserialize_fulfillment(self,
                                               #fulfillment_ed25519):
        #ilp_fulfillment = Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri'])
        #num_fulfillments = 20
        #threshold = ceil(num_fulfillments * 2 / 3)

        ## Create a threshold condition
        #fulfillment = ThresholdSha256Fulfillment(threshold=threshold)
        #for i in range(num_fulfillments):
            #fulfillment.add_subfulfillment(ilp_fulfillment)

        #fulfillment_uri = fulfillment.serialize_uri()

        #assert fulfillment.validate(MESSAGE)
        #deserialized_fulfillment = Fulfillment.from_uri(fulfillment_uri)

        #assert isinstance(deserialized_fulfillment, ThresholdSha256Fulfillment)
        #assert deserialized_fulfillment.threshold == threshold
        #assert len([f for f in deserialized_fulfillment.subconditions if f['type'] == 'fulfillment']) == threshold
        #assert len(deserialized_fulfillment.subconditions) == num_fulfillments
        #assert deserialized_fulfillment.serialize_uri() == fulfillment_uri
        #assert deserialized_fulfillment.validate(MESSAGE)

    #def test_fulfillment_didnt_reach_threshold(self, vk_ilp, fulfillment_ed25519):
        #ilp_fulfillment = Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri'])
        #threshold = 10

        ## Create a threshold condition
        #fulfillment = ThresholdSha256Fulfillment(threshold=threshold)

        #for i in range(threshold - 1):
            #fulfillment.add_subfulfillment(ilp_fulfillment)

        #with pytest.raises(KeyError):
            #fulfillment.serialize_uri()

        #assert fulfillment.validate(MESSAGE) is False

        #fulfillment.add_subfulfillment(ilp_fulfillment)

        #fulfillment_uri = fulfillment.serialize_uri()
        #assert fulfillment.validate(MESSAGE)

        #deserialized_fulfillment = Fulfillment.from_uri(fulfillment_uri)

        #assert isinstance(deserialized_fulfillment, ThresholdSha256Fulfillment)
        #assert deserialized_fulfillment.threshold == threshold
        #assert len([f for f in deserialized_fulfillment.subconditions if f['type'] == 'fulfillment']) == threshold
        #assert len(deserialized_fulfillment.subconditions) == threshold
        #assert deserialized_fulfillment.serialize_uri() == fulfillment_uri
        #assert deserialized_fulfillment.validate(MESSAGE)

        #fulfillment.add_subfulfillment(Ed25519Fulfillment(public_key=VerifyingKey(vk_ilp['b58'])))

        #assert fulfillment.validate(MESSAGE) == True

    #def test_fulfillment_nested_and_or(self,
                                       #fulfillment_sha256,
                                       #fulfillment_ed25519,
                                       #fulfillment_threshold_nested_and_or):
        #ilp_fulfillment_sha = Fulfillment.from_uri(fulfillment_sha256['fulfillment_uri'])
        #ilp_fulfillment_ed = Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri'])

        ## 2-of-2 (AND with 2 inputs)
        #fulfillment = ThresholdSha256Fulfillment(threshold=2)
        #fulfillment.add_subfulfillment(ilp_fulfillment_sha)

        #assert fulfillment.validate(MESSAGE) is False

        ## 1-of-2 (OR with 2 inputs)
        #nested_fulfillment = ThresholdSha256Fulfillment(threshold=1)
        #nested_fulfillment.add_subfulfillment(ilp_fulfillment_ed)
        #assert nested_fulfillment.validate(MESSAGE) is True
        #nested_fulfillment.add_subfulfillment(ilp_fulfillment_ed)
        #assert nested_fulfillment.validate(MESSAGE) is True

        #fulfillment.add_subfulfillment(nested_fulfillment)
        #assert fulfillment.validate(MESSAGE) is True

        #fulfillment_uri = fulfillment.serialize_uri()
        #assert fulfillment.condition_uri == fulfillment_threshold_nested_and_or['condition_uri']
        #assert fulfillment_uri == fulfillment_threshold_nested_and_or['fulfillment_uri']

        #print(fulfillment_uri)
        #deserialized_fulfillment = Fulfillment.from_uri(fulfillment_uri)

        #condition_uri = fulfillment.condition.serialize_uri()
        #deserialized_condition = Condition.from_uri(condition_uri)

        #assert isinstance(deserialized_fulfillment, ThresholdSha256Fulfillment)
        #assert deserialized_fulfillment.threshold == 2
        #assert len(deserialized_fulfillment.subconditions) == 2
        #assert len(deserialized_fulfillment.subconditions[1]['body'].subconditions) == 2
        #assert deserialized_fulfillment.serialize_uri() == fulfillment_uri
        #assert deserialized_fulfillment.validate(MESSAGE)
        #assert deserialized_condition.serialize_uri() == condition_uri
        #vk = ilp_fulfillment_ed.public_key.encode(encoding='base58')
        #assert len(fulfillment.get_subcondition_from_vk(vk)) == 2
        #assert len(deserialized_fulfillment.get_subcondition_from_vk(vk)) == 1

    #def test_fulfillment_nested(self,
                                #fulfillment_sha256,
                                #fulfillment_ed25519_2, ):
        #ilp_fulfillment_sha = Fulfillment.from_uri(fulfillment_sha256['fulfillment_uri'])
        #ilp_fulfillment_ed1 = Fulfillment.from_uri(fulfillment_ed25519_2['fulfillment_uri'])

        ## 2-of-2 (AND with 2 inputs)
        #fulfillment = ThresholdSha256Fulfillment(threshold=2)
        #fulfillment.add_subfulfillment(ilp_fulfillment_sha)

        #max_depth = 6

        #def add_nested_fulfillment(parent, current_depth=0):
            #current_depth += 1
            #child = ThresholdSha256Fulfillment(threshold=1)
            #if current_depth < max_depth:
                #add_nested_fulfillment(child, current_depth)
            #else:
                #child.add_subfulfillment(ilp_fulfillment_ed1)
            #parent.add_subfulfillment(child)
            #return parent

        #fulfillment = add_nested_fulfillment(fulfillment)

        #assert fulfillment.validate(MESSAGE) is True
        #assert len(fulfillment.subconditions) == 2
        #assert isinstance(fulfillment.subconditions[1]['body'], ThresholdSha256Fulfillment)
        #assert isinstance(fulfillment.subconditions[1]['body'].subconditions[0]['body'], ThresholdSha256Fulfillment)

        #fulfillment_uri = fulfillment.serialize_uri()
        #deserialized_fulfillment = Fulfillment.from_uri(fulfillment_uri)

        #condition_uri = fulfillment.condition.serialize_uri()
        #deserialized_condition = Condition.from_uri(condition_uri)

        #assert deserialized_fulfillment.serialize_uri() == fulfillment_uri
        #assert deserialized_fulfillment.validate(MESSAGE) is True
        #assert deserialized_condition.serialize_uri() == condition_uri


#class TestInvertedThresholdSha256Fulfillment:

    #def test_serialize_condition_and_validate_fulfillment(self,
                                                          #fulfillment_ed25519):
        #ilp_fulfillment_ed = Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri'])

        #fulfillment = InvertedThresholdSha256Fulfillment(threshold=1)
        #fulfillment.add_subfulfillment(ilp_fulfillment_ed)
        #parsed_fulfillment = fulfillment.from_dict(fulfillment.to_dict())

        #assert parsed_fulfillment.condition_uri == fulfillment.condition_uri
        #assert parsed_fulfillment.serialize_uri() == fulfillment.serialize_uri()
        #assert parsed_fulfillment.validate(MESSAGE) is False
        #assert parsed_fulfillment.validate() is True
        #assert isinstance(parsed_fulfillment, InvertedThresholdSha256Fulfillment)


#class TestTimeoutFulfillment:

    #def test_serialize_condition_and_validate_fulfillment(self):

        #fulfillment = TimeoutFulfillment(expire_time=timestamp())
        #parsed_fulfillment = fulfillment.from_dict(fulfillment.to_dict())

        #assert parsed_fulfillment.condition_uri == fulfillment.condition_uri
        #assert parsed_fulfillment.serialize_uri() == fulfillment.serialize_uri()
        #assert parsed_fulfillment.validate(now=timestamp()) is False

        #fulfillment = TimeoutFulfillment(expire_time=str(float(timestamp()) + 1000))
        #parsed_fulfillment = fulfillment.from_dict(fulfillment.to_dict())

        #assert parsed_fulfillment.condition_uri == fulfillment.condition_uri
        #assert parsed_fulfillment.serialize_uri() == fulfillment.serialize_uri()
        #assert parsed_fulfillment.validate(now=timestamp()) is True


#class TestEscrow:
    #def create_fulfillment_ed25519sha256(self, sk_ilp, vk_ilp):
        #sk = SigningKey(sk_ilp['b58'])
        #vk = VerifyingKey(vk_ilp['b58'])

        #fulfillment = Ed25519Fulfillment(public_key=vk)
        #fulfillment.sign(MESSAGE, sk)
        #return fulfillment

    #def test_serialize_condition_and_validate_fulfillment(self,
                                                          #fulfillment_sha256,
                                                          #fulfillment_ed25519):
        #ilp_fulfillment_sha = Fulfillment.from_uri(fulfillment_sha256['fulfillment_uri'])
        #ilp_fulfillment_ed = Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri'])

        #fulfillment_escrow = ThresholdSha256Fulfillment(threshold=1)
        #fulfillment_timeout = TimeoutFulfillment(expire_time=str(float(timestamp()) + 1000))
        #fulfillment_timeout_inverted = InvertedThresholdSha256Fulfillment(threshold=1)
        #fulfillment_timeout_inverted.add_subfulfillment(fulfillment_timeout)

        #fulfillment_and_execute = ThresholdSha256Fulfillment(threshold=2)
        #fulfillment_and_execute.add_subfulfillment(ilp_fulfillment_ed)
        #fulfillment_and_execute.add_subfulfillment(fulfillment_timeout)

        #assert fulfillment_and_execute.validate(MESSAGE, now=timestamp()) is True

        #fulfillment_and_abort = ThresholdSha256Fulfillment(threshold=2)
        #fulfillment_and_abort.add_subfulfillment(ilp_fulfillment_sha)
        #fulfillment_and_abort.add_subfulfillment(fulfillment_timeout_inverted)

        ## timeout has not occured (over about 1000 seconds)
        #assert fulfillment_and_abort.validate(MESSAGE, now=timestamp()) is False

        #fulfillment_escrow.add_subfulfillment(fulfillment_and_execute)
        #fulfillment_escrow.add_subfulfillment(fulfillment_and_abort)

        #parsed_fulfillment = fulfillment_escrow.from_dict(fulfillment_escrow.to_dict())

        #assert parsed_fulfillment.condition_uri == fulfillment_escrow.condition_uri
        #assert parsed_fulfillment.serialize_uri() == fulfillment_escrow.serialize_uri()
        #assert parsed_fulfillment.validate(MESSAGE, now=timestamp()) is True

    #def test_escrow_execute(self, fulfillment_sha256, fulfillment_ed25519):

        #ilp_fulfillment_sha = Fulfillment.from_uri(fulfillment_sha256['fulfillment_uri'])
        #ilp_fulfillment_ed = Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri'])

        #time_sleep = 3

        #fulfillment_escrow = ThresholdSha256Fulfillment(threshold=1)
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

        #fulfillment_escrow.add_subfulfillment(fulfillment_and_execute)
        #fulfillment_escrow.add_subfulfillment(fulfillment_and_abort)

        ## in-time validation
        #assert fulfillment_escrow.validate(MESSAGE, now=timestamp()) is True

        #sleep(3)
        ## out-of-time validation
        #assert fulfillment_escrow.validate(MESSAGE, now=timestamp()) is False

    #def test_escrow_abort(self, fulfillment_sha256, fulfillment_ed25519):
        #ilp_fulfillment_sha = Fulfillment.from_uri(fulfillment_sha256['fulfillment_uri'])
        #ilp_fulfillment_ed = Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri'])

        #time_sleep = 0

        #fulfillment_escrow = ThresholdSha256Fulfillment(threshold=1)
        #fulfillment_timeout = TimeoutFulfillment(expire_time=str(float(timestamp()) + time_sleep))
        #fulfillment_timeout_inverted = InvertedThresholdSha256Fulfillment(threshold=1)
        #fulfillment_timeout_inverted.add_subfulfillment(fulfillment_timeout)

        ## do not fulfill execute branch
        #fulfillment_and_execute = ThresholdSha256Fulfillment(threshold=2)
        #fulfillment_and_execute.add_subcondition(ilp_fulfillment_ed.condition)
        #fulfillment_and_execute.add_subfulfillment(fulfillment_timeout)

        #fulfillment_and_abort = ThresholdSha256Fulfillment(threshold=2)
        #fulfillment_and_abort.add_subfulfillment(ilp_fulfillment_sha)
        #fulfillment_and_abort.add_subfulfillment(fulfillment_timeout_inverted)

        #fulfillment_escrow.add_subfulfillment(fulfillment_and_execute)
        #fulfillment_escrow.add_subfulfillment(fulfillment_and_abort)

        ## out-of-time validation
        #assert fulfillment_escrow.validate(MESSAGE, now=timestamp()) is True

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


