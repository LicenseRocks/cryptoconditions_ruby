require 'spec_helper'

module CryptoconditionsRuby
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
    context 'test_ilp_keys' do
      let(:sk) { Crypto::Ed25519SigningKey.new(sk_ilp['b58']) }
      let(:vk) { Crypto::Ed25519VerifyingKey.new(vk_ilp['b58']) }

      it 'returns a correctly encoded signing key' do
        expect(sk.encode('base64')).to eq(sk_ilp['b64'])
        expect(hexlify(sk.encode('bytes').slice(0...32))).to eq(sk_ilp['hex'])
      end
    end
  end
end
  #class TestEd25519Sha256Fulfillment:
      #def test_ilp_keys(self, sk_ilp, vk_ilp):
          #sk = SigningKey(sk_ilp['b58'])
          #assert sk.encode(encoding='base64') == sk_ilp['b64']
          #assert binascii.hexlify(sk.encode(encoding='bytes')[:32]) == sk_ilp['hex']

          #vk = VerifyingKey(vk_ilp['b58'])
          #assert vk.encode(encoding='base64') == vk_ilp['b64']
          #assert binascii.hexlify(vk.encode(encoding='bytes')) == vk_ilp['hex']

      #def test_create(self, vk_ilp):
          #fulfillment1 = Ed25519Fulfillment(public_key=vk_ilp['b58'])
          #fulfillment2 = Ed25519Fulfillment(VerifyingKey(vk_ilp['b58']))
          #assert fulfillment1.condition.serialize_uri() == fulfillment2.condition.serialize_uri()

      #def test_serialize_condition_and_validate_fulfillment(self, sk_ilp, vk_ilp, fulfillment_ed25519):
          #sk = SigningKey(sk_ilp['b58'])
          #vk = VerifyingKey(vk_ilp['b58'])

          #fulfillment = Ed25519Fulfillment(public_key=vk)

          #assert fulfillment.condition.serialize_uri() == fulfillment_ed25519['condition_uri']
          #assert binascii.hexlify(fulfillment.condition.hash) == fulfillment_ed25519['condition_hash']

          ## ED25519-SHA256 condition not fulfilled
          #assert fulfillment.validate() == False

          ## Fulfill an ED25519-SHA256 condition
          #fulfillment.sign(MESSAGE, sk)

          #assert fulfillment.serialize_uri() == fulfillment_ed25519['fulfillment_uri']
          #assert fulfillment.validate(MESSAGE)

      #def test_deserialize_condition(self, fulfillment_ed25519):
          #deserialized_condition = Condition.from_uri(fulfillment_ed25519['condition_uri'])

          #assert deserialized_condition.serialize_uri() == fulfillment_ed25519['condition_uri']
          #assert binascii.hexlify(deserialized_condition.hash) == fulfillment_ed25519['condition_hash']

      #def test_serialize_signed_dict_to_fulfillment(self, fulfillment_ed25519):
          #fulfillment = Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri'])

          #assert fulfillment.to_dict()== \
              #{'bitmask': 32,
               #'public_key': 'Gtbi6WQDB6wUePiZm8aYs5XZ5pUqx9jMMLvRVHPESTjU',
               #'signature': '4eCt6SFPCzLQSAoQGW7CTu3MHdLj6FezSpjktE7tHsYGJ4pNSUnpHtV9XgdHF2XYd62M9fTJ4WYdhTVck27qNoHj',
               #'type': 'fulfillment',
               #'type_id': 4}

          #assert fulfillment.validate(MESSAGE) == True

      #def test_serialize_unsigned_dict_to_fulfillment(self, vk_ilp):
          #fulfillment = Ed25519Fulfillment(public_key=vk_ilp['b58'])

          #assert fulfillment.to_dict() == \
              #{'bitmask': 32,
               #'public_key': 'Gtbi6WQDB6wUePiZm8aYs5XZ5pUqx9jMMLvRVHPESTjU',
               #'signature': None,
               #'type': 'fulfillment',
               #'type_id': 4}
          #assert fulfillment.validate(MESSAGE) == False

      #def test_deserialize_signed_dict_to_fulfillment(self, fulfillment_ed25519):
          #fulfillment = Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri'])
          #parsed_fulfillment = fulfillment.from_dict(fulfillment.to_dict())

          #assert parsed_fulfillment.serialize_uri() == fulfillment_ed25519['fulfillment_uri']
          #assert parsed_fulfillment.condition.serialize_uri() == fulfillment.condition.serialize_uri()
          #assert parsed_fulfillment.to_dict() == fulfillment.to_dict()

      #def test_deserialize_unsigned_dict_to_fulfillment(self, vk_ilp):
          #fulfillment = Ed25519Fulfillment(public_key=vk_ilp['b58'])
          #parsed_fulfillment = fulfillment.from_dict(fulfillment.to_dict())

          #assert parsed_fulfillment.condition.serialize_uri() == fulfillment.condition.serialize_uri()
          #assert parsed_fulfillment.to_dict() == fulfillment.to_dict()

      #def test_serialize_deserialize_condition(self, vk_ilp):
          #vk = VerifyingKey(vk_ilp['b58'])

          #fulfillment = Ed25519Fulfillment(public_key=vk)

          #condition = fulfillment.condition
          #deserialized_condition = Condition.from_uri(condition.serialize_uri())

          #assert deserialized_condition.bitmask == condition.bitmask
          #assert deserialized_condition.hash == condition.hash
          #assert deserialized_condition.max_fulfillment_length == condition.max_fulfillment_length
          #assert deserialized_condition.serialize_uri() == condition.serialize_uri()

      #def test_deserialize_fulfillment(self, vk_ilp, fulfillment_ed25519):
          #fulfillment = Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri'])

          #assert isinstance(fulfillment, Ed25519Fulfillment)
          #assert fulfillment.serialize_uri() == fulfillment_ed25519['fulfillment_uri']
          #assert fulfillment.condition.serialize_uri() == fulfillment_ed25519['condition_uri']
          #assert binascii.hexlify(fulfillment.condition.hash) == fulfillment_ed25519['condition_hash']
          #assert fulfillment.public_key.encode(encoding='hex') == vk_ilp['hex']
          #assert fulfillment.validate(MESSAGE)

      #def test_deserialize_fulfillment_2(self, vk_ilp, fulfillment_ed25519_2):
          #fulfillment = Fulfillment.from_uri(fulfillment_ed25519_2['fulfillment_uri'])

          #assert isinstance(fulfillment, Ed25519Fulfillment)
          #assert fulfillment.serialize_uri() == fulfillment_ed25519_2['fulfillment_uri']
          #assert fulfillment.condition.serialize_uri() == fulfillment_ed25519_2['condition_uri']
          #assert binascii.hexlify(fulfillment.condition.hash) == fulfillment_ed25519_2['condition_hash']
          #assert fulfillment.public_key.encode(encoding='hex') == vk_ilp[2]['hex']
          #assert fulfillment.validate(MESSAGE)

      #def test_serialize_deserialize_fulfillment(self, sk_ilp, vk_ilp):
          #sk = SigningKey(sk_ilp['b58'])
          #vk = VerifyingKey(vk_ilp['b58'])

          #fulfillment = Ed25519Fulfillment(public_key=vk)
          #fulfillment.sign(MESSAGE, sk)

          #assert fulfillment.validate(MESSAGE)

          #deserialized_fulfillment = Fulfillment.from_uri(fulfillment.serialize_uri())
          #assert isinstance(deserialized_fulfillment, Ed25519Fulfillment)
          #assert deserialized_fulfillment.serialize_uri() == fulfillment.serialize_uri()
          #assert deserialized_fulfillment.condition.serialize_uri() == fulfillment.condition.serialize_uri()
          #assert deserialized_fulfillment.public_key.encode(encoding='bytes') == \
                  #fulfillment.public_key.encode(encoding='bytes')
          #assert deserialized_fulfillment.validate(MESSAGE)
