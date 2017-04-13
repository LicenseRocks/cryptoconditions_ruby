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
    end

    context 'test_condition_from_fulfillment' do

    end
  end
  #class TestSha256Fulfillment:
      #def test_deserialize_condition_and_validate_fulfillment(self, fulfillment_sha256):
          #condition = Condition.from_uri(fulfillment_sha256['condition_uri'])
          #fulfillment = PreimageSha256Fulfillment()
          #fulfillment.preimage = ''

          #assert fulfillment.serialize_uri() == fulfillment_sha256['fulfillment_uri']
          #assert fulfillment.condition.serialize_uri() == condition.serialize_uri()
          #assert fulfillment.validate()
          #assert fulfillment.validate() and fulfillment.condition.serialize_uri() == condition.serialize_uri()

      #def test_condition_from_fulfillment(self):
          #fulfillment = PreimageSha256Fulfillment()
          #with pytest.raises(ValueError):
              #fulfillment.condition

          #fulfillment.preimage = 'Hello World!'
          #condition = fulfillment.condition

          #verify_fulfillment = PreimageSha256Fulfillment()
          #verify_fulfillment.preimage = 'Hello World!'
          #assert verify_fulfillment.condition.serialize_uri() == condition.serialize_uri()
          #assert verify_fulfillment.validate()
end
