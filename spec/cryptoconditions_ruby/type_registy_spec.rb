require 'spec_helper'

describe CryptoconditionsRuby::TypeRegistry do
  describe '.get_class_from_type_id' do
    context 'id is greater than max safe for js' do
      it 'raises an error' do
        expect { described_class.get_class_from_type_id(2**53) }.to raise_error(TypeError)
      end
    end

    context 'type is not registered' do
      it 'raises and error' do
        expect { described_class.get_class_from_type_id(10) }.to raise_error(TypeError)
      end
    end

    context 'otherwise' do
      let(:my_type) { Class.new { TYPE_ID = 12 } }
      before { described_class.register_type(my_type) }

      it 'returns the class name' do
        expect(described_class.get_class_from_type_id(12)).to eq(my_type)
      end
    end
  end
end
