require 'spec_helper'

module CryptoconditionsRuby
  describe Fulfillment do
    describe '.from_uri' do
      context 'argument is a fulfillment' do
        let(:fulfillment) { described_class.new }
        it 'returns the fulfillment' do
          expect(described_class.from_uri(fulfillment)).to eq(fulfillment)
        end
      end

      context 'not a string' do
        it 'raises an error' do
          expect { described_class.from_uri(123) }.to raise_error(TypeError)
        end
      end

      context 'string does not start with cf' do
        it 'raises an error' do
          expect { described_class.from_uri('foo:bar') }.to raise_error(TypeError)
        end
      end

      context 'string does not match the fulfillment regex' do
        it 'raises an error' do
          expect { described_class.from_uri('cf:abbb:!') }.to raise_error(TypeError)
        end
      end

      context 'fulfillment is valid' do
        it 'initializes the correct fulfillment and parses the payload' do
          skip 'need to implement other stuff first'
        end
      end
    end
  end
end
