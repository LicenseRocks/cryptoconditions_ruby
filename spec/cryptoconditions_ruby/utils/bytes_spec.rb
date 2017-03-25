require 'spec_helper'

describe CryptoconditionsRuby::Utils::Bytes do
  describe '#to_i' do
    context 'input is an array' do
      context 'base 16' do
        subject { described_class.new([16,16,16]) }

        it 'returns the bytes as a base 10 integer' do
          expect(subject.to_i(16)).to eq(1052688)
        end
      end

      context 'base 10' do
        subject { described_class.new([12,34,56]) }

        it 'returns the bytes as a base 10 integer' do
          expect(subject.to_i(10)).to eq(123456)
        end
      end
    end

    context 'input is a byte string' do
      subject { described_class.new("\x10\x10\x10") }

      it 'returns the bytes as a base 10 integer' do
        expect(subject.to_i(16)).to eq(1052688)
      end
    end
  end
end
