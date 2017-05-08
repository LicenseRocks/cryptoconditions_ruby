require 'spec_helper'

describe CryptoconditionsRuby::Utils::Hasher do
  describe '#new' do
    context 'algorithm is not a SHA256' do
      it 'returns an error' do
        expect { described_class.new('md5') }.to raise_error NotImplementedError
      end
    end
  end

  describe '#digest' do
    subject { described_class.new('sha256') }
    let(:expected) do
      [
        44, 242, 77, 186, 95, 176, 163, 14, 38, 232, 59, 42, 197, 185, 226, 158, 27, 22, 30, 92,
        31, 167, 66, 94, 115, 4, 51, 98, 147, 139, 152, 36
      ].pack('C*')
    end

    before do
      subject.write('hello')
    end

    it 'returns the digest' do
      expect(subject.digest).to eq(expected)
    end
  end

  describe '.length' do
    it 'returns the length of the digest' do
      expect(described_class.length('sha256')).to eq(32)
    end
  end
end
