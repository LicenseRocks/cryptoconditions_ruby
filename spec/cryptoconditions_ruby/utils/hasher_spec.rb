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
        210, 106, 142, 69, 29, 249, 59, 240, 148, 97, 230,
        62, 241, 25, 118, 167, 81, 186, 125, 98, 240, 161,
        247, 175, 239, 112, 120, 59, 228, 212, 223, 165
      ].pack('C*')
    end

    before do
      subject.write([100, 200, 300])
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
