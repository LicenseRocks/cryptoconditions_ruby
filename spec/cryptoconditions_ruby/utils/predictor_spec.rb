require 'spec_helper'

describe CryptoconditionsRuby::Utils::Predictor do
  subject { described_class.new }

  describe '#write_uint' do
    it 'returns the size plus the given length' do
      expect(subject.write_uint(double, 10)).to eq(10)
    end
  end

  describe '#write_var_uint' do
    context 'value is a string' do
      it 'returns an octet string' do
        expect(subject.write_var_uint('abcdefghijklmnop')).to eq(17)
      end
    end

    context 'not an integer' do
      it 'raises an error' do
        expect { subject.write_var_uint([]) }.to raise_error(TypeError)
      end
    end

    context 'value is a negative integer' do
      it 'raises an error' do
        expect { subject.write_var_uint(-1) }.to raise_error(TypeError)
      end
    end

    context 'value is a positive integer' do
      it 'returns an octet string' do
        expect(subject.write_var_uint(1_000_000)).to eq(4)
      end
    end
  end

  describe '#write_octet_string' do
    before { subject.skip(2) }

    it 'returns the stored size plus the length' do
      expect(subject.write_octet_string(double, 10)).to eq(12)
    end
  end

  describe '#write_var_octet_string' do
    context 'length of value exceeds 127' do
      let(:value) { 128.times.map { 0 }.join }

      it 'returns the size plus a skip plus a skipped byte plus the length' do
        expect(subject.write_var_octet_string(value)).to eq(130)
      end
    end

    context 'length of value is below or equal to 127' do
      let(:value) { 127.times.map { 0 }.join }

      it 'returns a skip plus the length' do
        expect(subject.write_var_octet_string(value)).to eq(128)
      end
    end
  end

  describe '#write' do
    before { subject.skip(2) }

    it 'returns the length of the provided bytes plus the size' do
      expect(subject.write('hello')).to eq(7)
    end
  end

  describe '#skip' do
    before { subject.skip(2) }

    it 'skips the length given' do
      expect(subject.skip(10)).to eq(12)
    end
  end

  describe '#write_uint8' do
    it 'skips 1 byte' do
      expect(subject.write_uint8(double)).to eq(1)
    end
  end

  describe '#write_uint16' do
    it 'skips 2 bytes' do
      expect(subject.write_uint16(double)).to eq(2)
    end
  end

  describe '#write_uint32' do
    it 'skips 4 bytes' do
      expect(subject.write_uint32(double)).to eq(4)
    end
  end

  describe '#write_uint64' do
    it 'skips 8 bytes' do
      expect(subject.write_uint64(double)).to eq(8)
    end
  end
end
