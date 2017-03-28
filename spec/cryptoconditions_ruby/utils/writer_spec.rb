require 'spec_helper'

describe CryptoconditionsRuby::Utils::Writer do
  subject { described_class.new }

  describe '#write_uint' do
    context 'value is not an integer' do
      let(:value) { 'hello' }

      it 'raises an exception' do
        expect { subject.write_uint(value, 10) }.to raise_error TypeError
      end
    end

    context 'value is negative' do
      let(:value) { -4 }

      it 'raises an exception' do
        expect { subject.write_uint(value, 10 ) }.to raise_error TypeError
      end
    end

    context 'value byte length longer than length given' do
      let(:value) { 20_000_000 }

      it 'raises an exception' do
        expect { subject.write_uint(value, 3) }.to raise_error TypeError
      end
    end

    context 'value byte length less than length given' do
      let(:value) { 20_000_000 }

      it 'raises returns an array containing a binary packed value' do
        expect(subject.write_uint(value, 4)).to eq([[0, 0, 0, 0].pack('C*')])
      end
    end
  end

  describe '#write_var_uint' do
    context 'value is a string' do
      let(:value) { 'hello' }

      it 'returns an array containing a binary packed value' do
        expect(subject.write_var_uint(value)).to eq([[5].pack("C*")])
      end
    end

    context 'value is a positive integer' do
      let(:value) { 20_000_000 }

      it 'returns an array containing a binary packed value' do
        expect(subject.write_var_uint(value)).to eq([[4].pack("C*")])
      end
    end

    context 'value is neither a string nor an integer' do
      let(:value) { [] }

      it 'raises an exception' do
        expect { subject.write_var_uint(value) }.to raise_error TypeError
      end
    end

    context 'value is negative' do
      let(:value) { -4 }

      it 'raises an exception' do
        expect { subject.write_var_uint(value) }.to raise_error TypeError
      end
    end
  end

  describe '#write_var_octet_string' do
    context 'buffer length is less than 128' do
      let(:value) { 127.times.map { [5].pack("C*") } }

      it 'returns an array containing a binary packed value' do
        expect(subject.write_var_octet_string(value)).to eq([[127].pack("C*")])
      end
    end

    context 'buffer length is greater than 128' do
      let(:value) { 130.times.map { [5].pack("C*") } }

      it 'returns an array containing a binary packed value' do
        expect(subject.write_var_octet_string(value)).to eq([[129], [130]].map { |ary| ary.pack("C*") })
      end
    end
  end

  describe '#write' do
    context 'input is an array' do
      let(:value) { [129, 130, 131, 132] }

      it 'writes the raw bytes to the output buffer' do
        expect(subject.write(value)).to eq([[129, 130, 131, 132].pack("C*")])
      end
    end

    context 'input is a list of bytes' do
      let(:value) { [129, 130, 131, 132].pack("C*") }

      it 'writes the raw bytes to the output buffer' do
        expect(subject.write(value)).to eq([[129, 130, 131, 132].pack("C*")])
      end
    end

    context 'input is not utf8' do
      let(:value) { 'hällö'.encode("ISO-8859-1") }

      it 'writes th' do
        expect(subject.write(value)).to eq(['hällö'])
      end
    end
  end

  describe '#write_uint8' do
    let(:value) { (2**8 - 1) }

    it 'writes a binary encoded value to the buffer' do
      expect(subject.write_uint8(value)).to eq([[value]].map { |ary| ary.pack("C*") })
    end
  end

  describe '#write_uint16' do
    let(:value) { (2**16 - 1) }
    let(:padding) { 1.times.map { 0 } }

    it 'writes a binary encoded value to the buffer' do
      expect(subject.write_uint16(value)).to eq([padding + [value]].map { |ary| ary.pack("C*") })
    end
  end

  describe '#write_uint32' do
    let(:value) { (2**32 - 1) }
    let(:padding) { 3.times.map { 0 } }

    it 'writes a binary encoded value to the buffer' do
      expect(subject.write_uint32(value)).to eq([padding + [value]].map { |ary| ary.pack("C*") })
    end
  end

  describe '#write_uint64' do
    let(:value) { (2**64 - 1) }
    let(:padding) { 7.times.map { 0 } }

    it 'writes a binary encoded value to the buffer' do
      expect(subject.write_uint64(value)).to eq([padding + [value]].map { |ary| ary.pack("C*") })
    end
  end
end
