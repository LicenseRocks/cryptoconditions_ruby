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
      let(:value) { [254, 254].pack('C*') }

      it 'returns an array containing a binary packed value' do
        expect(subject.write_var_uint(value)).to eq([[2].pack('C*'), [254, 254].pack('C*')])
      end
    end

    context 'value is a positive integer' do
      let(:value) { 20_000_000 }

      it 'returns an array containing a binary packed value' do
        expect(subject.write_var_uint(value)).to eq(
          [[4], [0, 0, 0, 0]].map { |ary| ary.pack('C*') }
        )
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
      let(:value) { Array.new(127) { [5].pack("C*") } }

      it 'prepends the value with the length' do
        expect(subject.write_var_octet_string(value).first).to eq([127].pack('C*'))
      end
    end

    context 'buffer length is greater than 128' do
      let(:value) { Array.new(130) { [5].pack("C*") } }

      it 'prepends the value with the length and the length of the length' do
        expect(subject.write_var_octet_string(value).slice(0..1)).to eq(
          [[129], [130]].map { |ary| ary.pack('C*') }
        )
      end
    end
  end

  describe '#write' do
    it 'writes the input to the buffer' do
      expect(subject.write('hello')).to eq(['hello'])
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

  context 'writing various values' do
    let(:type_id) { 4 }
    let(:bitmask) { 32 }
    let(:_hash) do
      [
        236, 23, 43, 147, 173, 94, 86, 59, 244,
        147, 44, 112, 225, 36, 80, 52, 195, 84,
        103, 239, 46, 253, 77, 100, 235, 248,
        25, 104, 52, 103, 226, 191
      ].pack('C*')
    end
    let(:max_fulfillment_length) { 96 }

    it 'returns the correct buffer' do
      subject.write_uint16(type_id)
      expect(subject.components).to eq(["\x00\x04"])

      subject.write_var_uint(bitmask)
      expect(subject.components).to eq(["\x00\x04", "\x01", ' '])

      subject.write_var_octet_string(_hash)
      expect(subject.components).to eq(["\x00\x04", "\x01", ' ', ' ', _hash])

      subject.write_var_uint(max_fulfillment_length)
      expect(subject.components).to eq(["\x00\x04", "\x01", ' ', ' ', _hash, "\x01", '`'])
    end
  end
end
