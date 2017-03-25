require 'spec_helper'

describe CryptoconditionsRuby::Utils::Reader do
  describe '.from_source' do
    let(:buffer_string) { "\x10\x10\x10" }
    context 'source is a Reader instance' do
      let(:buffer) { described_class.new(buffer_string) }

      it 'returns the instance' do
        expect(described_class.from_source(buffer)).to eq(buffer)
      end
    end

    context 'source is a buffer' do
      let(:buffer) { buffer_string }

      it 'returns a new instance' do
        expect(described_class.from_source(buffer)).to be_a(described_class)
      end
    end
  end

  describe '#bookmark' do
    subject { described_class.new("\x10") }
    it 'pushes the current cursor onto the bookmarks' do
      subject.bookmark
      expect(subject.bookmarks).to eq([0])
    end
  end

  describe '#restore' do
    subject { described_class.new("\x10") }

    it 'restores the cursor' do
      subject.bookmark
      expect(subject.bookmarks).to eq([0])
      subject.restore
      expect(subject.bookmarks).to be_empty
    end
  end

  describe '#ensure_available' do
    subject { described_class.new("\x10\10") }
    context 'buffer length less than cursor plus no of bytes' do
      it 'raises an error' do
        expect { subject.ensure_available(3) }.to raise_error(RangeError)
      end
    end
  end

  describe '#read_uint' do
    subject { described_class.new([16,15,14,13,12].pack("C*")) }

    context 'length is greater than the max' do
      it 'raises an error' do
        expect { subject.read_uint(17) }.to raise_error(RangeError)
      end
    end

    context 'ensures available' do
      it 'raises an error' do
        expect { subject.read_uint(6) }.to raise_error(RangeError)
      end
    end

    context 'otherwise' do
      it 'returns the uint value of length of the buffer and moves the cursor' do
        expect(subject.read_uint(4)).to eq(269422093)
        expect(subject.cursor).to eq(4)
      end
    end
  end

  describe '#peek_uint' do
    subject { described_class.new([16,15,14,13,12].pack("C*")) }

    it 'returns the uint value of the length of the buffer without moving the cursor' do
      expect(subject.peek_uint(4)).to eq(269422093)
      expect(subject.cursor).to eq(0)
    end
  end

  describe '#skip_uint' do
    subject { described_class.new([16,16,16].pack("C*")) }

    context 'ensures available' do
      it 'raises an error' do
        expect { subject.skip_uint(4) }.to raise_error(RangeError)
      end
    end

    it 'moves the cursor by the given length' do
      subject.skip_uint(3)
      expect(subject.cursor).to eq(3)
    end
  end

  describe '#read_var_uint' do
    context 'length is greater than the max' do
      subject { described_class.new(16.times.map { 16 }.pack("C*")) }

      it 'raises an error' do
        expect { subject.read_var_uint }.to raise_error(RangeError)
      end
    end

    context 'otherwise' do
      subject { described_class.new([04,16,16,16,16].pack("C*")) }

      it 'returns the uint value of length of the buffer and moves the cursor' do
        expect(subject.read_var_uint).to eq(269488144)
        expect(subject.cursor).to eq(5)
      end
    end
  end

  describe '#peek_var_uint' do
    subject { described_class.new([04,16,16,16,16].pack("C*")) }

    it 'returns the uint value of length of the buffer while not moving the cursor' do
      expect(subject.peek_var_uint).to eq(269488144)
      expect(subject.cursor).to eq(0)
    end
  end
end
