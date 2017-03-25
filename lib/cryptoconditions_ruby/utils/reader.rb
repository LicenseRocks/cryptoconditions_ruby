require 'pry'
class CryptoconditionsRuby::Utils::Reader
  HIGH_BIT = 0x80
  LOWER_SEVEN_BITS = 0x7F
  MAX_INT_BYTES = 6

  attr_accessor :bookmarks, :buffer, :cursor
  def initialize(buffer)
    @buffer = buffer
    @cursor = 0
    @bookmarks = []
  end

  def self.from_source(source)
    source.is_a?(self) ? source : new(source)
  end

  def bookmark
    self.bookmarks << cursor
  end

  def restore
    self.cursor = bookmarks.pop
  end

  def ensure_available(num_bytes)
    if buffer.length < cursor + num_bytes
      raise RangeError.new("Tried to read #{num_bytes} bytes, but only #{buffer.length - cursor} bytes available")
    end
  end

  def read_uint(length, peek: false)
    if length > MAX_INT_BYTES
      raise RangeError.new("Tried to read too large integer (requested: #{length}, max: #{MAX_INT_BYTES})")
    end
    ensure_available(length)
    value = buffer[cursor...(cursor + length)]
    self.cursor += length unless peek
    CryptoconditionsRuby::Utils::Bytes.new(value).to_i(16)
  end

  def peek_uint(length)
    read_uint(length, peek: true)
  end

  def skip_uint(length)
    skip(length)
  end

  def read_var_uint
    buffer = read_var_octet_string
    if buffer.length > MAX_INT_BYTES
      raise RangeError.new("UInt of length #{butter.length} too large to parse as integer(#{MAX_INT_BYTES})")
    end
    value = buffer[0...buffer.length]
    CryptoconditionsRuby::Utils::Bytes.new(value).to_i(16)
  end

  def peek_var_uint
    bookmark
    read_var_uint.tap { restore }
  end

  def skip_var_uint
    skip_var_octet_string
  end

  def read_octet_string(length)
    read(length)
  end

  def peek_octet_string(length)
    peek(length)
  end

  def skip_octet_string(length)
    skip(length)
  end

  def read_length_prefix
    length = read_uint8

    if length & HIGH_BIT > 0
      read_uint(length & LOWER_SEVEN_BITS)
    end
    length
  end

  def read_var_octet_string
    length = read_length_prefix
    read(length)
  end

  def peek_var_octet_string
    bookmark
    read_var_octet_string.tap { restore }
  end

  def skip_var_octet_string
    length = read_length_prefix
    skip(length)
  end

  def read(num_bytes, peek: false)
    ensure_available(num_bytes)

    value = buffer[cursor...(cursor + num_bytes)]
    self.cursor += num_bytes unless peek
    value
  end

  def peek(num_bytes)
    read(num_bytes, peek: true)
  end

  def skip(num_bytes)
    ensure_available(num_bytes)
    self.cursor += num_bytes
  end

  def read_uint8
    read_uint(1)
  end

  def read_uint16
    read_uint(2)
  end

  def read_uint32
    read_uint(4)
  end

  def read_uint64
    read_uint(8)
  end

  def peek_uint8
    peek_uint(1)
  end

  def peek_uint16
    peek_uint(2)
  end

  def peek_uint32
    peek_uint(4)
  end

  def peek_uint64
    peek_uint(8)
  end

  def skip_uint8
    skip_uint(1)
  end

  def skip_uint16
    skip_uint(2)
  end

  def skip_uint32
    skip_uint(4)
  end

  def skip_uint64
    skip_uint(8)
  end
end
