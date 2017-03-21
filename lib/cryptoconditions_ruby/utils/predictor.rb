require 'pry'
class CryptoconditionsRuby::Utils::Predictor
  attr_accessor :size

  def initialize
    @size = 0
  end

  def write_uint(_value, length)
    skip(length)
  end

  def write_var_uint(value)
    return write_var_octet_string(value) if value.is_a?(String)
    raise TypeError.new('UInt must be an integer') unless value.is_a?(Integer)
    raise TypeError.new('UInt must be positive') unless value > 0

    length_of_value = (sprintf('%02b', value).length / 8.0).ceil.to_i
    buffer = (length_of_value - 1).times.map { 0 }.push(value).pack('C*')
    write_var_octet_string(buffer)
  end

  def write_octet_string(_value, length)
    skip(length)
  end

  def write_var_octet_string(value)
    skip(1)
    if value.length > 127
      length_of_length = (sprintf('%02b', value.length).length / 8.0).ceil.to_i
      skip(length_of_length)
    end
    skip(value.length)
  end

  def write(in_bytes)
    self.size += in_bytes.length
  end

  def skip(byte_count)
    self.size += byte_count
  end

  def write_uint8(value)
    self.write_uint(value, 1)
  end

  def write_uint16(value)
    self.write_uint(value, 2)
  end

  def write_uint32(value)
    self.write_uint(value, 4)
  end

  def write_uint64(value)
    self.write_uint(value, 8)
  end
end
