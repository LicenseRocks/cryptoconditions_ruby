class CryptoconditionsRuby::Utils::Bytes
  attr_reader :bytes
  private :bytes
  def initialize(input)
    @bytes = input.is_a?(Array) ? input : input.bytes
  end

  def to_i(base)
    bytes.reverse.each_with_index.inject(0) do |store, (byte, index)|
      store += byte * base**(index * 2)
    end
  end
end
