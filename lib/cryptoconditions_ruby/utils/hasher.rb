require 'digest'

class CryptoconditionsRuby::Utils::Hasher < CryptoconditionsRuby::Utils::Writer
  attr_reader :digest_instance
  private :digest_instance

  def initialize(algorithm)
    if algorithm == 'sha256'
      @digest_instance = Digest::SHA256.new
    else
      raise NotImplementedError
    end
    super()
  end

  def write(in_bytes)
    digest_instance.update(in_bytes)
  end

  def digest
    digest_instance.digest
  end

  def self.length(algorithm)
    new(algorithm).digest.length
  end
end
