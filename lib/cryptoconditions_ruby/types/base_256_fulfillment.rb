module Cryptoconditions
  module Types
    class Base256Fulfillment < Fulfillment
      def generate_hash
        hasher = Utils::Hasher.new('sha256')
        write_hash_payload(hasher)
        hasher.digest
      end

      def write_hash_payload(_hasher)
        raise 'Implement me'
      end
    end
  end
end
