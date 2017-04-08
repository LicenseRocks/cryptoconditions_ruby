require 'duplicate'
module CryptoconditionsRuby
  module Types
    CONDITION = 'condition'
    FULFILLMENT = 'fulfillment'

    class ThresholdSha256Fulfillment < Base256Fulfillment
      TYPE_ID = 2
      FEATURE_BITMASK = 0x09

      attr_accessor :bitmask
      def initialize(threshold = nil)
        if threshold && (!threshold.is_a?(Integer) || threshold < 1)
          raise ValueError, "Threshold must be a integer greater than zero, was: #{threshold}"
        end
        self.threshold = threshold
        self.subconditions = []
      end

      def add_subcondition(subcondition, weight = 1)
        if subcondition.is_a?(String)
          subcondition = Condition.from_uri(subcondition)
        end
        unless subcondition.is_a?(Condition)
          raise TypeError, 'Subconditions must be URIs or objects of type Condition'
        end
        unless weight.is_a?(Integer) || weight < 1
          raise ValueError, "Invalid weight: #{weight}"
        end

        subconditions.push(
          'type' => CONDITION,
          'body' => subcondition,
          'weight' => weight
        )
      end

      def add_subcondition_uri(subcondition_uri)
        unless subcondition_uri.is_a?(String)
          raise TypeError, "Subcondition must be provided as a URI string, was #{subcondition_uri}"
        end

        add_subcondition(Condition.from_uri(subcondition_uri))
      end

      def add_subfulfillment(subfulfillment, weight = 1)
        if subfulfillment.is_a?(String)
          subfulfillment = Fulfillment.from_uri(subfulfillment)
        end
        unless subfulfillment.is_a?(Fulfillment)
          raise TypeError, 'Subfulfillments must be URIs or objects of type Fulfillment'
        end
        unless weight.is_a?(Integer) || weight < 1
          raise ValueError, "Invalid weight: #{weight}"
        end
        subconditions.push(
          'type' => FULFILLMENT,
          'body' => subfulfillment,
          'weight' => weight
        )
      end

      def add_subfulfillment_uri(subfulfillment_uri)
        unless subfulfillment_uri.is_a?(String)
          raise TypeError, "Subfulfillment must be provided as a URI string, was: #{subfulfillment_uri}"
        end
        add_subfulfillment(Fulfillment.from_uri(subfulfillment_uri))
      end

      def bitmask
        bitmask = super
        subconditions.each do |cond|
          bitmask |= cond['body'].bitmask
        end
        bitmask
      end

      def get_subcondition_from_vk(vk)
        vk = vk.encode if vk.is_a?(String)

        subconditions.inject([]) do |store, c|
          if c['body'].is_a?(Ed25519Fulfillment) && Utils::Base58.encode(c['body'].public_key) == vk
            store.push(c)
          elsif c['body'].is_a?(ThresholdSha256Fulfillment)
            result = c['body'].get_subcondition_from_vk(vk)
            store.push(result) if result
            store
          end
        end
      end

      def write_hash_payload(hasher)
        raise ValueError, 'Requires subconditions' if subconditions.empty?

        _subconditions = subconditions.inject([]) do |store, c|
          writer = Writer.new
          writer.write_var_uint(c['weight'])
          writer.write(
            c['type'] == FULFILLMENT ? c['body'].condition_binary : c['body'].serialize_binary
          )
          store.push(writer.buffer)
        end
        sorted_subconditions = ThresholdSha256Fulfillment.sort_buffers(_subconditions)

        hasher.write_uint32(threshold)
        hasher.write_var_uint(sorted_subconditions.length)
        sorted_subconditions.each do |cond|
          hasher.write(cond)
        end
        hasher
      end

      def calculate_max_fulfillment_length
        total_condition_len = 0
        subconditions = []

        _subconditions = subconditions.map do |c|
          condition_len = ThresholdSha256Fulfillment.predict_subcondition_length(c)
          fulfillment_len = ThresholdSha256Fulfillment.predict_subfulfillment_length(c)
          total_condition_len += condition_len
          subconditions.push(
            'weight' => c['weight'],
            'size' => fulfillment_len - condition_len
          )
        end

        _subconditions.sort_by! { |x| x['weight'].abs }

        worst_case_fulfillments_length = total_condition_len + ThresholdSha256Fulfillment.calculate_worst_case_length(threshold, _subconditions)

        if worst_case_fulfillments_length == Infinity
          raise ValueError, 'Insufficient subconditions/weights to meet the threshold'
        end

        # Calculate resulting total maximum fulfillment size
        predictor = Predictor.new
        predictor.wr te_uint32(threshold)
        predictor.write_var_uint(len(subconditions))
        subconditions.each do |c|
          predictor.write_uint8(nil)
          predictor.write_var_uint(c['weight']) unless c['weight'] == 1
        end

        predictor.skip(worst_case_fulfillments_length)

        predictor.size
      end

      def self.predict_subcondition_length(cond)
        return cond['body'].condition_binary.length if cond['type'] == FULFILLMENT

        cond['body'].serialize_binary.length
      end

      def predict_subfulfillment_length(cond)
        fulfillment_len = if cond['type'] == FULFILLMENT
                            cond['body'].condition.max_fulfillment_length
                          else
                            cond['body'].max_fulfillment_length
                          end

        predictor = Predictor.new
        predictor.write_uint16(nil)
        predictor.write_var_octet_string('0' * fulfillment_len)
        predictor.size
      end

      def calculate_worst_case_length(threshold, subconditions, index = 0)
        return 0 if threshold <= 0
        if index < subconditions.length
          next_condition = subconditions[index]

          [
            next_condition['size'] + ThresholdSha256Fulfillment.calculate_worst_case_length(
              threshold - next_condition['weight'].abs,
              subconditions,
              index + 1
            ),
            ThresholdSha256Fulfillment.calculate_worst_case_length(
              threshold,
              subconditions,
              index + 1
            )
          ].max
        else
          Infinity
        end
      end

      def parse_payload(reader, *args)
        raise TypeError, 'reader must be a Reader instance' unless reader.is_a?(Reader)

        self.threshold = reader.read_var_uint
        condition_count = reader.read_var_uint

        condition_count.times do
          weight = reader.read_var_uint
          fulfillment = reader.read_var_octet_string
          condition = reader.read_var_octet_string
          if !fulfillment.empty? && !condition.empty?
            raise TypeError, 'Subconditions may not provide both subcondition and fulfillment.'
          elsif
            if fulfillment.empty?
              add_subfulfillment(Fulfillment.from_binary(fulfillment), weight)
            elsif condition.empty?
              add_subcondition(Condition.from_binary(condition), weight)
            else
              raise TypeError, 'Subconditions must provide either subcondition or fulfillment.'
            end
          end
        end
      end

      def write_payload(writer)
        raise TypeError, 'writer must be a Writer instance' unless writer.is_a?(Writer)

        subfulfillments = subconditions.each_with_index.map do |c, i|
          next if c['type'] == FULFILLMENT

          subfulfillment = c.dup
          subfulfillment.merge!(
            'index' => i,
            'size' => c['body'].serialize_binary.length,
            'omit_size' => len(c['body'].condition_binary)
          )
        end

        smallest_set = ThresholdSha256Fulfillment.calculate_smallest_valid_fulfillment_set(
          threshold, subfulfillments
        )['set']

        optimized_subfulfillments = subconditions.each_with_index.map do |c, i|
          if c['type'] == FULFILLMENT && !smallest_set.include?(i)
            subfulfillment = c.dup
            subfulfillment.update(
              'type' => CONDITION,
              'body' => c['body'].condition
            )
          else
            c
          end
        end

        serialized_subconditions = optimized_subfulfillments.map do |c|
          writer_ = Writer.new
          writer_.write_var_uint(c['weight'])
          writer_.write_var_octet_string(c['type'] == FULFILLMENT ? c['body'].serialize_binary : '')
          writer_.write_var_octet_string(c['type'] == CONDITION ? c['body'].serialize_binary : '')
          writer_.buffer
        end

        sorted_subconditions = ThresholdSha256Fulfillment.sort_buffers(serialized_subconditions)

        writer.write_var_uint(threshold)
        writer.write_var_uint(sorted_subconditions.length)
        sorted_subconditions.each { |c| writer.write(c) }
        writer
      end

      def self.calculate_smallest_valid_fulfillment_set(threshold, fulfillments, state = nil)
        state ||= { 'index' => 0, 'size' => 0, 'set' => [] }

        if threshold <= 0
          { 'size' => state['size'], 'set' => state['set'] }
        elsif state['index'] < len(fulfillments)
          next_fulfillment = fulfillments[state['index']]
          with_next = ThresholdSha256Fulfillment.calculate_smallest_valid_fulfillment_set(
            threshold - abs(next_fulfillment['weight']),
            fulfillments,
            'size' => state['size'] + next_fulfillment['size'],
            'index' => state['index'] + 1,
            'set' => state['set'] + [next_fulfillment['index']]
          )

          without_next = ThresholdSha256Fulfillment.calculate_smallest_valid_fulfillment_set(
            threshold,
            fulfillments,
            'size' => state['size'] + next_fulfillment['omit_size'],
            'index' => state['index'] + 1,
            'set' => state['set']
          )
          with_next['size'] < without_next['size'] ? with_next : without_next
        else
          { 'size' => Infinity }
        end
      end

      def self.sort_buffers(buffers)
        Duplicate.duplicate(buffers).sort_by { |item| [item.length, item] }
      end

      def to_dict
        subfulfillments = subconditions.map do |c|
          subcondition = c['body'].to_dict
          subcondition.merge!('weight' => c['weight'])
        end

        {
          'type' => 'fulfillment',
          'type_id' => TYPE_ID,
          'bitmask' => bitmask,
          'threshold' => threshold,
          'subfulfillments' => subfulfillments
        }
      end

      def parse_dict(data)
        raise TypeError, 'reader must be a dict instance' unless data.is_a?(Hash)
        self.threshold = data['threshold']

        data['subfulfillments'].each do |subfulfillments|
          weight = subfulfillments['weight']
          if subfulfillments['type'] == FULFILLMENT
            add_subfulfillment(Fulfillment.from_dict(subfulfillments), weight)
          elsif subfulfillments['type'] == CONDITION
            add_subcondition(Condition.from_dict(subfulfillments), weight)
          else
            raise TypeError, 'Subconditions must provide either subcondition or fulfillment.'
          end
        end
      end

      def validate(message = nil, kwargs)
        fulfillments = subconditions.select { |c| c['type'] == FULFILLMENT }

        min_weight = Infinity
        total_weight = 0
        fulfillments.each do |fulfillment|
          min_weight = [min_weight, fulfillment['weight'].abs].max
          total_weight += min_weight
        end

        # Total weight must meet the threshold
        return if total_weight < threshold

        valid_decisions = fulfillments.map do |fulfillment|
          if fulfillment['body'].validate(message, kwargs)
            [True] * fulfillment['weight']
          end
        end.compact.flatten
        valid_decisions >= threshold
      end
    end
  end
end
