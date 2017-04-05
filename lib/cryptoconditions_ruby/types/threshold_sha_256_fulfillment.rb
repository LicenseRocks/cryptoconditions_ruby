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
        if !subcondition.is_a?(Condition)
          raise TypeError, 'Subconditions must be URIs or objects of type Condition'
        end
        if !weight.is_a?(Integer) || weight < 1
          raise ValueError, "Invalid weight: #{weight}"
        end

        subconditions.push({
          'type' => CONDITION,
          'body' => subcondition,
          'weight' => weight
        })
      end

      def add_subcondition_uri(subcondition_uri)
        if !subcondition_uri.is_a?(String)
          raise TypeError, "Subcondition must be provided as a URI string, was #{subcondition_uri}"
        end
        self.add_subcondition(Condition.from_uri(subcondition_uri))
      end

      def add_subfulfillment(subfulfillment, weight = 1)
        if subfulfillment.is_a?(String)
          subfulfillment = Fulfillment.from_uri(subfulfillment)
        end
        if !subfulfillment.is_a?(Fulfillment)
          raise TypeError, 'Subfulfillments must be URIs or objects of type Fulfillment'
        end
        if !weight.is_a?(Integer) || weight < 1
          raise ValueError, "Invalid weight: #{weight}"
        end
        subconditions.push({
          'type' => FULFILLMENT,
          'body' => subfulfillment,
          'weight' => weight
        })

        def add_subfulfillment_uri(subfulfillment_uri)
          if !subfulfillment_uri.is_a?(String)
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
              if result
                store.push(result)
              end
              store
            end
          end
        end

        def write_hash_payload(hasher)
          if subconditions.empty?
            raise ValueError, 'Requires subconditions'
          end
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

        def calculate_max_fulfillment_length(self):
            """
            Calculates the longest possible fulfillment length.

            In a threshold condition, the maximum length of the fulfillment depends on
            the maximum lengths of the fulfillments of the subconditions. However,
            usually not all subconditions must be fulfilled in order to meet the threshold.

            Consequently, this method relies on an algorithm to determine which
            combination of fulfillments, where no fulfillment can be left out, results
            in the largest total fulfillment size.

            Return:
                 int: Maximum length of the fulfillment payload

            """
            total_condition_len = 0
            subconditions = []
            for c in self.subconditions:
                condition_len = ThresholdSha256Fulfillment.predict_subcondition_length(c)
                fulfillment_len = ThresholdSha256Fulfillment.predict_subfulfillment_length(c)
                total_condition_len += condition_len
                subconditions.append({
                    'weight': c['weight'],
                    'size': fulfillment_len - condition_len
                })

            subconditions.sort(key=lambda x: abs(x['weight']))

            worst_case_fulfillments_length = total_condition_len + \
                ThresholdSha256Fulfillment.calculate_worst_case_length(self.threshold, subconditions)

            if worst_case_fulfillments_length == float('-inf'):
                raise ValueError('Insufficient subconditions/weights to meet the threshold')

            # Calculate resulting total maximum fulfillment size
            predictor = Predictor()
            predictor.write_uint32(self.threshold)             # threshold
            predictor.write_var_uint(len(self.subconditions))  # count
            for c in self.subconditions:
                predictor.write_uint8(None)                        # presence bitmask
                if not c['weight'] == 1:
                    # write_weight(predictor, c['weight'])
                    predictor.write_var_uint(c['weight'])      # weight

            # Represents the sum of CONDITION/FULFILLMENT values
            predictor.skip(worst_case_fulfillments_length)

            return predictor.size

        @staticmethod
        def predict_subcondition_length(cond):
            return len(cond['body'].condition_binary) \
                if cond['type'] == FULFILLMENT \
                else len(cond['body'].serialize_binary())

        @staticmethod
        def predict_subfulfillment_length(cond):
            fulfillment_len = cond['body'].condition.max_fulfillment_length \
                if cond['type'] == FULFILLMENT \
                else cond['body'].max_fulfillment_length

            predictor = Predictor()
            predictor.write_uint16(None)                       # type
            predictor.write_var_octet_string(b'0' * fulfillment_len)  # payload

            return predictor.size

        @staticmethod
        def calculate_worst_case_length(threshold, subconditions, index=0):
            """
            Calculate the worst case length of a set of conditions.

            This implements a recursive algorithm to determine the longest possible
            length for a valid, minimal (no fulfillment can be removed) set of subconditions.

            Note that the input array of subconditions must be sorted by weight descending.

            The algorithm works by recursively adding and not adding each subcondition.
            Finally, it determines the maximum of all valid solutions.

            Author:
                Evan Schwartz <evan@ripple.com>

            Args:
                threshold (int): Threshold that the remaining subconditions have to meet.
                subconditions (:obj:`list` of :class:`~cryptoconditions.condition.Condition`): Set of subconditions.

                    * ``subconditions[].weight`` Weight of the subcondition
                    * ``subconditions[].size`` Maximum number of bytes added to the
                      size if the fulfillment is included.
                    * ``subconditions[].omitSize`` Maximum number of bytes added to
                      the size if the fulfillment is omitted (and the
                      condition is added instead.)

                index (int): Current index in the subconditions array (used by the recursive calls.)

            Returns:
                int: Maximum size of a valid, minimal set of fulfillments or -inf if there is no valid set.
            """
            if threshold <= 0:
                return 0
            elif index < len(subconditions):
                next_condition = subconditions[index]
                return max(
                    next_condition['size'] + ThresholdSha256Fulfillment.calculate_worst_case_length(
                        threshold - abs(next_condition['weight']), subconditions, index + 1),
                    ThresholdSha256Fulfillment.calculate_worst_case_length(threshold, subconditions, index + 1)
                )
            else:
                return float('-inf')

        def parse_payload(self, reader, *args):
            """
            Parse a fulfillment payload.

            Read a fulfillment payload from a Reader and populate this object with that fulfillment.

            Args:
                reader (Reader): Source to read the fulfillment payload from.
            """
            if not isinstance(reader, Reader):
                raise TypeError('reader must be a Reader instance')
            self.threshold = reader.read_var_uint()

            condition_count = reader.read_var_uint()
            for i in range(condition_count):
                weight = reader.read_var_uint()
                # reader, weight = read_weight(reader)
                fulfillment = reader.read_var_octet_string()
                condition = reader.read_var_octet_string()

                if len(fulfillment) and len(condition):
                    raise TypeError('Subconditions may not provide both subcondition and fulfillment.')
                elif len(fulfillment):
                    self.add_subfulfillment(Fulfillment.from_binary(fulfillment), weight)
                elif len(condition):
                    self.add_subcondition(Condition.from_binary(condition), weight)
                else:
                    raise TypeError('Subconditions must provide either subcondition or fulfillment.')

        def write_payload(self, writer):
            """
            Generate the fulfillment payload.

            This writes the fulfillment payload to a Writer.

            .. code-block:: none

                FULFILLMENT_PAYLOAD =
                    VARUINT THRESHOLD
                    VARARRAY
                        VARUINT WEIGHT
                        FULFILLMENT
                    VARARRAY
                        VARUINT WEIGHT
                        CONDITION

            Args:
                writer (Writer): Subject for writing the fulfillment payload.
            """
            if not isinstance(writer, Writer):
                raise TypeError('writer must be a Writer instance')

            subfulfillments = []
            for i, c in enumerate(self.subconditions):
                if c['type'] == FULFILLMENT:
                    subfulfillment = c.copy()
                    subfulfillment.update(
                        {
                            'index': i,
                            'size': len(c['body'].serialize_binary()),
                            'omit_size': len(c['body'].condition_binary)
                        }
                    )
                    subfulfillments.append(subfulfillment)

            # FIXME: KeyError due to returned `{'size': inf}` when self.threshold > len(subfulfillments)
            smallest_set = \
                ThresholdSha256Fulfillment.calculate_smallest_valid_fulfillment_set(self.threshold, subfulfillments)['set']

            optimized_subfulfillments = []
            for i, c in enumerate(self.subconditions):
                # Take minimum set of fulfillments and turn rest into conditions
                if c['type'] == FULFILLMENT and i not in smallest_set:
                    subfulfillment = c.copy()
                    subfulfillment.update({
                        'type': CONDITION,
                        'body': c['body'].condition
                    })
                    optimized_subfulfillments.append(subfulfillment)
                else:
                    optimized_subfulfillments.append(c)

            serialized_subconditions = []
            for c in optimized_subfulfillments:
                writer_ = Writer()
                # writer_ = write_weight(writer_, c['weight'])
                writer_.write_var_uint(c['weight'])
                writer_.write_var_octet_string(c['body'].serialize_binary() if c['type'] == FULFILLMENT else '')
                writer_.write_var_octet_string(c['body'].serialize_binary() if c['type'] == CONDITION else '')
                serialized_subconditions.append(writer_.buffer)

            sorted_subconditions = ThresholdSha256Fulfillment.sort_buffers(serialized_subconditions)

            writer.write_var_uint(self.threshold)
            writer.write_var_uint(len(sorted_subconditions))
            for c in sorted_subconditions:
                writer.write(c)

            return writer

        @staticmethod
        def calculate_smallest_valid_fulfillment_set(threshold, fulfillments, state=None):
            """
            Select the smallest valid set of fulfillments.

            From a set of fulfillments, selects the smallest combination of
            fulfillments which meets the given threshold.

            Args:
                threshold (int): (Remaining) threshold that must be met.
                fulfillments ([{}]): Set of fulfillments
                state (dict): Used for recursion
                              state.index (int): Current index being processed.
                              state.size (int): Size of the binary so far
                              state.set ([{}]): Set of fulfillments that were included.
            Returns:
                (dict): Result with size and set properties.
            """
            if not state:
                state = {'index': 0, 'size': 0, 'set': []}

            if threshold <= 0:
                return {'size': state['size'], 'set': state['set']}
            elif state['index'] < len(fulfillments):
                next_fulfillment = fulfillments[state['index']]
                with_next = ThresholdSha256Fulfillment.calculate_smallest_valid_fulfillment_set(
                    threshold - abs(next_fulfillment['weight']),
                    fulfillments,
                    {
                        'size': state['size'] + next_fulfillment['size'],
                        'index': state['index'] + 1,
                        'set': state['set'] + [next_fulfillment['index']]
                    }
                )

                without_next = ThresholdSha256Fulfillment.calculate_smallest_valid_fulfillment_set(
                    threshold,
                    fulfillments,
                    {
                        'size': state['size'] + next_fulfillment['omit_size'],
                        'index': state['index'] + 1,
                        'set': state['set']
                    }
                )
                return with_next if with_next['size'] < without_next['size'] else without_next
            else:
                return {'size': float("inf")}

        @staticmethod
        def sort_buffers(buffers):
            """
            Sort buffers according to spec.

            Buffers must be sorted first by length. Buffers with the same length are sorted lexicographically.

            Args:
                buffers ([]): Set of octet strings to sort.

            Returns:
                Sorted buffers.
            """
            buffers_copy = copy.deepcopy(buffers)
            buffers_copy.sort(key=lambda item: (len(item), item))
            return buffers_copy

        def to_dict(self):
            """
            Generate a dict of the fulfillment

            Returns:
                dict: representing the fulfillment
            """
            subfulfillments = []
            for c in self.subconditions:
                subcondition = c['body'].to_dict()
                subcondition.update({'weight': c['weight']})
                subfulfillments.append(subcondition)

            return {
                'type': 'fulfillment',
                'type_id': self.TYPE_ID,
                'bitmask': self.bitmask,
                'threshold': self.threshold,
                'subfulfillments': subfulfillments
            }

        def parse_dict(self, data):
            """
            Generate fulfillment payload from a dict

            Args:
                data (dict): description of the fulfillment

            Returns:
                Fulfillment
            """
            if not isinstance(data, dict):
                raise TypeError('reader must be a dict instance')
            self.threshold = data['threshold']

            for subfulfillments in data['subfulfillments']:
                weight = subfulfillments['weight']

                if subfulfillments['type'] == FULFILLMENT:
                    self.add_subfulfillment(Fulfillment.from_dict(subfulfillments), weight)
                elif subfulfillments['type'] == CONDITION:
                    self.add_subcondition(Condition.from_dict(subfulfillments), weight)
                else:
                    raise TypeError('Subconditions must provide either subcondition or fulfillment.')

        def validate(self, message=None, **kwargs):
            """
            Check whether this fulfillment meets all validation criteria.

            This will validate the subfulfillments and verify that there are enough
            subfulfillments to meet the threshold.

            Args:
                message (str): message to validate against
            Returns:
                boolean: Whether this fulfillment is valid.
            """
            fulfillments = [c for c in self.subconditions if c['type'] == FULFILLMENT]

            # Find total weight and smallest individual weight
            min_weight = float('inf')
            total_weight = 0
            for fulfillment in fulfillments:
                min_weight = min(min_weight, abs(fulfillment['weight']))
                total_weight += min_weight

            # Total weight must meet the threshold
            if total_weight < self.threshold:
                # Threshold not met
                return False

            # TODO: Discuss with ILP
            # But the set must be minimal, there mustn't be any fulfillments we could take out
            # if self.threshold + min_weight <= total_weight:
            #     # Fulfillment is not minimal
            #     return False
            # TODO: ILP specs see unfulfilled conditions as conditions and not fulfillments
            valid_decisions = []
            for fulfillment in fulfillments:
                if fulfillment['body'].validate(message, **kwargs):
                    valid_decisions += [True] * fulfillment['weight']
            return len(valid_decisions) >= self.threshold
    end
  end
end
