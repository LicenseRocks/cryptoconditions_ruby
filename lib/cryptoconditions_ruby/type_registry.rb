class CryptoconditionsRuby::TypeRegistry
  MAX_SAFE_INTEGER_JS = 2 ** 53 - 1

  def self.registered_types
    @registered_types ||=[]
  end

  def self.get_class_from_type_id(type_id)
    if type_id > MAX_SAFE_INTEGER_JS
      raise TypeError.new("Type #{type_id} is not supported")
    end

    type = registered_types.find do |registered_type|
      type_id == registered_type['type_id']
    end

    if type
      type['class']
    else
      raise TypeError.new("Type #{type_id} is not supported")
    end
  end

  def self.register_type(cls)
    registered_types.push({'type_id' => cls::TYPE_ID, 'class' => cls})
  end
end
