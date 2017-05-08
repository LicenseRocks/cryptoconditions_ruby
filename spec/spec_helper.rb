$LOAD_PATH.unshift File.expand_path("../../lib", __FILE__)
require 'cryptoconditions_ruby'
require_relative 'conftest'

include Conftest
include CryptoconditionsRuby::Utils::Hexlify
