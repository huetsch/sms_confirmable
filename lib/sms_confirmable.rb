require 'sms_confirmable/version'
require 'devise'
require 'active_support/concern'
require "active_model"
require "active_record"
require "active_support/core_ext/class/attribute_accessors"
require "cgi"

module Devise
  mattr_accessor :authenticate_on_login
  @@authenticate_on_login = false
end

module SmsConfirmable
end

Devise.add_module :sms_confirmable, :model => 'sms_confirmable/models/sms_confirmable', :controller => :confirmable, :route => :confirmable

require 'sms_confirmable/models/sms_confirmable'
