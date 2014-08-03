# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "sms_confirmable/version"

Gem::Specification.new do |s|
  s.name        = "sms_confirmable"
  s.version     = SmsConfirmable::VERSION.dup
  s.authors     = ["Mark Huetsch"]
  s.email       = ["markhuetsch@gmail.com"]
  s.homepage    = "https://github.com/huetsch/sms_confirmable"
  s.summary     = %q{SMS confirmable plugin for devise}
  s.description = <<-EOF
    ### Features ###
    * use sms instead of email to confirm a resource
    * your own sms logic
  EOF

  s.rubyforge_project = "sms_confirmable"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  s.add_runtime_dependency 'rails', '>= 3.1.1'
  s.add_runtime_dependency 'devise'
  s.add_runtime_dependency 'randexp'
  s.add_runtime_dependency 'rotp'

  s.add_development_dependency 'bundler'
  s.add_development_dependency 'rake'
  s.add_development_dependency 'rspec-rails', '>= 3.0.1'
  s.add_development_dependency 'capybara', '2.4.1'
  s.add_development_dependency 'pry'
end
