MRuby::Gem::Specification.new('mruby-network-analyzer') do |spec|
  spec.license = 'MIT'
  spec.authors = 'pyama86'
  spec.linker.libraries << %w(pcap pthread)
  spec.cc.flags << "-DMRB_THREAD_COPY_VALUES"
  spec.add_dependency 'mruby-thread'
  spec.add_dependency 'mruby-signal-thread'
  spec.add_test_dependency 'mruby-process'
  spec.add_test_dependency 'mruby-print'
end
