MRuby::Gem::Specification.new('mruby-network-analyzer') do |spec|
  spec.license = 'MIT'
  spec.authors = 'pyama86'
  spec.linker.libraries << %w(pcap pthread)
  spec.cc.flags << "-DMRB_THREAD_COPY_VALUES"
  spec.add_dependency 'mruby-signal-thread', :github => 'udzura/mruby-signal-thread', :branch => 'class-to-hash'  
  spec.add_dependency 'mruby-thread', :github => 'udzura/mruby-thread', :branch => 'after-1.3'
  spec.add_test_dependency 'mruby-process'
  spec.add_test_dependency 'mruby-print'
end
