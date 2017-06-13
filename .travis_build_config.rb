MRuby::Build.new do |conf|
  toolchain :gcc
  conf.gembox 'default'
  conf.gem File.expand_path(File.dirname(__FILE__))
  conf.enable_test
  conf.linker.libraries << ['pcap']
  conf.cc.flags << "-DMRB_THREAD_COPY_VALUES"
#  conf.cc.flags << "-O0 -g3"
end
