MRuby::Build.new do |conf|
  toolchain :gcc
  conf.gembox 'default'
  conf.gem '../mruby-network-analyzer'
  conf.enable_test
#  conf.cc.flags << "-O0 -g3"
end
