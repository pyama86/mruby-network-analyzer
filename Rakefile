MRUBY_CONFIG=File.expand_path(ENV["MRUBY_CONFIG"] || ".travis_build_config.rb")
MRUBY_VERSION=ENV["MRUBY_VERSION"] || 'd6e41c3e512673dac91906416a9c4543bbb2ab19'

file :mruby do
  cmd =  "git clone --depth=1 git://github.com/mruby/mruby.git"
  case MRUBY_VERSION
  when /\A[a-fA-F0-9]+\z/
    cmd << " && cd mruby"
    cmd << " && git fetch --depth=100 && git checkout #{MRUBY_VERSION}"
  when /\A\d\.\d\.\d\z/
    cmd << " && cd mruby"
    cmd << " && git fetch --tags && git checkout $(git rev-parse #{MRUBY_VERSION})"
  when "master"
    # skip
  else
    fail "Invalid MRUBY_VERSION spec: #{MRUBY_VERSION}"
  end
  sh cmd
end

desc "compile binary"
task :compile => :mruby do
  sh "cd mruby && MRUBY_CONFIG=#{MRUBY_CONFIG} rake all"
end

desc "test"
task :test => :mruby do
  sh "cd mruby && MRUBY_CONFIG=#{MRUBY_CONFIG} rake all test"
end

desc "cleanup"
task :clean do
  exit 0 unless File.directory?('mruby')
  sh "cd mruby && rake deep_clean"
end

task :default => :compile
