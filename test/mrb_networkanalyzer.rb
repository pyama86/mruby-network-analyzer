##
## NetworkAnalyzer Test
##

assert("NetworkAnalyzer#new") do
  n = NetworkAnalyzer.new("lo")
  system('ping 127.0.0.1 -c 3')
  assert_equal('127.0.0.1', n.current.first['src_host'])
end
