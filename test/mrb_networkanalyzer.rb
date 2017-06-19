##
## NetworkAnalyzer Test
##

assert("NetworkAnalyzer#collect") do
  system('ping 127.0.0.1 -c 3 &')
  assert_true(NetworkAnalyzer.collect("lo", 3).first['src_host'] == '127.0.0.1')
end
