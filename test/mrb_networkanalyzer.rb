##
## NetworkAnalyzer Test
##

assert("NetworkAnalyzer#new") do
  n = NetworkAnalyzer.new("lo")
  system('ping 127.0.0.1 -c 5')
  assert_true(n.current.is_a?(Array))
end
