##
## NetworkAnalyzer Test
##

assert("NetworkAnalyzer#hello") do
  t = NetworkAnalyzer.new "hello"
  assert_equal("hello", t.hello)
end

assert("NetworkAnalyzer#bye") do
  t = NetworkAnalyzer.new "hello"
  assert_equal("hello bye", t.bye)
end

assert("NetworkAnalyzer.hi") do
  assert_equal("hi!!", NetworkAnalyzer.hi)
end
