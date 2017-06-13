n = NetworkAnalyzer.new("lo")
system('ping 127.0.0.1 -c 3')
puts n.current.first
